// Package commp allows calculating a Filecoin Unsealed Commitment (commP/commD)
// given a bytestream. It is implemented as a standard hash.Hash() interface, with
// the entire padding and treebuilding algorithm written in golang.
//
// The returned digest is a 32-byte raw commitment payload. Use something like
// https://pkg.go.dev/github.com/filecoin-project/go-fil-commcid#DataCommitmentV1ToCID
// in order to convert it to a proper cid.Cid.
//
// The output of this library is 100% identical to https://github.com/filecoin-project/filecoin-ffi/blob/d82899449741ce19/proofs.go#L177-L196
package commp

import (
	"hash"
	"math/bits"
	"sync"

	sha256simd "github.com/minio/sha256-simd"
	"golang.org/x/xerrors"
)

// Calc is an implementation of a commP "hash" calculator, implementing the
// familiar hash.Hash interface. The zero-value of this object is ready to
// accept Write()s without further initialization.
type Calc struct {
	state
	mu sync.Mutex
}
type state struct {
	bytesConsumed uint64
	layerQueues   [MaxLayers + 2]chan []byte // one extra layer for the initial leaves, one more for the dummy never-to-use channel
	resultCommP   chan []byte
	carry         []byte
}

var _ hash.Hash = &Calc{} // make sure we are hash.Hash compliant

const MaxLayers = uint(31) // result of log2( 64 GiB / 32 )
const MaxPiecePayload = uint64((1 << MaxLayers) * 32 / 128 * 127)

const layerQueueDepth = 256 // SANCHECK: too much? too little? can't think this through right now...

var stackedNulPadding [MaxLayers][]byte

var shaPool = sync.Pool{New: func() interface{} { return sha256simd.New() }}

// initialize the nul padding stack (cheap to do upfront, just MaxLayers loops)
func init() {
	h := shaPool.Get().(hash.Hash)
	for i := range stackedNulPadding {
		if i == 0 {
			stackedNulPadding[0] = make([]byte, 32)
		} else {
			h.Reset()
			h.Write(stackedNulPadding[i-1]) // yes, got to
			h.Write(stackedNulPadding[i-1]) // do it twice
			stackedNulPadding[i] = h.Sum(make([]byte, 0, 32))
			stackedNulPadding[i][31] &= 0x3F
		}
	}
	shaPool.Put(h)
}

// BlockSize is the amount of bytes consumed by the commP algorithm in one go
// Write()ing data in multiples of BlockSize would obviate the need to maintain
// an internal carry buffer. The BlockSize of this module is 127 bytes.
func (cp *Calc) BlockSize() int { return 127 }

// Size is the amount of bytes returned on Sum()/Digest(), which is 32 bytes
// for this module.
func (cp *Calc) Size() int { return 32 }

// Reset re-initializes the accumulator object, clearing its state and
// terminating all background goroutines. It is safe to Reset() an accumulator
// in any state.
func (cp *Calc) Reset() {
	cp.mu.Lock()
	if cp.bytesConsumed != 0 {
		// we are resetting without digesting: close everything out to terminate
		// the layer workers
		close(cp.layerQueues[0])
		<-cp.resultCommP
	}
	cp.state = state{} // reset
	cp.mu.Unlock()
}

// Sum is a thin wrapper around Digest() and is provided solely to satisfy
// the hash.Hash interface. It panics on errors returned from Digest().
// Note that unlike classic (hash.Hash).Sum(), calling this method is
// destructive: the internal state is reset and all goroutines kicked off
// by Write() are terminated.
func (cp *Calc) Sum(buf []byte) []byte {
	commP, _, err := cp.Digest()
	if err != nil {
		panic(err)
	}
	return append(buf, commP...)
}

// Digest collapses the internal hash state and returns the resulting raw 32
// bytes of commP and the padded piece size, or alternatively an error in
// case of insufficient accumulated state. On success invokes Reset(), which
// terminates all goroutines kicked off by Write().
func (cp *Calc) Digest() (commP []byte, paddedPieceSize uint64, err error) {
	cp.mu.Lock()

	defer func() {
		// reset only if we did succeed
		if err == nil {
			cp.state = state{}
		}
		cp.mu.Unlock()
	}()

	if cp.bytesConsumed < 65 {
		err = xerrors.Errorf(
			"insufficient state accumulated: commP is not defined for inputs shorter than 65 bytes, but only %d processed so far",
			cp.bytesConsumed,
		)
		return
	}

	// If any, flush remaining bytes padded up with zeroes
	if len(cp.carry) > 0 {
		if 127-len(cp.carry) > 0 {
			cp.carry = append(cp.carry, make([]byte, 127-len(cp.carry))...)
		}
		cp.digestLeading127Bytes(cp.carry)
	}

	// This is how we signal to the bottom of the stack that we are done
	// which in turn collapses the rest all the way to acc.resultCommP
	close(cp.layerQueues[0])

	paddedPieceSize = ((cp.bytesConsumed + 126) / 127 * 128) // why is 6 afraid of 7...?

	// hacky round-up-to-next-pow2
	if bits.OnesCount64(paddedPieceSize) != 1 {
		paddedPieceSize = 1 << uint(64-bits.LeadingZeros64(paddedPieceSize))
	}

	return <-cp.resultCommP, paddedPieceSize, nil
}

// Write adds bytes to the accumulator, for a subsequent Digest(). Upon the
// first call of this method a few goroutines are started in the background to
// service each layer of the digest tower. If you wrote some data and then
// decide to abandon the object without invoking Digest(), you need to call
// Reset() to terminate all remaining background workers. Unlike a typical
// (hash.Hash).Write, calling this method can return an error when the total
// amount of bytes is about to go over the maximum currently supported by
// Filecoin.
func (cp *Calc) Write(input []byte) (int, error) {
	inputSize := len(input)
	if inputSize == 0 {
		return 0, nil
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.bytesConsumed+uint64(inputSize) > MaxPiecePayload {
		return 0, xerrors.Errorf(
			"writing %d bytes to the accumulator would overflow the maximum supported unpadded piece size %d",
			len(input), MaxPiecePayload,
		)
	}

	// just starting: initialize internal state, start first background layer-goroutine
	if cp.bytesConsumed == 0 {
		cp.carry = make([]byte, 0, 127)
		cp.resultCommP = make(chan []byte, 1)
		cp.layerQueues[0] = make(chan []byte, layerQueueDepth)
		cp.addLayer(0)
	}

	cp.bytesConsumed += uint64(inputSize)

	carrySize := len(cp.carry)
	if carrySize > 0 {

		// super short Write - just carry it
		if carrySize+inputSize < 127 {
			cp.carry = append(cp.carry, input...)
			return inputSize, nil
		}

		cp.carry = append(cp.carry, input[:127-carrySize]...)
		input = input[127-carrySize:]

		cp.digestLeading127Bytes(cp.carry)
		cp.carry = cp.carry[:0]
	}

	for len(input) >= 127 {
		cp.digestLeading127Bytes(input)
		input = input[127:]
	}

	if len(input) > 0 {
		cp.carry = cp.carry[:len(input)]
		copy(cp.carry, input)
	}

	return inputSize, nil
}

func (cp *Calc) digestLeading127Bytes(input []byte) {

	// Holds this round's shifts of the original 127 bytes plus the 6 bit overflow
	// at the end of the expansion cycle. We *do not* reuse the slice: it is being
	// fed to hash254Into which reuses the slice for the result
	expander := make([]byte, 128)

	// Cycle over four(4) 31-byte groups, leaving 1 byte in between:
	// 31 + 1 + 31 + 1 + 31 + 1 + 31 = 127

	// First 31 bytes + 6 bits are taken as-is (trimmed later)
	// Note that copying them into the expansion buffer is mandatory:
	// we will be feeding it to the workers which reuse the bottom half
	// of the chunk for the result
	copy(expander, input[:32])

	// first 2-bit "shim" forced into the otherwise identical bitstream
	expander[31] &= 0x3F

	// simplify pointer math
	inputPlus1, expanderPlus1 := input[1:], expander[1:]

	//  In: {{ C[7] C[6] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
	// Out:                 X[5] X[4] X[3] X[2] X[1] X[0] C[7] C[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] X[7] X[6] Z[5] Z[4] Z[3]...
	for i := 31; i < 63; i++ {
		expanderPlus1[i] = inputPlus1[i]<<2 | input[i]>>6
	}

	// next 2-bit shim
	expander[63] &= 0x3F

	// ready to dispatch first half
	cp.layerQueues[0] <- expander[:32]
	cp.layerQueues[0] <- expander[32:64]

	//  In: {{ C[7] C[6] C[5] C[4] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
	// Out:                           X[3] X[2] X[1] X[0] C[7] C[6] C[5] C[4] Y[3] Y[2] Y[1] Y[0] X[7] X[6] X[5] X[4] Z[3] Z[2] Z[1]...
	for i := 63; i < 95; i++ {
		expanderPlus1[i] = inputPlus1[i]<<4 | input[i]>>4
	}

	// next 2-bit shim
	expander[95] &= 0x3F

	//  In: {{ C[7] C[6] C[5] C[4] C[3] C[2] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
	// Out:                                     X[1] X[0] C[7] C[6] C[5] C[4] C[3] C[2] Y[1] Y[0] X[7] X[6] X[5] X[4] X[3] X[2] Z[1] Z[0] Y[7]...
	for i := 95; i < 126; i++ {
		expanderPlus1[i] = inputPlus1[i]<<6 | input[i]>>2
	}
	// the final 6 bit remainder is exactly the value of the last expanded byte
	expander[127] = input[126] >> 2

	// and dispatch remainder
	cp.layerQueues[0] <- expander[64:96]
	cp.layerQueues[0] <- expander[96:]
}

func (cp *Calc) addLayer(myIdx uint) {
	// the next layer channel, which we might *not* use
	cp.layerQueues[myIdx+1] = make(chan []byte, layerQueueDepth)

	go func() {
		var chunkHold []byte

		for {

			chunk, queueIsOpen := <-cp.layerQueues[myIdx]

			// the dream is collapsing
			if !queueIsOpen {

				// I am last
				if myIdx == MaxLayers || cp.layerQueues[myIdx+2] == nil {
					cp.resultCommP <- chunkHold
					return
				}

				if chunkHold != nil {
					cp.hash254Into(
						cp.layerQueues[myIdx+1],
						chunkHold,
						stackedNulPadding[myIdx],
					)
				}

				// signal the next in line that they are done too
				close(cp.layerQueues[myIdx+1])
				return
			}

			if chunkHold == nil {
				chunkHold = chunk
			} else {

				// We are last right now
				// N.b.: we will not blow out of the preallocated layerQueues array,
				// as we disallow Write()s above a certain threshhold
				if cp.layerQueues[myIdx+2] == nil {
					cp.addLayer(myIdx + 1)
				}

				cp.hash254Into(cp.layerQueues[myIdx+1], chunkHold, chunk)
				chunkHold = nil
			}
		}
	}()
}

func (cp *Calc) hash254Into(out chan<- []byte, half1ToOverwrite, half2 []byte) {
	h := shaPool.Get().(hash.Hash)
	h.Reset()
	h.Write(half1ToOverwrite)
	h.Write(half2)
	d := h.Sum(half1ToOverwrite[:0]) // callers expect we will reuse-reduce-recycle
	d[31] &= 0x3F
	out <- d
	shaPool.Put(h)
}

// PadCommP is experimental, do not use it.
func PadCommP(sourceCommP []byte, sourcePaddedSize, targetPaddedSize uint64) ([]byte, error) {

	if len(sourceCommP) != 32 {
		return nil, xerrors.Errorf("provided commP must be exactly 32 bytes long, got %d bytes instead", len(sourceCommP))
	}
	if bits.OnesCount64(sourcePaddedSize) != 1 {
		return nil, xerrors.Errorf("source padded size %d is not a power of 2", sourcePaddedSize)
	}
	if bits.OnesCount64(targetPaddedSize) != 1 {
		return nil, xerrors.Errorf("target padded size %d is not a power of 2", targetPaddedSize)
	}
	if sourcePaddedSize > targetPaddedSize {
		return nil, xerrors.Errorf("source padded size %d larger than target padded size %d", sourcePaddedSize, targetPaddedSize)
	}
	if sourcePaddedSize < 128 {
		return nil, xerrors.Errorf("source padded size %d smaller than the minimum of 128 bytes", sourcePaddedSize)
	}
	if targetPaddedSize > 1<<(MaxLayers+5) {
		return nil, xerrors.Errorf("target padded size %d larger than Filecoin maximum of %d bytes", targetPaddedSize, 1<<(MaxLayers+5))
	}

	// noop
	if sourcePaddedSize == targetPaddedSize {
		return sourceCommP, nil
	}

	out := make([]byte, 32)
	copy(out, sourceCommP)

	s := bits.TrailingZeros64(sourcePaddedSize)
	t := bits.TrailingZeros64(targetPaddedSize)

	h := shaPool.Get().(hash.Hash)
	for ; s < t; s++ {
		h.Reset()
		h.Write(out)
		h.Write(stackedNulPadding[s-5]) // account for 32byte chunks + off-by-one padding tower offset
		out = h.Sum(out[:0])
		out[31] &= 0x3F
	}
	shaPool.Put(h)

	return out, nil
}
