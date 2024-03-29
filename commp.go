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
	quadsEnqueued uint64
	layerQueues   [MaxLayers + 2]chan []byte // one extra layer for the initial leaves, one more for the dummy never-to-use channel
	resultCommP   chan []byte
	buffer        []byte
}

var _ hash.Hash = &Calc{} // make sure we are hash.Hash compliant

// MaxLayers is the current maximum height of the rust-fil-proofs proving tree.
const MaxLayers = uint(31) // result of log2( 64 GiB / 32 )

// MaxPieceSize is the current maximum size of the rust-fil-proofs proving tree.
const MaxPieceSize = uint64(1 << (MaxLayers + 5))

// MaxPiecePayload is the maximum amount of data that one can Write() to the
// Calc object, before needing to derive a Digest(). Constrained by the value
// of MaxLayers.
const MaxPiecePayload = MaxPieceSize / 128 * 127

// MinPiecePayload is the smallest amount of data for which FR32 padding has
// a defined result. It is not possible to derive a Digest() before Write()ing
// at least this amount of bytes.
const MinPiecePayload = uint64(65)

const (
	commpDigestSize = sha256simd.Size
	quadPayload     = int(127)
	bufferSize      = 256 * quadPayload // FIXME: tune better, chosen by rough experiment
)

var (
	layerQueueDepth   = 32 // FIXME: tune better, chosen by rough experiment
	stackedNulPadding [MaxLayers][]byte
)

// initialize the nul padding stack (cheap to do upfront, just MaxLayers loops)
func init() {
	h := sha256simd.New()

	stackedNulPadding[0] = make([]byte, commpDigestSize)
	for i := uint(1); i < MaxLayers; i++ {
		h.Reset()
		h.Write(stackedNulPadding[i-1]) // yes, got to...
		h.Write(stackedNulPadding[i-1]) // ...do it twice
		stackedNulPadding[i] = h.Sum(make([]byte, 0, commpDigestSize))
		stackedNulPadding[i][31] &= 0x3F
	}
}

// BlockSize is the amount of bytes consumed by the commP algorithm in one go.
// Write()ing data in multiples of BlockSize would obviate the need to maintain
// an internal carry buffer. The BlockSize of this module is 127 bytes.
func (cp *Calc) BlockSize() int { return quadPayload }

// Size is the amount of bytes returned on Sum()/Digest(), which is 32 bytes
// for this module.
func (cp *Calc) Size() int { return commpDigestSize }

// Reset re-initializes the accumulator object, clearing its state and
// terminating all background goroutines. It is safe to Reset() an accumulator
// in any state.
func (cp *Calc) Reset() {
	cp.mu.Lock()
	if cp.buffer != nil {
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

	if processed := cp.quadsEnqueued*uint64(quadPayload) + uint64(len(cp.buffer)); processed < MinPiecePayload {
		err = xerrors.Errorf(
			"insufficient state accumulated: commP is not defined for inputs shorter than %d bytes, but only %d processed so far",
			MinPiecePayload, processed,
		)
		return
	}

	// If any, flush remaining bytes padded up with zeroes
	if len(cp.buffer) > 0 {
		if mod := len(cp.buffer) % quadPayload; mod != 0 {
			cp.buffer = append(cp.buffer, make([]byte, quadPayload-mod)...)
		}
		for len(cp.buffer) > 0 {
			// FIXME: there is a smarter way to do this instead of 127-at-a-time,
			// but that's for another PR
			cp.digestQuads(cp.buffer[:127])
			cp.buffer = cp.buffer[127:]
		}
	}

	// This is how we signal to the bottom of the stack that we are done
	// which in turn collapses the rest all the way to resultCommP
	close(cp.layerQueues[0])

	paddedPieceSize = cp.quadsEnqueued * 128
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
	if len(input) == 0 {
		return 0, nil
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if MaxPiecePayload <
		(cp.quadsEnqueued*uint64(quadPayload))+
			uint64(len(input)) {
		return 0, xerrors.Errorf(
			"writing additional %d bytes to the accumulator would overflow the maximum supported unpadded piece size %d",
			len(input), MaxPiecePayload,
		)
	}

	// just starting: initialize internal state, start first background layer-goroutine
	if cp.buffer == nil {
		cp.buffer = make([]byte, 0, bufferSize)
		cp.resultCommP = make(chan []byte, 1)
		cp.layerQueues[0] = make(chan []byte, layerQueueDepth)
		cp.addLayer(0)
	}

	// short Write() - just buffer it
	if len(cp.buffer)+len(input) < bufferSize {
		cp.buffer = append(cp.buffer, input...)
		return len(input), nil
	}

	totalInputBytes := len(input)

	if toSplice := bufferSize - len(cp.buffer); toSplice < bufferSize {
		cp.buffer = append(cp.buffer, input[:toSplice]...)
		input = input[toSplice:]

		cp.digestQuads(cp.buffer)
		cp.buffer = cp.buffer[:0]
	}

	// FIXME: suboptimal, limits each slab to a buffer size, but could go exponentially larger
	for len(input) >= bufferSize {
		cp.digestQuads(input[:bufferSize])
		input = input[bufferSize:]
	}

	if len(input) > 0 {
		cp.buffer = append(cp.buffer, input...)
	}

	return totalInputBytes, nil
}

// always called with power-of-2 amount of quads
func (cp *Calc) digestQuads(inSlab []byte) {

	quadsCount := len(inSlab) / 127
	cp.quadsEnqueued += uint64(quadsCount)
	outSlab := make([]byte, quadsCount*128)

	for j := 0; j < quadsCount; j++ {
		// Cycle over four(4) 31-byte groups, leaving 1 byte in between:
		// 31 + 1 + 31 + 1 + 31 + 1 + 31 = 127
		input := inSlab[j*127 : (j+1)*127]
		expander := outSlab[j*128 : (j+1)*128]
		inputPlus1, expanderPlus1 := input[1:], expander[1:]

		// First 31 bytes + 6 bits are taken as-is (trimmed later)
		// Note that copying them into the expansion buffer is mandatory:
		// we will be feeding it to the workers which reuse the bottom half
		// of the chunk for the result
		copy(expander[:], input[:32])

		// first 2-bit "shim" forced into the otherwise identical bitstream
		expander[31] &= 0x3F

		//  In: {{ C[7] C[6] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] Y[7] Y[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] Z[7] Z[6] Z[5]...
		// Out:                 X[5] X[4] X[3] X[2] X[1] X[0] C[7] C[6] Y[5] Y[4] Y[3] Y[2] Y[1] Y[0] X[7] X[6] Z[5] Z[4] Z[3]...
		for i := 31; i < 63; i++ {
			expanderPlus1[i] = inputPlus1[i]<<2 | input[i]>>6
		}

		// next 2-bit shim
		expander[63] &= 0x3F

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
	}

	cp.layerQueues[0] <- outSlab
}

func (cp *Calc) addLayer(myIdx uint) {
	// the next layer channel, which we might *not* use
	if cp.layerQueues[myIdx+1] != nil {
		panic("addLayer called more than once with identical idx argument")
	}
	cp.layerQueues[myIdx+1] = make(chan []byte, layerQueueDepth)

	go func() {
		s256 := sha256simd.New()
		var twinHold []byte

		for {
			slab, queueIsOpen := <-cp.layerQueues[myIdx]

			// the dream is collapsing
			if !queueIsOpen {
				defer func() { twinHold = nil }()

				// I am last
				if myIdx == MaxLayers || cp.layerQueues[myIdx+2] == nil {
					cp.resultCommP <- append(make([]byte, 0, 32), twinHold[0:32]...)
					return
				}

				if twinHold != nil {
					copy(twinHold[32:64], stackedNulPadding[myIdx])
					cp.hashSlab254(s256, 0, twinHold[0:64])
					cp.layerQueues[myIdx+1] <- twinHold[0:64:64]
				}

				// signal the next in line that they are done too
				close(cp.layerQueues[myIdx+1])
				return
			}

			switch {
			case uint64(len(slab)) > uint64(1<<(5+myIdx)): // uint64 cast needed on 32-bit systems
				cp.hashSlab254(s256, myIdx, slab)
				cp.layerQueues[myIdx+1] <- slab
			case twinHold != nil:
				copy(twinHold[32:64], slab[0:32])
				cp.hashSlab254(s256, 0, twinHold[0:64])
				cp.layerQueues[myIdx+1] <- twinHold[0:32:64]
				twinHold = nil
			default:
				twinHold = slab[0:32:64]
				// avoid code below
				continue
			}

			// Check whether we need another worker for what we just pushed
			//
			// n.b. we will not blow out of the preallocated layerQueues array,
			// as we disallow Write()s above a certain threshold
			if cp.layerQueues[myIdx+2] == nil {
				cp.addLayer(myIdx + 1)
			}
		}
	}()
}

func (cp *Calc) hashSlab254(h hash.Hash, layerIdx uint, slab []byte) {
	stride := 1 << (5 + layerIdx)
	for i := 0; len(slab) > i+stride; i += 2 * stride {
		h.Reset()
		h.Write(slab[i : i+32])
		h.Write(slab[i+stride : 32+i+stride])
		h.Sum(slab[i:i])[31] &= 0x3F // callers expect we will reuse-reduce-recycle
	}
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
	if targetPaddedSize > MaxPieceSize {
		return nil, xerrors.Errorf("target padded size %d larger than Filecoin maximum of %d bytes", targetPaddedSize, MaxPieceSize)
	}

	// noop
	if sourcePaddedSize == targetPaddedSize {
		return sourceCommP, nil
	}

	out := make([]byte, 32)
	copy(out, sourceCommP)

	s := bits.TrailingZeros64(sourcePaddedSize)
	t := bits.TrailingZeros64(targetPaddedSize)

	h := sha256simd.New()
	for ; s < t; s++ {
		h.Reset()
		h.Write(out)
		h.Write(stackedNulPadding[s-5]) // account for 32byte chunks + off-by-one padding tower offset
		out = h.Sum(out[:0])
		out[31] &= 0x3F
	}

	return out, nil
}
