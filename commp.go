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

type Accumulator struct {
	mu             sync.Mutex
	bytesProcessed uint64
	carry          []byte
	layerQueues    []chan []byte
	resultCommP    chan []byte
}

var _ hash.Hash = &Accumulator{} // make sure we are hash.Hash compliant

const MaxLayers = uint(31) // result of log2( 64 GiB / 32 )
const MaxPiecePayload = uint64((1 << MaxLayers) * 32 / 128 * 127)

const layerQueueDepth = 8 // SANCHECK: too much? too little? can't think this through right now...

var stackedNulPadding = make([][]byte, MaxLayers)

// initialize the nul padding stack (cheap to do upfront, just MaxLayers loops)
func init() {
	h := sha256simd.New()
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
}

// NewAccumulator returns a commP accumulator object, implementing the familiar
// hash.Hash interface.
func NewAccumulator() *Accumulator {
	acc := &Accumulator{}
	acc.reset() // initialize state
	return acc
}

// BlockSize is the amount of bytes consumed by the commP algorithm in one go
// Write()ing data in multiples of BlockSize would obviate the need to maintain
// an internal carry buffer.
func (acc *Accumulator) BlockSize() int { return 127 }

// Size is the amount of bytes returned as digest
func (acc *Accumulator) Size() int { return 32 }

// Reset re-initializes the accumulator object, clearing its state and
// terminating all background goroutines. It is safe to Reset() an accumulator
// in any state.
func (acc *Accumulator) Reset() {
	acc.mu.Lock()
	if acc.bytesProcessed != 0 {
		// we are resetting without digesting: close everything out
		close(acc.layerQueues[0])
		<-acc.resultCommP
	}
	acc.reset()
	acc.mu.Unlock()
}

// Sum is a thin wrapper around Digest() and is provided solely to satisfy
// the hash.Hash interface. It panics on errors returned from Digest().
// Note that unlike classic (hash.Hash).Sum(), calling this method is
// destructive: the internal state is reset and all goroutines kicked off
// by Write() are terminated.
func (acc *Accumulator) Sum(buf []byte) []byte {
	commP, _, err := acc.Digest()
	if err != nil {
		panic(err)
	}
	return append(buf, commP...)
}

// Digest collapses the internal hash state and returns the resulting raw 32
// bytes of commP and the padded piece size, or alternatively an error in
// case of insufficient accumulated state. On success invokes Reset(), which
// terminates all goroutines kicked off by Write().
func (acc *Accumulator) Digest() (commP []byte, paddedPieceSize uint64, err error) {
	acc.mu.Lock()

	if acc.bytesProcessed < 65 {
		acc.mu.Unlock()
		return nil, 0, xerrors.Errorf(
			"insufficient state accumulated: commP is not defined for inputs shorter than 65 bytes, but only %d processed so far",
			acc.bytesProcessed,
		)
	}

	if len(acc.carry) > 0 {
		if 127-len(acc.carry) > 0 {
			acc.carry = append(acc.carry, make([]byte, 127-len(acc.carry))...)
		}
		acc.digest127bytes(acc.carry)
	}

	// This is how we signal to the bottom of the stack that we are done
	// which in turn collapses the rest all the way to acc.resultCommP
	close(acc.layerQueues[0])

	paddedPieceSize = ((acc.bytesProcessed + 126) / 127 * 128) // why is 6 afraid of 7...?

	if bits.OnesCount64(paddedPieceSize) != 1 {
		paddedPieceSize = 1 << uint(64-bits.LeadingZeros64(paddedPieceSize))
	}

	commP = <-acc.resultCommP

	acc.reset()

	acc.mu.Unlock()

	return commP, paddedPieceSize, nil
}

// lock-less workhorse to be called by Reset/Digest
func (acc *Accumulator) reset() {
	acc.layerQueues = make([]chan []byte, MaxLayers)
	acc.resultCommP = make(chan []byte, 1)
	acc.carry = make([]byte, 0, 127)
	acc.bytesProcessed = 0
}

// Write adds bytes to the accumulator, for a subsequent Digest(). Upon the
// first call of this method a few goroutines are started in the background to
// service each layer of the digest tower. If you wrote some data and then
// decide to abandon the object without invoking Digest(), you need to call
// Reset() to terminate all remaining background workers.
func (acc *Accumulator) Write(input []byte) (int, error) {
	inputSize := len(input)
	if inputSize == 0 {
		return 0, nil
	}

	acc.mu.Lock()
	defer acc.mu.Unlock()

	if acc.bytesProcessed+uint64(inputSize) > MaxPiecePayload {
		return 0, xerrors.Errorf(
			"writing %d bytes to the accumulator would overflow the maximum supported unpadded piece size %d",
			len(input), MaxPiecePayload,
		)
	}

	// just starting
	if acc.bytesProcessed == 0 {
		acc.layerQueues[0] = make(chan []byte, layerQueueDepth)
		acc.addLayer(0)
	}

	acc.bytesProcessed += uint64(inputSize)

	carrySize := len(acc.carry)
	if carrySize > 0 {

		// super short Write - just carry it
		if carrySize+inputSize < 127 {
			acc.carry = append(acc.carry, input...)
			return inputSize, nil
		}

		acc.carry = append(acc.carry, input[:127-carrySize]...)
		acc.digest127bytes(acc.carry)
		acc.carry = acc.carry[:0]
		input = input[127-carrySize:]
	}

	for len(input) >= 127 {
		acc.digest127bytes(input)
		input = input[127:]
	}

	acc.carry = acc.carry[:len(input)]
	if len(input) > 0 {
		copy(acc.carry, input)
	}

	return inputSize, nil
}

func (acc *Accumulator) digest127bytes(input []byte) {

	// Holds this round's shifts of the original 127 bytes plus the 6 bit overflow
	// at the end of the expansion cycle. We *do not* reuse the slice: it is being
	// fed to hash254Into which reuses the slice for the result
	expander := make([]byte, 128)

	// Cycle over four(4) 31-byte groups, leaving 1 byte in between:
	// 31 + 1 + 31 + 1 + 31 + 1 + 31 = 127

	// First 31 bytes + 6 bits are taken as-is (trimmed later)
	// Note that copying them into the expansion buffer is not strictly
	// necessary: one could feed the range to the hasher directly. However
	// there are significant optimizations to be had when feeding exactly 64
	// bytes at a time to the sha256 implementation, thus keeping the copy()
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

	acc.hash254Into(acc.layerQueues[0], expander[:64])
	acc.hash254Into(acc.layerQueues[0], expander[64:])
}

func (acc *Accumulator) addLayer(myIdx int) {
	// the next layer channel, which we might *not* use
	acc.layerQueues[myIdx+1] = make(chan []byte, layerQueueDepth)

	go func() {
		var chunkHold []byte

		for {

			chunk, queueIsOpen := <-acc.layerQueues[myIdx]

			// the dream is collapsing
			if !queueIsOpen {

				// I am last
				if acc.layerQueues[myIdx+2] == nil {
					acc.resultCommP <- chunkHold
					return
				}

				if chunkHold != nil {
					acc.hash254Into(
						acc.layerQueues[myIdx+1],
						chunkHold,
						stackedNulPadding[myIdx+1], // stackedNulPadding is one longer than the main queue
					)
				}

				// signal the next in line that they are done too
				close(acc.layerQueues[myIdx+1])
				return
			}

			if chunkHold == nil {
				chunkHold = chunk
			} else {

				// I am last right now
				if acc.layerQueues[myIdx+2] == nil {
					acc.addLayer(myIdx + 1)
				}

				acc.hash254Into(acc.layerQueues[myIdx+1], chunkHold, chunk)
				chunkHold = nil
			}
		}
	}()
}

func (acc *Accumulator) hash254Into(out chan<- []byte, data ...[]byte) {
	h := sha256simd.New()
	for i := range data {
		h.Write(data[i])
	}
	d := h.Sum(data[0][:0]) // callers expect we will reuse-reduce-recycle
	d[31] &= 0x3F
	out <- d
}

// PadCommP is experimental, do not use it
func PadCommP(sourceCommP []byte, sourcePieceBitsize, targetPieceBitsize uint) ([]byte, error) {

	out := make([]byte, 32)
	copy(out, sourceCommP)

	if targetPieceBitsize > MaxLayers+5 {
		return nil, xerrors.Errorf(
			"target bitsize %d larger than the maximum %d (%dGiB)",
			targetPieceBitsize, MaxLayers+5, 1<<(MaxLayers-25),
		)
	}

	if sourcePieceBitsize > targetPieceBitsize {
		return nil, xerrors.Errorf("source bitsize %d larger than target %d", sourcePieceBitsize, targetPieceBitsize)
	}

	// noop
	if sourcePieceBitsize == targetPieceBitsize {
		return sourceCommP, nil
	}

	h := sha256simd.New()
	for i := sourcePieceBitsize; i < targetPieceBitsize; i++ {
		h.Reset()
		h.Write(out)
		h.Write(stackedNulPadding[i-5]) // account for 32byte chunks + off-by-one padding tower offset
		out = h.Sum(out[:0])
		out[31] &= 0x3F
	}

	return out, nil
}
