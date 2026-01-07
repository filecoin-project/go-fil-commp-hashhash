// Package commp2 allows calculating a Filecoin Unsealed Commitment v2 (commPat)
// given a bytestream. It is implemented as a standard hash.Hash() interface, with
// the treebuilding algorithm written in golang.
package commp2

import (
	"hash"
	"runtime"
	"sync"

	pool "github.com/libp2p/go-buffer-pool"
	sha256simd "github.com/minio/sha256-simd"
	"golang.org/x/xerrors"
)

const (
	commpDigestSize = sha256simd.Size
	quadPayload     = int(127)
)

// MaxLayers is the current maximum height of the rust-fil-proofs proving tree.
const MaxLayers = uint(31) // result of log2( 64 GiB / 32 )

// Calc is an implementation of a commP "hash" calculator, implementing the
// familiar hash.Hash interface. The zero-value of this object is ready to
// accept Write()s without further initialization.
type Calc struct {
	state
	mu sync.Mutex
}
type state struct {
	bufStartOffset uint64
	buffer         []byte

	throttle chan struct{}

	// Subgraph storage for stitching
	subgraphsMu   sync.Mutex
	subgraphs     map[int]*subgraph // indexed by chunk number
	chunksPending sync.WaitGroup
	nextChunkIdx  int
	totalLeaves   uint64 // total number of leaves processed
}

type subgraph struct {
	// First and last leaf index (absolute) processed in this chunk
	firstLeaf uint64
	lastLeaf  uint64

	// nodes computed up to the right side of their parent
	// rightOnLeft[level] is valid if the first node at this level is a right child
	// whose left sibling is in a previous chunk
	rightOnLeft [MaxLayers][commpDigestSize]byte
	rightValid  [MaxLayers]bool

	// nodes on the left side of their parent
	// left[level] is valid if the last node at this level is a left child
	// whose right sibling is in a future chunk
	left      [MaxLayers][commpDigestSize]byte
	leftValid [MaxLayers]bool
}

var _ hash.Hash = &Calc{} // make sure we are hash.Hash compliant

// MaxPieceSize is the current maximum size of the rust-fil-proofs proving tree.
const MaxPieceSize = uint64(1 << (MaxLayers + 5))

// MaxPiecePayload is the maximum amount of data that one can Write() to the
// Calc object, before needing to derive a Digest(). Constrained by the value
// of MaxLayers.
const MaxPiecePayload = MaxPieceSize / 128 * 127

var TargetDigestChunk = uint64((4 << 20) / 128 * 127)
var DefaultParallelism = min(16, runtime.GOMAXPROCS(0)/2)

var (
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

func (cp *Calc) BlockSize() int { return quadPayload }

func (cp *Calc) Size() int { return commpDigestSize }

func (cp *Calc) Reset() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	cp.bufStartOffset = 0
	if cap(cp.buffer) > 0 {
		cp.buffer = cp.buffer[:0]
	} else {
		cp.buffer = nil
	}
	cp.subgraphs = nil
	cp.nextChunkIdx = 0
	cp.totalLeaves = 0
}

func (cp *Calc) BeginAt(bytePosition uint64) error {
	if bytePosition != 0 {
		return xerrors.Errorf("bytePosition must be 0")
	}
	cp.bufStartOffset = bytePosition
	return nil
}

func (cp *Calc) Sum(buf []byte) []byte {
	commP, _, err := cp.Digest()
	if err != nil {
		panic(err)
	}
	return append(buf, commP...)
}

func (cp *Calc) Digest() (commP []byte, paddedPieceSize uint64, err error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	// Process any remaining data in the buffer
	if len(cp.buffer) > 0 {
		cp.processBuffer(true) // true = final buffer, pad last quad to 4 leaves
	}

	// Wait for all chunks to complete
	cp.chunksPending.Wait()

	// Check if we have any data
	if cp.totalLeaves == 0 {
		return nil, 0, xerrors.Errorf("no data written")
	}

	// Calculate padded piece size (round up to next power of 2)
	// Each leaf is 32 bytes in the padded tree
	paddedPieceSize = nextPow2(cp.totalLeaves * leafExpandedSize)

	// Stitch all subgraphs together to get the root
	root := cp.stitchTrees()

	return root[:], paddedPieceSize, nil
}

func (cp *Calc) Write(input []byte) (int, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	n := 0
	for len(input) > 0 {
		targetBufSize := cp.targetBufSize()

		// Calculate how much space is left in the buffer
		spaceInBuffer := targetBufSize - len(cp.buffer)
		toAdd := min(len(input), spaceInBuffer)

		cp.buffer = append(cp.buffer, input[:toAdd]...)
		n += toAdd
		input = input[toAdd:]

		// If buffer is now full, process it
		if len(cp.buffer) == targetBufSize {
			cp.processBuffer(false) // false = not final, more data coming
		}
	}

	return n, nil
}

func (cp *Calc) processBuffer(isLastBuffer bool) (int, error) {
	// save current state that we will be processing
	buf := cp.buffer
	start := cp.bufStartOffset

	// Initialize subgraph storage if needed
	if cp.subgraphs == nil {
		cp.subgraphs = make(map[int]*subgraph)
	}

	// Assign chunk index and track pending
	chunkIdx := cp.nextChunkIdx
	cp.nextChunkIdx++
	cp.chunksPending.Add(1)

	// update state to next buffer
	cp.buffer = pool.Get(cp.targetBufSize())[:0]
	cp.bufStartOffset = start + uint64(len(buf))

	// start a new goroutine to process the buffer
	if cp.throttle == nil {
		cp.throttle = make(chan struct{}, DefaultParallelism)
	}
	cp.throttle <- struct{}{}
	go func() {
		defer func() {
			<-cp.throttle
			cp.chunksPending.Done()
		}()

		end := start + uint64(len(buf))
		startQuad := start / uint64(quadPayload)
		endQuad := (end + uint64(quadPayload) - 1) / uint64(quadPayload)

		// First leaf index in this chunk that has actual data
		// (may be different from startQuad * numLeaves if chunk starts mid-quad)
		posInFirstQuad := int(start % uint64(quadPayload))
		firstDataLeaf := startQuad*numLeaves + uint64(payloadPosToLeaf(posInFirstQuad))

		// Track the last leaf processed for totalLeaves calculation
		var lastLeafIdx uint64

		sg := &subgraph{
			firstLeaf: firstDataLeaf,
		}
		var paddedQuad [quadExpanded]byte
		h := sha256simd.New()

		// pending holds the last unpaired "left" node at each level computed within this chunk.
		// Anything that remains pending after processing becomes sg.left[level] for stitching.
		var pending [MaxLayers][commpDigestSize]byte
		var pendingValid [MaxLayers]bool

		// reduce combines a node into the tree at the given level.
		// level 0 = raw leaf data (32 bytes), level 1+ = hashes.
		// nodeIdx is the absolute node index at this level.
		// For level 0, data points to 32 bytes of raw leaf data.
		// For level 1+, data points to a 32-byte hash.
		// When we're on the right and have the left sibling in this chunk, we combine them
		// and continue reducing up the tree.
		var reduce func(level int, nodeIdx uint64, data *[commpDigestSize]byte)
		reduce = func(level int, nodeIdx uint64, data *[commpDigestSize]byte) {
			if isLeft(nodeIdx) {
				// On the left, store and wait for right sibling (within this chunk)
				copy(pending[level][:], data[:])
				pendingValid[level] = true
			} else {
				// On the right: if we have a pending left at this level, combine.
				// Otherwise, the left sibling is in a previous chunk => boundary node.
				if pendingValid[level] {
					var parentHash [commpDigestSize]byte
					h.Reset()
					h.Write(pending[level][:])
					h.Write(data[:])
					h.Sum(parentHash[:0])
					parentHash[31] &= 0x3F // clear top 2 bits for FR32 validity
					pendingValid[level] = false

					// Continue reducing at parent level
					reduce(level+1, nodeIdx/2, &parentHash)
				} else {
					copy(sg.rightOnLeft[level][:], data[:])
					sg.rightValid[level] = true
				}
			}
		}

		for quadIdx := startQuad; quadIdx < endQuad; quadIdx++ {
			startLeafInQuad, endLeafInQuad := quadFromBuf(paddedQuad[:], buf, start, quadIdx)
			if startLeafInQuad < 0 {
				continue // no data in this quad
			}

			// For the last quad of the final buffer, extend to all 4 leaves
			// to match v1's behavior which pads to complete quads
			if isLastBuffer && quadIdx == endQuad-1 {
				endLeafInQuad = numLeaves - 1 // extend to leaf 3
			}

			// Process each leaf that has data
			for leafInQuad := startLeafInQuad; leafInQuad <= endLeafInQuad; leafInQuad++ {
				leafIdx := quadIdx*numLeaves + uint64(leafInQuad)
				var leafData [commpDigestSize]byte
				copy(leafData[:], paddedQuad[leafInQuad*leafExpandedSize:(leafInQuad+1)*leafExpandedSize])

				// Feed raw leaf data to reduce at level 0
				reduce(0, leafIdx, &leafData)
				lastLeafIdx = leafIdx
			}
		}

		// Export any in-chunk pending left nodes as stitchable boundaries.
		for level := 0; level < int(MaxLayers); level++ {
			if pendingValid[level] {
				copy(sg.left[level][:], pending[level][:])
				sg.leftValid[level] = true
			}
		}

		// Store subgraph for stitching
		cp.subgraphsMu.Lock()
		sg.lastLeaf = lastLeafIdx
		cp.subgraphs[chunkIdx] = sg
		if lastLeafIdx+1 > cp.totalLeaves {
			cp.totalLeaves = lastLeafIdx + 1
		}
		cp.subgraphsMu.Unlock()
	}()

	return len(buf), nil
}

const (
	leafPayloadSize  = 31                           // FR32 leaf payload size (input bytes per leaf)
	leafExpandedSize = 32                           // FR32 leaf expanded size (output bytes per leaf)
	numLeaves        = 4                            // number of FR32 leaves per quad
	quadExpanded     = numLeaves * leafExpandedSize // 128 bytes
)

// quadFromBuf extracts a quad from the buffer, performs FR32 expansion, and writes to out.
// - out: 128-byte output buffer for the FR32-expanded quad (4 x 32-byte leaves)
// - buf: the buffer containing data
// - start: byte offset in the stream where buf starts
// - quadIdx: the index of the quad to extract (quad N covers stream bytes [N*127, (N+1)*127))
//
// Returns (startLeaf, endLeaf) indicating which leaves (0-3) contain actual data.
// Returns (-1, -1) if there's no overlap between the quad and buffer.
//
// NOTE: Quad index is absolute, i.e. quadIdx=0 implies stream bytes [0, 127).
// The output buffer is always fully written with FR32-expanded data (zero-padded where needed).
func quadFromBuf(out []byte, buf []byte, start uint64, quadIdx uint64) (startLeaf, endLeaf int) {
	if len(out) < quadExpanded {
		panic("output buffer must be at least 128 bytes")
	}

	// Quad N covers stream bytes [quadIdx*127, quadIdx*127 + 127)
	// Buffer covers stream bytes [start, start + len(buf))
	bufStartOff := int64(quadIdx)*int64(quadPayload) - int64(start)
	bufEndOff := bufStartOff + int64(quadPayload)

	// Calculate which part of the quad has actual data (positions within quad, 0-indexed)
	dataStartInQuad := int64(0)
	if bufStartOff < 0 {
		dataStartInQuad = -bufStartOff
	}
	dataEndInQuad := int64(quadPayload)
	if bufEndOff > int64(len(buf)) {
		dataEndInQuad = int64(len(buf)) - bufStartOff
	}

	// No data overlap
	if dataStartInQuad >= dataEndInQuad || dataEndInQuad <= 0 || dataStartInQuad >= int64(quadPayload) {
		return -1, -1
	}

	// Clamp to quad bounds
	if dataEndInQuad > int64(quadPayload) {
		dataEndInQuad = int64(quadPayload)
	}

	// Find first and last leaf (0-indexed, max numLeaves-1) that contain any data
	// Leaf boundaries in payload space: [0,31), [31,62), [62,93), [93,127)
	startLeaf = payloadPosToLeaf(int(dataStartInQuad))
	endLeaf = payloadPosToLeaf(int(dataEndInQuad) - 1)

	if endLeaf < startLeaf {
		return -1, -1
	}

	// Build the 127-byte input for FR32 expansion (zero-padded where needed)
	var input [quadPayload]byte

	// Copy data from buffer
	for i := int(dataStartInQuad); i < int(dataEndInQuad); i++ {
		bufPos := int(bufStartOff) + i
		if bufPos >= 0 && bufPos < len(buf) {
			input[i] = buf[bufPos]
		}
	}

	// Perform FR32 expansion: 127 bytes -> 128 bytes
	fr32Expand(out, input[:])

	return startLeaf, endLeaf
}

// payloadPosToLeaf returns which leaf (0-3) a payload byte position falls into.
// Leaf boundaries: [0,31), [31,62), [62,93), [93,127)
func payloadPosToLeaf(pos int) int {
	switch {
	case pos < 31:
		return 0
	case pos < 62:
		return 1
	case pos < 93:
		return 2
	default:
		return 3
	}
}

// fr32Expand performs FR32 padding expansion from 127 bytes to 128 bytes.
// This inserts 2-bit shims at positions 31, 63, 95 to create 4 valid FR32 leaves.
func fr32Expand(out []byte, input []byte) {
	if len(input) < quadPayload || len(out) < quadExpanded {
		panic("invalid buffer sizes for fr32Expand")
	}

	inputPlus1 := input[1:]
	outPlus1 := out[1:]

	// First 31 bytes + 6 bits are taken as-is
	copy(out[:32], input[:32])

	// First 2-bit shim: clear top 2 bits of byte 31
	out[31] &= 0x3F

	// Leaf 1: bytes 32-63
	// Shift bits to account for the 2-bit shim
	//  In: {{ C[7] C[6] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] ...
	// Out:                 X[5] X[4] X[3] X[2] X[1] X[0] C[7] C[6] ...
	for i := 31; i < 63; i++ {
		outPlus1[i] = inputPlus1[i]<<2 | input[i]>>6
	}

	// Second 2-bit shim: clear top 2 bits of byte 63
	out[63] &= 0x3F

	// Leaf 2: bytes 64-95
	//  In: {{ C[7] C[6] C[5] C[4] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] ...
	// Out:                           X[3] X[2] X[1] X[0] C[7] C[6] C[5] C[4] ...
	for i := 63; i < 95; i++ {
		outPlus1[i] = inputPlus1[i]<<4 | input[i]>>4
	}

	// Third 2-bit shim: clear top 2 bits of byte 95
	out[95] &= 0x3F

	// Leaf 3: bytes 96-127
	//  In: {{ C[7] C[6] C[5] C[4] C[3] C[2] }} X[7] X[6] X[5] X[4] X[3] X[2] X[1] X[0] ...
	// Out:                                     X[1] X[0] C[7] C[6] C[5] C[4] C[3] C[2] ...
	for i := 95; i < 126; i++ {
		outPlus1[i] = inputPlus1[i]<<6 | input[i]>>2
	}

	// The final 6-bit remainder is exactly the value of the last expanded byte
	out[127] = input[126] >> 2
}

func isLeft(leafIdx uint64) bool {
	return leafIdx%2 == 0
}

// targetBufSize calculates target size of a buffer such that it ends cleanly on a leaf boundary.
// only the first buffer processed after BeginAt() with a non-127-byte aligned offset will need to be slightly truncated.
func (cp *Calc) targetBufSize() int {
	bufStartLeaf := cp.bufStartOffset % uint64(quadPayload)
	if bufStartLeaf == 0 {
		return int(TargetDigestChunk)
	}
	return int(TargetDigestChunk) - int(bufStartLeaf)
}

// stitchTrees combines all subgraphs and computes the final root hash.
// It processes subgraphs in order, stitching rightOnLeft from chunk N
// with left from chunk N+1, and filling missing siblings with zero padding.
func (cp *Calc) stitchTrees() [commpDigestSize]byte {
	h := sha256simd.New()

	// Calculate the tree height: for N leaves, we need log2(nextPow2(N)) levels
	// The root is at level treeHeight
	paddedLeaves := nextPow2(cp.totalLeaves)
	treeHeight := 0
	for (uint64(1) << treeHeight) < paddedLeaves {
		treeHeight++
	}

	// Accumulated state: for each level, track the "carry" node
	// that needs to be combined with the next chunk's contribution
	var carry [MaxLayers][commpDigestSize]byte
	var carryValid [MaxLayers]bool

	// Process subgraphs in order
	for chunkIdx := 0; chunkIdx < cp.nextChunkIdx; chunkIdx++ {
		sg := cp.subgraphs[chunkIdx]
		if sg == nil {
			continue
		}

		// For each level, stitch boundary nodes emitted by the chunk reduction.
		for level := 0; level < int(MaxLayers); level++ {
			if sg.rightValid[level] {
				// This chunk has a right node that needs its left sibling
				if carryValid[level] {
					// We have a left sibling from previous chunk, combine them
					var parentHash [commpDigestSize]byte
					h.Reset()
					h.Write(carry[level][:])
					h.Write(sg.rightOnLeft[level][:])
					h.Sum(parentHash[:0])
					parentHash[31] &= 0x3F

					// This becomes a node at level+1, feed it up
					feedUp(h, &carry, &carryValid, level+1, &parentHash)
					carryValid[level] = false
				} else {
					// No left sibling from previous chunk
					// The left sibling must be zero padding
					var parentHash [commpDigestSize]byte
					h.Reset()
					h.Write(stackedNulPadding[level])
					h.Write(sg.rightOnLeft[level][:])
					h.Sum(parentHash[:0])
					parentHash[31] &= 0x3F

					feedUp(h, &carry, &carryValid, level+1, &parentHash)
				}

			}

			if sg.leftValid[level] {
				// This chunk ends with a left node at this level
				// It becomes the new carry for the next chunk
				if carryValid[level] {
					// There's already a carry at this level - this means the previous
					// chunk's left node at this level needs to be combined with zero padding
					var parentHash [commpDigestSize]byte
					h.Reset()
					h.Write(carry[level][:])
					h.Write(stackedNulPadding[level])
					h.Sum(parentHash[:0])
					parentHash[31] &= 0x3F
					feedUp(h, &carry, &carryValid, level+1, &parentHash)
				}
				copy(carry[level][:], sg.left[level][:])
				carryValid[level] = true
			}
		}
	}

	// After processing all chunks, collapse remaining carries with zero padding
	// up to the tree height (but not beyond!)
	for level := 0; level < treeHeight; level++ {
		if carryValid[level] {
			// This carry needs a right sibling (zero padding)
			var parentHash [commpDigestSize]byte
			h.Reset()
			h.Write(carry[level][:])
			h.Write(stackedNulPadding[level])
			h.Sum(parentHash[:0])
			parentHash[31] &= 0x3F

			carryValid[level] = false

			// Feed up to next level
			if carryValid[level+1] {
				// Combine with existing carry at next level
				var combined [commpDigestSize]byte
				h.Reset()
				h.Write(carry[level+1][:])
				h.Write(parentHash[:])
				h.Sum(combined[:0])
				combined[31] &= 0x3F
				copy(carry[level+1][:], combined[:])
			} else {
				copy(carry[level+1][:], parentHash[:])
				carryValid[level+1] = true
			}
		}
	}

	// The root should be at treeHeight
	if carryValid[treeHeight] {
		return carry[treeHeight]
	}

	// Fallback: find the highest level with a valid carry
	for level := int(MaxLayers) - 1; level >= 0; level-- {
		if carryValid[level] {
			return carry[level]
		}
	}

	// No data - return zero
	var zero [commpDigestSize]byte
	return zero
}

// feedUp takes a hash at a given level and feeds it up through the carry structure
func feedUp(h hash.Hash, carry *[MaxLayers][commpDigestSize]byte, carryValid *[MaxLayers]bool, level int, data *[commpDigestSize]byte) {
	if level >= int(MaxLayers) {
		return
	}

	if carryValid[level] {
		// Combine with existing carry
		var parentHash [commpDigestSize]byte
		h.Reset()
		h.Write(carry[level][:])
		h.Write(data[:])
		h.Sum(parentHash[:0])
		parentHash[31] &= 0x3F

		carryValid[level] = false
		feedUp(h, carry, carryValid, level+1, &parentHash)
	} else {
		// Store as new carry
		copy(carry[level][:], data[:])
		carryValid[level] = true
	}
}

// isZero checks if a byte slice is all zeros
func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// nextPow2 returns the smallest power of 2 >= n
func nextPow2(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}
