package commp2

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	randmath "math/rand"

	commp "github.com/filecoin-project/go-fil-commp-hashhash"
)

func TestFr32Expand(t *testing.T) {
	// Test that FR32 expansion produces correct output
	// Each leaf should have its top 2 bits cleared (the shim)

	t.Run("all zeros", func(t *testing.T) {
		input := make([]byte, 127)
		out := make([]byte, 128)
		fr32Expand(out, input)

		// All output should be zeros
		for i, b := range out {
			if b != 0 {
				t.Errorf("expected zero at position %d, got %d", i, b)
			}
		}
	})

	t.Run("shim positions cleared", func(t *testing.T) {
		// Fill with 0xFF to test that shims are properly cleared
		input := make([]byte, 127)
		for i := range input {
			input[i] = 0xFF
		}
		out := make([]byte, 128)
		fr32Expand(out, input)

		// Check shim positions have top 2 bits cleared
		shimPositions := []int{31, 63, 95}
		for _, pos := range shimPositions {
			if out[pos]&0xC0 != 0 {
				t.Errorf("shim at position %d should have top 2 bits cleared, got 0x%02X", pos, out[pos])
			}
		}
	})

	t.Run("first leaf passthrough", func(t *testing.T) {
		input := make([]byte, 127)
		for i := 0; i < 31; i++ {
			input[i] = byte(i + 1)
		}
		out := make([]byte, 128)
		fr32Expand(out, input)

		// First 31 bytes should be copied directly
		for i := 0; i < 31; i++ {
			if out[i] != input[i] {
				t.Errorf("byte %d: expected %d, got %d", i, input[i], out[i])
			}
		}
	})
}

func TestPayloadPosToLeaf(t *testing.T) {
	tests := []struct {
		pos      int
		expected int
	}{
		{0, 0},
		{30, 0},
		{31, 1},
		{61, 1},
		{62, 2},
		{92, 2},
		{93, 3},
		{126, 3},
	}

	for _, tt := range tests {
		got := payloadPosToLeaf(tt.pos)
		if got != tt.expected {
			t.Errorf("payloadPosToLeaf(%d) = %d, want %d", tt.pos, got, tt.expected)
		}
	}
}

func TestQuadFromBuf(t *testing.T) {
	// Create a test buffer with recognizable pattern (each byte = its index mod 256)
	makeTestBuf := func(size int) []byte {
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = byte(i)
		}
		return buf
	}

	t.Run("aligned buffer, first quad fully in buffer", func(t *testing.T) {
		buf := makeTestBuf(254)
		out := make([]byte, 128)

		startLeaf, endLeaf := quadFromBuf(out, buf, 0, 0)

		if startLeaf != 0 || endLeaf != 3 {
			t.Errorf("expected leaves 0-3, got %d-%d", startLeaf, endLeaf)
		}

		// Verify shims are cleared
		if out[31]&0xC0 != 0 || out[63]&0xC0 != 0 || out[95]&0xC0 != 0 {
			t.Error("shim bits should be cleared")
		}
	})

	t.Run("aligned buffer, second quad fully in buffer", func(t *testing.T) {
		buf := makeTestBuf(254)
		out := make([]byte, 128)

		startLeaf, endLeaf := quadFromBuf(out, buf, 0, 1)

		if startLeaf != 0 || endLeaf != 3 {
			t.Errorf("expected leaves 0-3, got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("buffer starts mid-quad, first quad needs leading padding", func(t *testing.T) {
		buf := makeTestBuf(200)
		out := make([]byte, 128)

		// Buffer starts at stream byte 50 (within leaf 1: [31,62))
		startLeaf, endLeaf := quadFromBuf(out, buf, 50, 0)

		// Data starts at payload pos 50 (leaf 1), ends at 126 (leaf 3)
		if startLeaf != 1 || endLeaf != 3 {
			t.Errorf("expected leaves 1-3, got %d-%d", startLeaf, endLeaf)
		}

		// Leaf 0 should be all zeros (FR32 expanded zeros)
		for i := 0; i < 32; i++ {
			if out[i] != 0 {
				t.Errorf("leaf 0 byte %d should be 0, got %d", i, out[i])
			}
		}
	})

	t.Run("buffer ends mid-quad, last quad needs trailing padding", func(t *testing.T) {
		buf := makeTestBuf(150)
		out := make([]byte, 128)

		// Quad 1 = stream bytes [127, 254), buffer has [0, 150)
		// Data in quad: bytes 0-22 (falls within leaf 0: [0,31))
		startLeaf, endLeaf := quadFromBuf(out, buf, 0, 1)

		if startLeaf != 0 || endLeaf != 0 {
			t.Errorf("expected leaves 0-0, got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("quad entirely before buffer", func(t *testing.T) {
		buf := makeTestBuf(100)
		out := make([]byte, 128)

		startLeaf, endLeaf := quadFromBuf(out, buf, 200, 0)

		if startLeaf != -1 || endLeaf != -1 {
			t.Errorf("expected no overlap (-1,-1), got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("quad entirely after buffer", func(t *testing.T) {
		buf := makeTestBuf(100)
		out := make([]byte, 128)

		startLeaf, endLeaf := quadFromBuf(out, buf, 0, 5)

		if startLeaf != -1 || endLeaf != -1 {
			t.Errorf("expected no overlap (-1,-1), got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("unaligned start, quad fully in buffer", func(t *testing.T) {
		buf := makeTestBuf(400)
		out := make([]byte, 128)

		startLeaf, endLeaf := quadFromBuf(out, buf, 50, 1)

		if startLeaf != 0 || endLeaf != 3 {
			t.Errorf("expected leaves 0-3, got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("exact quad size buffer aligned", func(t *testing.T) {
		buf := makeTestBuf(127)
		out := make([]byte, 128)

		startLeaf, endLeaf := quadFromBuf(out, buf, 127, 1)

		if startLeaf != 0 || endLeaf != 3 {
			t.Errorf("expected leaves 0-3, got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("data spans only one leaf", func(t *testing.T) {
		buf := makeTestBuf(20)
		out := make([]byte, 128)

		// Buffer starts at stream byte 35, within leaf 1 [31,62)
		startLeaf, endLeaf := quadFromBuf(out, buf, 35, 0)

		if startLeaf != 1 || endLeaf != 1 {
			t.Errorf("expected leaves 1-1, got %d-%d", startLeaf, endLeaf)
		}
	})

	t.Run("data at very end of quad", func(t *testing.T) {
		buf := makeTestBuf(30)
		out := make([]byte, 128)

		// Buffer starts at stream byte 95. Due to FR32 bit shifting,
		// byte 95's bottom 2 bits go to leaf 2, top 6 bits to leaf 3.
		// So data starting at byte 95 affects leaves 2-3.
		startLeaf, endLeaf := quadFromBuf(out, buf, 95, 0)

		if startLeaf != 2 || endLeaf != 3 {
			t.Errorf("expected leaves 2-3, got %d-%d", startLeaf, endLeaf)
		}
	})
}

func TestQuadFromBuf_FR32Expansion(t *testing.T) {
	// Verify that the FR32 expansion is applied correctly

	t.Run("verify expansion matches fr32Expand", func(t *testing.T) {
		// Create input that will be fully contained
		buf := make([]byte, 127)
		for i := range buf {
			buf[i] = byte(i * 3) // recognizable pattern
		}

		out1 := make([]byte, 128)
		out2 := make([]byte, 128)

		// Get result from quadFromBuf
		startLeaf, endLeaf := quadFromBuf(out1, buf, 0, 0)
		if startLeaf != 0 || endLeaf != 3 {
			t.Fatalf("unexpected leaf range: %d-%d", startLeaf, endLeaf)
		}

		// Get result from direct fr32Expand
		fr32Expand(out2, buf)

		// Should match
		if !bytes.Equal(out1, out2) {
			t.Error("quadFromBuf output doesn't match fr32Expand output")
			for i := 0; i < 128; i++ {
				if out1[i] != out2[i] {
					t.Errorf("first diff at %d: got %d, want %d", i, out1[i], out2[i])
					break
				}
			}
		}
	})

	t.Run("partial data with zero padding", func(t *testing.T) {
		buf := make([]byte, 50)
		for i := range buf {
			buf[i] = byte(i + 100)
		}
		out := make([]byte, 128)

		// Buffer at stream pos 50, so data is at payload positions 50-99
		startLeaf, endLeaf := quadFromBuf(out, buf, 50, 0)

		if startLeaf != 1 || endLeaf != 3 {
			t.Fatalf("unexpected leaf range: %d-%d", startLeaf, endLeaf)
		}

		// Build expected: zero-padded input, then FR32 expanded
		var expectedInput [127]byte
		for i := 50; i < 100; i++ {
			expectedInput[i] = byte(i - 50 + 100)
		}
		expected := make([]byte, 128)
		fr32Expand(expected, expectedInput[:])

		if !bytes.Equal(out, expected) {
			t.Error("output doesn't match expected FR32 expansion of zero-padded input")
		}
	})
}

// generateRandomData generates deterministic random data using the same algorithm as go-random
func generateRandomData(size int64, seed int64) []byte {
	rand := randmath.New(randmath.NewSource(seed))
	data := make([]byte, size)

	for i := int64(0); i < size; {
		n := rand.Uint32()
		for j := 0; j < 4 && i < size; j++ {
			data[i] = byte(n & 0xff)
			n >>= 8
			i++
		}
	}
	return data
}

// TestEquivalence_PowerOfTwoSizes tests that v1 and v2 produce identical output
// for pieces of powerOfTwo/128*127 sizes (aligned piece sizes)
func TestEquivalence_PowerOfTwoSizes(t *testing.T) {
	// Test various power-of-2 padded sizes from 128 bytes to 1MB
	// Payload size = paddedSize / 128 * 127
	paddedSizes := []uint64{
		128,     // 127 bytes payload
		256,     // 254 bytes payload
		512,     // 508 bytes payload
		1024,    // 1016 bytes payload
		2048,    // 2032 bytes payload
		4096,    // 4064 bytes payload
		8192,    // 8128 bytes payload
		16384,   // 16256 bytes payload
		32768,   // 32512 bytes payload
		65536,   // 65024 bytes payload
		131072,  // 130048 bytes payload
		262144,  // 260096 bytes payload
		524288,  // 520192 bytes payload
		1 << 20, // 1MB padded
	}

	for _, paddedSize := range paddedSizes {
		payloadSize := int64(paddedSize / 128 * 127)
		t.Run(formatSize(payloadSize), func(t *testing.T) {
			// Generate deterministic random data
			data := generateRandomData(payloadSize, 1337)

			// Compute with v1
			v1Calc := &commp.Calc{}
			if _, err := io.Copy(v1Calc, bytes.NewReader(data)); err != nil {
				t.Fatalf("v1 Write failed: %v", err)
			}
			v1CommP, v1PaddedSize, err := v1Calc.Digest()
			if err != nil {
				t.Fatalf("v1 Digest failed: %v", err)
			}

			// Compute with v2
			v2Calc := &Calc{}
			if _, err := v2Calc.Write(data); err != nil {
				t.Fatalf("v2 Write failed: %v", err)
			}
			v2CommP, v2PaddedSize, err := v2Calc.Digest()
			if err != nil {
				t.Fatalf("v2 Digest failed: %v", err)
			}

			// Compare results
			// todo do we actually expect size to match??
			if v1PaddedSize != v2PaddedSize {
				t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
			}
			if !bytes.Equal(v1CommP, v2CommP) {
				t.Errorf("commP mismatch:\n  v1: %x\n  v2: %x", v1CommP, v2CommP)
			}
		})
	}
}

// TestEquivalence_ZeroWithOffset tests that:
// v1(largePiece with small data at offset) == v2(smallPiece, atOffset)
// This verifies the offset/streaming capability of v2
func TestEquivalence_ZeroWithOffset(t *testing.T) {
	rand := randmath.New(randmath.NewSource(42))

	// Test cases with different large piece sizes
	largePaddedSizes := []uint64{
		131072,  // 128KB padded
		262144,  // 256KB padded
		524288,  // 512KB padded
		1 << 20, // 1MB padded
	}

	for _, largePaddedSize := range largePaddedSizes {
		largePayloadSize := int64(largePaddedSize / 128 * 127)

		// Test with a few different small piece sizes and offsets
		// Offsets must be >= largePayloadSize/2 to test offset-aware commP properly
		// (data in the second half means zeros in the first half affect the tree structure)
		testCases := []struct {
			smallSize int64
			offset    int64
		}{
			{127, largePayloadSize / 2},        // one quad at 50%
			{254, largePayloadSize / 2},        // two quads at 50%
			{1016, largePayloadSize * 3 / 4},   // 8 quads at 75%
			{rand.Int63n(5000) + 500, largePayloadSize/2 + rand.Int63n(largePayloadSize/2-6000)}, // random in second half
		}

		for _, tc := range testCases {
			// Ensure offset + size doesn't exceed large piece
			if tc.offset+tc.smallSize > largePayloadSize {
				tc.offset = largePayloadSize - tc.smallSize
			}
			if tc.offset < 0 {
				tc.offset = 0
			}

			name := formatSize(largePayloadSize) + "_small" + formatSize(tc.smallSize) + "_at" + formatSize(tc.offset)
			t.Run(name, func(t *testing.T) {
				// Generate random small piece data
				smallData := generateRandomData(tc.smallSize, 9999)

				// Create large piece: zeros with small data at offset
				largePiece := make([]byte, largePayloadSize)
				copy(largePiece[tc.offset:], smallData)

				// Compute v1 on the full large piece
				v1Calc := &commp.Calc{}
				if _, err := io.Copy(v1Calc, bytes.NewReader(largePiece)); err != nil {
					t.Fatalf("v1 Write failed: %v", err)
				}
				v1CommP, v1PaddedSize, err := v1Calc.Digest()
				if err != nil {
					t.Fatalf("v1 Digest failed: %v", err)
				}

				// Compute v2 on just the small piece at offset
				v2Calc := &Calc{}
				if err := v2Calc.BeginAt(uint64(tc.offset)); err != nil {
					t.Fatalf("v2 BeginAt failed: %v", err)
				}
				if _, err := v2Calc.Write(smallData); err != nil {
					t.Fatalf("v2 Write failed: %v", err)
				}
				v2CommP, v2PaddedSize, err := v2Calc.Digest()
				if err != nil {
					t.Fatalf("v2 Digest failed: %v", err)
				}

				// Compare results
				if v1PaddedSize != v2PaddedSize {
					t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
				}
				if !bytes.Equal(v1CommP, v2CommP) {
					t.Errorf("commP mismatch:\n  v1: %x\n  v2: %x\n  offset=%d, smallSize=%d, largeSize=%d",
						v1CommP, v2CommP, tc.offset, tc.smallSize, largePayloadSize)
				}
			})
		}
	}
}

// TestEquivalence_RandomSizes tests v1 vs v2 for various non-power-of-2 sizes
func TestEquivalence_RandomSizes(t *testing.T) {
	rand := randmath.New(randmath.NewSource(12345))

	// Minimum size: 127 bytes (1 complete quad = 4 leaves)
	// v2 requires at least 1 complete quad for proper equivalence
	minSize := 127

	for i := 0; i < 10; i++ {
		// Random size between minSize and 100KB
		payloadSize := int64(rand.Intn(100000-minSize) + minSize)

		t.Run(formatSize(payloadSize), func(t *testing.T) {
			data := generateRandomData(payloadSize, int64(i*1000))

			// v1
			v1Calc := &commp.Calc{}
			if _, err := io.Copy(v1Calc, bytes.NewReader(data)); err != nil {
				t.Fatalf("v1 Write failed: %v", err)
			}
			v1CommP, v1PaddedSize, err := v1Calc.Digest()
			if err != nil {
				t.Fatalf("v1 Digest failed: %v", err)
			}

			// v2
			v2Calc := &Calc{}
			if _, err := v2Calc.Write(data); err != nil {
				t.Fatalf("v2 Write failed: %v", err)
			}
			v2CommP, v2PaddedSize, err := v2Calc.Digest()
			if err != nil {
				t.Fatalf("v2 Digest failed: %v", err)
			}

			if v1PaddedSize != v2PaddedSize {
				t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
			}
			if !bytes.Equal(v1CommP, v2CommP) {
				t.Errorf("commP mismatch:\n  v1: %x\n  v2: %x", v1CommP, v2CommP)
			}
		})
	}
}

func formatSize(size int64) string {
	if size >= 1<<20 {
		return fmt.Sprintf("%dMB", size/(1<<20))
	}
	if size >= 1<<10 {
		return fmt.Sprintf("%dKB", size/(1<<10))
	}
	return fmt.Sprintf("%dB", size)
}

// TestBeginAt_QuadAligned tests BeginAt with offsets aligned to quad boundaries (127 bytes)
func TestBeginAt_QuadAligned(t *testing.T) {
	// Test offsets at exact quad boundaries
	quadBoundaries := []int64{
		127,       // 1 quad
		127 * 2,   // 2 quads
		127 * 4,   // 4 quads
		127 * 8,   // 8 quads
		127 * 16,  // 16 quads
		127 * 64,  // 64 quads
		127 * 256, // 256 quads
		127 * 512, // 512 quads (64KB)
	}

	for _, offset := range quadBoundaries {
		t.Run(fmt.Sprintf("offset_%d", offset), func(t *testing.T) {
			dataSize := int64(127 * 4) // 4 quads of data
			data := generateRandomData(dataSize, 12345)

			// v1: create full piece with zeros + data
			totalSize := offset + dataSize
			largePiece := make([]byte, totalSize)
			copy(largePiece[offset:], data)

			v1Calc := &commp.Calc{}
			if _, err := io.Copy(v1Calc, bytes.NewReader(largePiece)); err != nil {
				t.Fatalf("v1 Write failed: %v", err)
			}
			v1CommP, v1PaddedSize, err := v1Calc.Digest()
			if err != nil {
				t.Fatalf("v1 Digest failed: %v", err)
			}

			// v2: use BeginAt
			v2Calc := &Calc{}
			if err := v2Calc.BeginAt(uint64(offset)); err != nil {
				t.Fatalf("v2 BeginAt failed: %v", err)
			}
			if _, err := v2Calc.Write(data); err != nil {
				t.Fatalf("v2 Write failed: %v", err)
			}
			v2CommP, v2PaddedSize, err := v2Calc.Digest()
			if err != nil {
				t.Fatalf("v2 Digest failed: %v", err)
			}

			if v1PaddedSize != v2PaddedSize {
				t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
			}
			if !bytes.Equal(v1CommP, v2CommP) {
				t.Errorf("commP mismatch at offset %d:\n  v1: %x\n  v2: %x", offset, v1CommP, v2CommP)
			}
		})
	}
}

// TestBeginAt_MidQuad tests BeginAt with offsets in the middle of quads (non-127-aligned)
func TestBeginAt_MidQuad(t *testing.T) {
	testCases := []struct {
		name   string
		offset int64
	}{
		{"mid_first_quad", 50},             // Middle of first quad
		{"leaf_boundary_31", 31},           // Start of leaf 1
		{"leaf_boundary_62", 62},           // Start of leaf 2
		{"leaf_boundary_93", 93},           // Start of leaf 3
		{"mid_second_quad", 127 + 50},      // Middle of second quad
		{"mid_tenth_quad", 127*10 + 63},    // Middle of tenth quad
		{"arbitrary_1234", 1234},           // Arbitrary offset
		{"arbitrary_5678", 5678},           // Another arbitrary offset
		{"large_unaligned", 127*100 + 100}, // Large unaligned offset
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(254) // 2 quads of data
			data := generateRandomData(dataSize, 54321)

			// v1: create full piece with zeros + data
			totalSize := tc.offset + dataSize
			largePiece := make([]byte, totalSize)
			copy(largePiece[tc.offset:], data)

			v1Calc := &commp.Calc{}
			if _, err := io.Copy(v1Calc, bytes.NewReader(largePiece)); err != nil {
				t.Fatalf("v1 Write failed: %v", err)
			}
			v1CommP, v1PaddedSize, err := v1Calc.Digest()
			if err != nil {
				t.Fatalf("v1 Digest failed: %v", err)
			}

			// v2: use BeginAt
			v2Calc := &Calc{}
			if err := v2Calc.BeginAt(uint64(tc.offset)); err != nil {
				t.Fatalf("v2 BeginAt failed: %v", err)
			}
			if _, err := v2Calc.Write(data); err != nil {
				t.Fatalf("v2 Write failed: %v", err)
			}
			v2CommP, v2PaddedSize, err := v2Calc.Digest()
			if err != nil {
				t.Fatalf("v2 Digest failed: %v", err)
			}

			if v1PaddedSize != v2PaddedSize {
				t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
			}
			if !bytes.Equal(v1CommP, v2CommP) {
				t.Errorf("commP mismatch at offset %d:\n  v1: %x\n  v2: %x", tc.offset, v1CommP, v2CommP)
			}
		})
	}
}

// TestBeginAt_SmallData tests BeginAt with very small data sizes at various offsets
func TestBeginAt_SmallData(t *testing.T) {
	// Small data sizes that don't fill complete quads
	smallSizes := []int64{1, 10, 31, 50, 100, 126}
	offsets := []int64{0, 50, 127, 127 * 10, 127 * 100}

	for _, size := range smallSizes {
		for _, offset := range offsets {
			name := fmt.Sprintf("size%d_offset%d", size, offset)
			t.Run(name, func(t *testing.T) {
				data := generateRandomData(size, size*1000+offset)

				// v1: create full piece
				totalSize := offset + size
				// Ensure minimum size for v1 (65 bytes)
				if totalSize < 65 {
					totalSize = 65
				}
				largePiece := make([]byte, totalSize)
				copy(largePiece[offset:], data)

				v1Calc := &commp.Calc{}
				if _, err := io.Copy(v1Calc, bytes.NewReader(largePiece)); err != nil {
					t.Fatalf("v1 Write failed: %v", err)
				}
				v1CommP, v1PaddedSize, err := v1Calc.Digest()
				if err != nil {
					t.Fatalf("v1 Digest failed: %v", err)
				}

				// v2: use BeginAt
				v2Calc := &Calc{}
				if err := v2Calc.BeginAt(uint64(offset)); err != nil {
					t.Fatalf("v2 BeginAt failed: %v", err)
				}
				if _, err := v2Calc.Write(data); err != nil {
					t.Fatalf("v2 Write failed: %v", err)
				}
				v2CommP, v2PaddedSize, err := v2Calc.Digest()
				if err != nil {
					t.Fatalf("v2 Digest failed: %v", err)
				}

				if v1PaddedSize != v2PaddedSize {
					t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
				}
				if !bytes.Equal(v1CommP, v2CommP) {
					t.Errorf("commP mismatch (size=%d, offset=%d):\n  v1: %x\n  v2: %x",
						size, offset, v1CommP, v2CommP)
				}
			})
		}
	}
}

// TestBeginAt_TreeLevelBoundaries tests offsets that create boundaries at different tree levels
func TestBeginAt_TreeLevelBoundaries(t *testing.T) {
	// Offsets that create boundaries at specific tree levels
	// Level L boundary: offset = 2^L * 32 bytes (in padded space) = 2^L * 31.75 bytes (in payload space)
	// Using quad-aligned offsets for simplicity: 127 * 2^(L-2) bytes
	testCases := []struct {
		name   string
		offset int64
	}{
		{"level_2_boundary", 127 * 1},       // 4 leaves = 1 quad
		{"level_3_boundary", 127 * 2},       // 8 leaves = 2 quads
		{"level_4_boundary", 127 * 4},       // 16 leaves = 4 quads
		{"level_5_boundary", 127 * 8},       // 32 leaves = 8 quads
		{"level_6_boundary", 127 * 16},      // 64 leaves = 16 quads
		{"level_7_boundary", 127 * 32},      // 128 leaves = 32 quads
		{"level_8_boundary", 127 * 64},      // 256 leaves = 64 quads
		{"level_9_boundary", 127 * 128},     // 512 leaves = 128 quads
		{"level_10_boundary", 127 * 256},    // 1024 leaves = 256 quads
		{"level_11_boundary", 127 * 512},    // 2048 leaves = 512 quads
		{"level_12_boundary", 127 * 1024},   // 4096 leaves = 1024 quads (128KB)
		{"just_past_level_5", 127*8 + 50},   // Just past level 5 boundary
		{"just_past_level_8", 127*64 + 100}, // Just past level 8 boundary
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(127 * 8) // 8 quads = 32 leaves
			data := generateRandomData(dataSize, 99999)

			// v1
			totalSize := tc.offset + dataSize
			largePiece := make([]byte, totalSize)
			copy(largePiece[tc.offset:], data)

			v1Calc := &commp.Calc{}
			if _, err := io.Copy(v1Calc, bytes.NewReader(largePiece)); err != nil {
				t.Fatalf("v1 Write failed: %v", err)
			}
			v1CommP, v1PaddedSize, err := v1Calc.Digest()
			if err != nil {
				t.Fatalf("v1 Digest failed: %v", err)
			}

			// v2
			v2Calc := &Calc{}
			if err := v2Calc.BeginAt(uint64(tc.offset)); err != nil {
				t.Fatalf("v2 BeginAt failed: %v", err)
			}
			if _, err := v2Calc.Write(data); err != nil {
				t.Fatalf("v2 Write failed: %v", err)
			}
			v2CommP, v2PaddedSize, err := v2Calc.Digest()
			if err != nil {
				t.Fatalf("v2 Digest failed: %v", err)
			}

			if v1PaddedSize != v2PaddedSize {
				t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
			}
			if !bytes.Equal(v1CommP, v2CommP) {
				t.Errorf("commP mismatch:\n  v1: %x\n  v2: %x", v1CommP, v2CommP)
			}
		})
	}
}

// TestStitching_MultipleChunks tests stitching across multiple chunks with varying sizes
func TestStitching_MultipleChunks(t *testing.T) {
	// Test data sizes that span multiple chunks
	// TargetDigestChunk is roughly 4MB / 128 * 127 ≈ 4MB payload per chunk
	// Use smaller sizes that still create multiple chunks

	// Save original and use smaller chunk size for testing
	origChunk := TargetDigestChunk
	defer func() { TargetDigestChunk = origChunk }()

	chunkSizes := []uint64{
		127 * 8,   // 8 quads per chunk (1KB)
		127 * 16,  // 16 quads per chunk (2KB)
		127 * 32,  // 32 quads per chunk (4KB)
		127 * 64,  // 64 quads per chunk (8KB)
		127 * 128, // 128 quads per chunk (16KB)
	}

	for _, chunkSize := range chunkSizes {
		TargetDigestChunk = chunkSize

		// Test various data sizes relative to chunk size
		dataSizes := []int64{
			int64(chunkSize) - 127,     // Just under 1 chunk
			int64(chunkSize),           // Exactly 1 chunk
			int64(chunkSize) + 127,     // Just over 1 chunk
			int64(chunkSize) * 2,       // 2 chunks
			int64(chunkSize)*2 + 500,   // 2+ chunks
			int64(chunkSize) * 3,       // 3 chunks
			int64(chunkSize)*3 + 1000,  // 3+ chunks
			int64(chunkSize) * 5,       // 5 chunks
			int64(chunkSize)*7 + 12345, // 7+ chunks with odd remainder
		}

		for _, dataSize := range dataSizes {
			name := fmt.Sprintf("chunk%d_data%d", chunkSize, dataSize)
			t.Run(name, func(t *testing.T) {
				data := generateRandomData(dataSize, dataSize)

				// v1
				v1Calc := &commp.Calc{}
				if _, err := io.Copy(v1Calc, bytes.NewReader(data)); err != nil {
					t.Fatalf("v1 Write failed: %v", err)
				}
				v1CommP, v1PaddedSize, err := v1Calc.Digest()
				if err != nil {
					t.Fatalf("v1 Digest failed: %v", err)
				}

				// v2
				v2Calc := &Calc{}
				if _, err := v2Calc.Write(data); err != nil {
					t.Fatalf("v2 Write failed: %v", err)
				}
				v2CommP, v2PaddedSize, err := v2Calc.Digest()
				if err != nil {
					t.Fatalf("v2 Digest failed: %v", err)
				}

				if v1PaddedSize != v2PaddedSize {
					t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
				}
				if !bytes.Equal(v1CommP, v2CommP) {
					t.Errorf("commP mismatch:\n  v1: %x\n  v2: %x", v1CommP, v2CommP)
				}
			})
		}
	}
}

// TestStitching_WithOffset_MultipleChunks tests stitching with BeginAt across multiple chunks
func TestStitching_WithOffset_MultipleChunks(t *testing.T) {
	// Use smaller chunk size for testing
	origChunk := TargetDigestChunk
	TargetDigestChunk = 127 * 32 // 32 quads per chunk (4KB)
	defer func() { TargetDigestChunk = origChunk }()

	testCases := []struct {
		name     string
		offset   int64
		dataSize int64
	}{
		{"offset_1chunk_data_2chunks", 127 * 32, 127 * 64},
		{"offset_half_chunk_data_3chunks", 127 * 16, 127 * 96},
		{"offset_2chunks_data_1chunk", 127 * 64, 127 * 32},
		{"offset_unaligned_data_multiple", 127*32 + 500, 127 * 80},
		{"large_offset_small_data", 127 * 200, 127 * 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := generateRandomData(tc.dataSize, tc.offset+tc.dataSize)

			// v1
			totalSize := tc.offset + tc.dataSize
			largePiece := make([]byte, totalSize)
			copy(largePiece[tc.offset:], data)

			v1Calc := &commp.Calc{}
			if _, err := io.Copy(v1Calc, bytes.NewReader(largePiece)); err != nil {
				t.Fatalf("v1 Write failed: %v", err)
			}
			v1CommP, v1PaddedSize, err := v1Calc.Digest()
			if err != nil {
				t.Fatalf("v1 Digest failed: %v", err)
			}

			// v2
			v2Calc := &Calc{}
			if err := v2Calc.BeginAt(uint64(tc.offset)); err != nil {
				t.Fatalf("v2 BeginAt failed: %v", err)
			}
			if _, err := v2Calc.Write(data); err != nil {
				t.Fatalf("v2 Write failed: %v", err)
			}
			v2CommP, v2PaddedSize, err := v2Calc.Digest()
			if err != nil {
				t.Fatalf("v2 Digest failed: %v", err)
			}

			if v1PaddedSize != v2PaddedSize {
				t.Errorf("padded size mismatch: v1=%d, v2=%d", v1PaddedSize, v2PaddedSize)
			}
			if !bytes.Equal(v1CommP, v2CommP) {
				t.Errorf("commP mismatch:\n  v1: %x\n  v2: %x", v1CommP, v2CommP)
			}
		})
	}
}

// TestStitching_IncrementalWrites tests that multiple Write calls produce same result as single Write
func TestStitching_IncrementalWrites(t *testing.T) {
	dataSize := int64(127 * 100) // 100 quads
	data := generateRandomData(dataSize, 777)

	// Single write
	v2Single := &Calc{}
	if _, err := v2Single.Write(data); err != nil {
		t.Fatalf("single Write failed: %v", err)
	}
	singleCommP, singleSize, err := v2Single.Digest()
	if err != nil {
		t.Fatalf("single Digest failed: %v", err)
	}

	// Multiple small writes
	writeSizes := []int{1, 10, 50, 100, 127, 200, 500, 1000}
	for _, writeSize := range writeSizes {
		t.Run(fmt.Sprintf("writeSize_%d", writeSize), func(t *testing.T) {
			v2Multi := &Calc{}
			remaining := data
			for len(remaining) > 0 {
				toWrite := writeSize
				if toWrite > len(remaining) {
					toWrite = len(remaining)
				}
				if _, err := v2Multi.Write(remaining[:toWrite]); err != nil {
					t.Fatalf("incremental Write failed: %v", err)
				}
				remaining = remaining[toWrite:]
			}
			multiCommP, multiSize, err := v2Multi.Digest()
			if err != nil {
				t.Fatalf("incremental Digest failed: %v", err)
			}

			if singleSize != multiSize {
				t.Errorf("size mismatch: single=%d, multi=%d", singleSize, multiSize)
			}
			if !bytes.Equal(singleCommP, multiCommP) {
				t.Errorf("commP mismatch:\n  single: %x\n  multi:  %x", singleCommP, multiCommP)
			}
		})
	}
}

// TestReset verifies that Reset properly clears state for reuse
func TestReset(t *testing.T) {
	data1 := generateRandomData(1000, 111)
	data2 := generateRandomData(2000, 222)

	calc := &Calc{}

	// First computation
	if _, err := calc.Write(data1); err != nil {
		t.Fatalf("first Write failed: %v", err)
	}
	commP1, _, err := calc.Digest()
	if err != nil {
		t.Fatalf("first Digest failed: %v", err)
	}

	// Reset and compute again with different data
	calc.Reset()
	if _, err := calc.Write(data2); err != nil {
		t.Fatalf("second Write failed: %v", err)
	}
	commP2, _, err := calc.Digest()
	if err != nil {
		t.Fatalf("second Digest failed: %v", err)
	}

	// Results should be different
	if bytes.Equal(commP1, commP2) {
		t.Error("commP should be different after Reset with different data")
	}

	// Verify second result matches fresh computation
	freshCalc := &Calc{}
	if _, err := freshCalc.Write(data2); err != nil {
		t.Fatalf("fresh Write failed: %v", err)
	}
	freshCommP, _, err := freshCalc.Digest()
	if err != nil {
		t.Fatalf("fresh Digest failed: %v", err)
	}

	if !bytes.Equal(commP2, freshCommP) {
		t.Errorf("Reset didn't properly clear state:\n  after reset: %x\n  fresh:       %x", commP2, freshCommP)
	}
}

// Benchmarks

func BenchmarkV2_Write(b *testing.B) {
	sizes := []int64{
		127,          // 1 quad
		127 * 8,      // 8 quads (1KB)
		127 * 80,     // ~10KB
		127 * 800,    // ~100KB
		127 * 8000,   // ~1MB
		127 * 80000,  // ~10MB
		127 * 400000, // ~50MB
	}

	for _, size := range sizes {
		data := generateRandomData(size, 12345)
		b.Run(formatSize(size), func(b *testing.B) {
			b.SetBytes(size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				calc := &Calc{}
				calc.Write(data)
				calc.Digest()
			}
		})
	}
}

func BenchmarkV1_Write(b *testing.B) {
	sizes := []int64{
		127,          // 1 quad
		127 * 8,      // 8 quads (1KB)
		127 * 80,     // ~10KB
		127 * 800,    // ~100KB
		127 * 8000,   // ~1MB
		127 * 80000,  // ~10MB
		127 * 400000, // ~50MB
	}

	for _, size := range sizes {
		data := generateRandomData(size, 12345)
		b.Run(formatSize(size), func(b *testing.B) {
			b.SetBytes(size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				calc := &commp.Calc{}
				io.Copy(calc, bytes.NewReader(data))
				calc.Digest()
			}
		})
	}
}

func BenchmarkV2_WithOffset(b *testing.B) {
	// Benchmark offset-aware CommP computation
	dataSize := int64(127 * 800) // ~100KB of actual data
	data := generateRandomData(dataSize, 12345)

	offsets := []int64{
		0,
		127 * 100,   // ~12KB offset
		127 * 1000,  // ~125KB offset
		127 * 10000, // ~1.2MB offset
	}

	for _, offset := range offsets {
		b.Run(fmt.Sprintf("offset_%s", formatSize(offset)), func(b *testing.B) {
			b.SetBytes(dataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				calc := &Calc{}
				calc.BeginAt(uint64(offset))
				calc.Write(data)
				calc.Digest()
			}
		})
	}
}

func BenchmarkV2_Parallel(b *testing.B) {
	// Test parallel processing benefit with different parallelism levels
	dataSize := int64(127 * 80000) // ~10MB
	data := generateRandomData(dataSize, 12345)

	parallelisms := []int{1, 2, 4, 8, 16}
	origParallelism := DefaultParallelism
	defer func() { DefaultParallelism = origParallelism }()

	for _, p := range parallelisms {
		DefaultParallelism = p
		b.Run(fmt.Sprintf("parallel_%d", p), func(b *testing.B) {
			b.SetBytes(dataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				calc := &Calc{}
				calc.Write(data)
				calc.Digest()
			}
		})
	}
}

func BenchmarkStitching(b *testing.B) {
	// Benchmark stitching overhead with different chunk sizes
	dataSize := int64(127 * 8000) // ~1MB
	data := generateRandomData(dataSize, 12345)

	origChunk := TargetDigestChunk
	defer func() { TargetDigestChunk = origChunk }()

	chunkSizes := []uint64{
		127 * 8,    // Very small chunks (lots of stitching)
		127 * 64,   // Small chunks
		127 * 512,  // Medium chunks
		127 * 4096, // Large chunks (less stitching)
	}

	for _, chunkSize := range chunkSizes {
		TargetDigestChunk = chunkSize
		numChunks := dataSize / int64(chunkSize)
		b.Run(fmt.Sprintf("chunks_%d", numChunks), func(b *testing.B) {
			b.SetBytes(dataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				calc := &Calc{}
				calc.Write(data)
				calc.Digest()
			}
		})
	}
}
