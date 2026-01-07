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

		// Buffer starts at stream byte 95, within leaf 3 [93,127)
		startLeaf, endLeaf := quadFromBuf(out, buf, 95, 0)

		if startLeaf != 3 || endLeaf != 3 {
			t.Errorf("expected leaves 3-3, got %d-%d", startLeaf, endLeaf)
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
		testCases := []struct {
			smallSize int64
			offset    int64
		}{
			{127, 0},                      // one quad at start
			{127, largePayloadSize - 127}, // one quad at end
			{254, largePayloadSize / 4},   // two quads at 25%
			{1016, largePayloadSize / 2},  // 8 quads at 50%
			{rand.Int63n(5000) + 500, rand.Int63n(largePayloadSize - 6000)}, // random
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
