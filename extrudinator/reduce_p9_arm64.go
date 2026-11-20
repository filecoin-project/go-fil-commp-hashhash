//go:build arm64

// reduce_p9_arm64.go - Go declarations for Plan 9 NEON pairwise reduce kernel
//
// SIMD core for CommP pairwise SHA256 tree reduction:
//
// input:  buf []byte - pairs of 32B hashes laid out as [L0|R0|L1|R1|...]
//                      byteLen = n_pairs * 64 (each pair is 64B)
//                      byteLen must be 128 * 2^N
//                      (n_pairs is power of 2, minimum two pairs)
//
// output: buf reduced in-place
//         results contiguous at buf[0 .. result_pairs * 32]
//         result_pairs = outPairCount (1 if outPairCount = 0)
//         each hash truncated to 254 bits
//
// outPairCount: stop reducing when n_pairs <= this value
//               0 = full tree reduction to single root
//
// pairwiseReduceBufferX4Neon: SIMD, 4 hashes per batch
//   minimum input: 2 pairs (128 bytes)
//   all tree levels processed in a single call
//   constraint: n_pairs must be power of 2, callers pre-pad
//

package extrudinator

//go:nosplit
//go:noescape
func pairwiseReduceBufferX4Neon(buf *byte, byteLen uint64, outPairCount uint64)

// PairwiseReduceBuffer - entry point for pairwise SHA256 tree reduction
//
// input:  bytes with pairs of 32B hashes, byteLen = n_pairs * 64
// output: bytes reduced in-place, results at bufs[0 .. final_pairs * 32]
func PairwiseReduceBuffer(buf []byte, byteLen, outPairCount int) {
	// fmt.Printf("ReduceP9: byteLen=%d nPairs=%d outPairCount=%d\n", byteLen, byteLen/64, outPairCount)
	pairwiseReduceBufferX4Neon(&buf[0], uint64(byteLen), uint64(outPairCount))
}
