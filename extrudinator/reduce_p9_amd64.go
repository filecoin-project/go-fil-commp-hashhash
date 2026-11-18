//go:build amd64

// reduce_p9_amd64.go - Go declarations for Plan 9 AVX-512 pairwise reduce kernel
//
// SIMD core for CommP pairwise SHA256 tree reduction:
//
// input:  buf []byte - pairs of 32B hashes laid out as [L0|R0|L1|R1|...]
//                      byteLen = n_pairs * 64 (each pair is 64B)
//                      byteLen must be 128 * 2^N
//                      (n_pairs is power of 2, minimum two pairs)
//                      cap(buf) must be at least byteLen + 512
//                      (kernel writes 512B internally regardless of pair count)
//
// output: buf reduced in-place
//         results contiguous at buf[0 .. result_pairs * 32]
//         result_pairs = outPairCount (1 if outPairCount = 0)
//         each hash truncated to 254 bits
//
// outPairCount: stop reducing when n_pairs <= this value
//               0 = full tree reduction to single root
//
// pairwiseReduceBufferX16Soa:
//   wrapper -> reads args from FP, calls inner (below)
//
// pairwiseReduceBufferX16SoaInner:
//   actual kernel - manages own stack
//   wrapper+inner split required on x86:
//   kernel needs scratch stack space, Go runtime doesn't allow that
//   in a single function - wrapper provides the Go-managed frame
//
// SIMD, 16 hashes per batch
//   all tree levels processed in a single call
//   constraint: n_pairs must be power of 2, callers pre-pad
//   constraint: cap(buf) >= byteLen + 512

package extrudinator

import "golang.org/x/sys/cpu"

//go:noescape
func pairwiseReduceBufferX16Soa(buf *byte, byteLen int, outPairCount int)

//go:noescape
func pairwiseReduceBufferX16SoaInner()

func init() {
	if cpu.X86.HasAVX512 {
		simdReduceFunc = func(buf []byte, byteLen, outPairCount int) {
			pairwiseReduceBufferX16Soa(&buf[0], byteLen, outPairCount)
		}
	}
}
