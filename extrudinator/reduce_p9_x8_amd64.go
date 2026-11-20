//go:build amd64

// reduce_p9_x8_amd64.go - Go declarations for Plan 9 AVX2 x8 pairwise reduce kernel
//
// AVX2 fallback for machines without AVX-512. Same contract as the x16 kernel:
//
// input:  buf []byte - pairs of 32B hashes laid out as [L0|R0|L1|R1|...]
//                      byteLen = n_pairs * 64 (each pair is 64B)
//                      byteLen must be 128 * 2^N (n_pairs power of 2, min two pairs)
//                      buf must have enough capacity for the kernel's scratch writes
//
// output: buf reduced in-place
//         results contiguous at buf[0 .. result_pairs * 32]
//         result_pairs = outPairCount (1 if outPairCount = 0)
//         each hash truncated to 254 bits
//
// outPairCount: stop reducing when n_pairs <= this value
//               0 = full tree reduction to single root
//
// pairwiseReduceBufferX8Avx2:
//   wrapper -> reads args from FP, calls inner
//
// pairwiseReduceBufferX8Avx2Inner:
//   actual kernel - manages own stack (832B frame + 6 GPR saves)
//   wrapper+inner split required on x86 for Go runtime SPWRITE
//
// Dispatch: init() fires only on (AVX2 && !AVX-512) so x16 wins when both
// are available. On AVX-512-only machines simdReduceFunc is set by
// reduce_p9_amd64.go; this file leaves it alone.

package extrudinator

import "golang.org/x/sys/cpu"

//go:noescape
func pairwiseReduceBufferX8Avx2(buf *byte, byteLen int, outPairCount int)

//go:noescape
func pairwiseReduceBufferX8Avx2Inner()

func init() {
	if cpu.X86.HasAVX2 && !cpu.X86.HasAVX512 {
		simdReduceFunc = func(buf []byte, byteLen, outPairCount int) {
			pairwiseReduceBufferX8Avx2(&buf[0], byteLen, outPairCount)
		}
	}
}
