//go:build amd64

/*
 * extrude_p9_avx512.go - Go declarations for Plan 9 AVX512 extrude kernels
 *
 * Two SIMD cores for FR32 extrusion (127B src -> 128B dst per quad):
 *
 * input:  dst []byte (at least count*128 bytes)
 *         src []byte (at least count*127 bytes)
 *
 * output: dst filled with FR32-extruded quads
 *
 * extrudeQuadsAvx512Core:   SIMD, one quad per iteration
 *                           (any count >= 1)
 *
 * extrudeQuads4xAvx512Core: SIMD, four quads per iteration
 *                           (count MUST be multiple of 4)
 */

package extrudinator

import "golang.org/x/sys/cpu"

//go:noescape
func extrudeQuadsAvx512Core(buf *byte, count uint64)

//go:noescape
func extrudeQuads4xAvx512Core(buf *byte, count uint64)

// the kernel uses VPSHLDQ, which is AVX-512 VBMI2
// Skylake-X and Cascade Lake have AVX-512 without it and stay on SSE
func init() {
	if cpu.X86.HasAVX512 && cpu.X86.HasAVX512VBMI2 {
		extrudeFunc = extrudeQuadsAvx512
	}
}

// extrudeQuadsAvx512 — convenience: dispatches to:
//                                   ↓  4x core, whole buf (count multiple of 4)
//                                   ⮑ 1x core, whole buf (any other count)
//
// input:  dst []byte (at least len(src)/127 * 128 bytes)
//         src []byte (FR32 payload, 127 bytes per quad)
//
// output: dst filled with FR32-extruded quads
//

func extrudeQuadsAvx512(buf []byte) {
	count := len(buf) / 128
	if count == 0 {
		return
	}

	if count%4 == 0 {
		extrudeQuads4xAvx512Core(&buf[0], uint64(count))
	} else {
		extrudeQuadsAvx512Core(&buf[0], uint64(count))
	}
}
