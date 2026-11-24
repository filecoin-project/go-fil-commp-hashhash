//go:build amd64

/*
 * extrude_p9_sse.go - Go declarations for Plan 9 SSE extrude kernel
 *
 * SIMD core for FR32 extrusion (127B src -> 128B dst per quad), in-place.
 *
 * input:  buf []byte (at least count*128 bytes)
 *         first count*127 bytes hold src; kernel rewrites in-place as
 *         count*128 bytes (FR32-padded)
 *
 * 128-bit SSE (SSSE3) — same algorithm as NEON and WASM SIMD.
 * No 4x unrolled variant — only 16 XMM registers available,
 * one quad uses 11, no room for a second.
 *
 * vs AVX512: 128-bit XMM not 256-bit YMM, PALIGNR+shift+or
 *            not VPSHLDQ, 5 instructions per node not 3.
 *            Available on all x86-64 (no AVX512 required).
 *
 * extrudeQuadsSSECore: SIMD, one quad per iteration, any count >= 0
 */
package extrudinator

//go:noescape
func extrudeQuadsSSECore(buf *byte, count uint64)

// ExtrudeQuadsSSE - in-place extrude, single buffer.
//
// input:  buf []byte (at least count*128 bytes)
//         first count*127 bytes hold packed src
//
// output: buf rewritten as count*128 FR32-padded bytes

func ExtrudeQuadsSSE(buf []byte) {
	count := len(buf) / 128
	if count == 0 {
		return
	}
	extrudeQuadsSSECore(&buf[0], uint64(count))
}
