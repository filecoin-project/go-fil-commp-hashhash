//go:build arm64

/*
 * extrude_p9_neon.go — Go declarations for Plan 9 NEON extrude kernels
 *
 * input:  dst []byte (at least count*128 bytes)
 *         src []byte (at least count*127 bytes)
 *
 * output: dst filled with FR32-extruded quads
 *         (127B src -> 128B dst per quad)
 *
 * Boundary logic:
 *   2x unrolled bulk -> 1x remainder -> temp buffer for last quad
 *
 * extrudeQuadsPlan9Core:   1-quad-at-a-time loop, any count ≥ 1
 * extrudeQuads2xPlan9Core: 2-quad unrolled loop, count MUST be a multiple of 2
 *
 */
package extrudinator

//go:nosplit
//go:noescape
func extrudeQuadsPlan9Core(buf *byte, count uint64)

//go:nosplit
//go:noescape
func extrudeQuads2xPlan9Core(buf *byte, count uint64)

// ExtrudeQuadsNeon processes FR32 extrusion using ARM64 NEON via Plan 9 assembly.
// count even: 2x core does whole buf
// count odd:  1x core does whole buf
func extrudeQuadsNeon(buf []byte) {
	count := len(buf) / 128
	if count == 0 {
		return
	}

	if count >= 2 && count%2 == 0 {
		extrudeQuads2xPlan9Core(&buf[0], uint64(count))
	} else {
		extrudeQuadsPlan9Core(&buf[0], uint64(count))
	}
}

// ExtrudeQuads is the exported entry point -> NEON path (arm64)
func ExtrudeQuads(buf []byte) { extrudeQuadsNeon(buf) }
