//go:build !amd64 && !arm64

package extrudinator

// no SIMD reduce on this arch, the caller keeps its Go loop
func HasSIMDReduce() bool { return false }

// never called here: HasSIMDReduce is false
func PairwiseReduceBuffer(buf []byte, byteLen, outPairCount int) {}

// in-place extrude through the scalar ExtrudeQuadsBytewise, which reads src and writes dst
func ExtrudeQuads(buf []byte) {
	count := len(buf) / 128
	if count == 0 {
		return
	}

	src := make([]byte, count*127)
	copy(src, buf[:count*127])
	ExtrudeQuadsBytewise(buf, src)
}
