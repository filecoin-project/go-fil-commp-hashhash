//go:build amd64

package extrudinator

var extrudeFunc = ExtrudeQuadsSSE

func ExtrudeQuads(buf []byte) { extrudeFunc(buf) }
