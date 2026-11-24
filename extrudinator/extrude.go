package extrudinator

// ExtrudeQuadsBytewise is the byte-level shift version (the commented-out code in commp.go).
func ExtrudeQuadsBytewise(dst, src []byte) {
	count := len(src) / 127
	for j := 0; j < count; j++ {
		input := src[j*127 : (j+1)*127]
		exp := dst[j*128 : (j+1)*128]

		copy(exp[:32], input[:32])
		exp[31] &= 0x3F

		for i := 31; i < 63; i++ {
			exp[i+1] = input[i+1]<<2 | input[i]>>6
		}
		exp[63] &= 0x3F

		for i := 63; i < 95; i++ {
			exp[i+1] = input[i+1]<<4 | input[i]>>4
		}
		exp[95] &= 0x3F

		for i := 95; i < 126; i++ {
			exp[i+1] = input[i+1]<<6 | input[i]>>2
		}
		exp[127] = input[126] >> 2
	}
}
