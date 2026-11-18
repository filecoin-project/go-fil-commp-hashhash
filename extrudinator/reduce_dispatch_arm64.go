package extrudinator

// HasSIMDReduce always true on arm64: NEON SHA256 extensions assumed.
// PairwiseReduceBuffer in reduce_p9_arm64.go calls
// the kernel directly rather than through simdReduceFunc.
func HasSIMDReduce() bool { return true }
