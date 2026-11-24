package extrudinator

var simdReduceFunc func([]byte, int, int)

func HasSIMDReduce() bool { return simdReduceFunc != nil }

func PairwiseReduceBuffer(buf []byte, byteLen, outPairCount int) {
	if simdReduceFunc != nil {
		simdReduceFunc(buf, byteLen, outPairCount)
		return
	}

	pairwiseReduceScalar(buf, byteLen, outPairCount)
}
