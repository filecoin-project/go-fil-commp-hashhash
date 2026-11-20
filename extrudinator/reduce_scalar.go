//go:build amd64

package extrudinator

import (
	"hash"

	sha256simd "github.com/minio/sha256-simd"
)

func pairwiseReduceScalar(buf []byte, byteLen int, outPairCount int) {
	h := sha256simd.New()

	nPairs := byteLen / 64
	for nPairs > outPairCount && nPairs >= 1 {
		reduceOneLevel(h, buf, nPairs)
		nPairs /= 2
	}
}

func reduceOneLevel(h hash.Hash, buf []byte, nPairs int) {
	for i := 0; i < nPairs; i++ {
		h.Reset()
		h.Write(buf[i*64 : i*64+32])
		h.Write(buf[i*64+32 : i*64+64])
		h.Sum(buf[i*32 : i*32 : i*32+32])
		buf[i*32+31] &= 0x3F
	}
}
