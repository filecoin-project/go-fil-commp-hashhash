package commp

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	randmath "math/rand"
)

type testCase struct {
	PayloadSize int64
	PieceSize   uint64
	RawCommP    []byte
}

func TestCommP(t *testing.T) {
	t.Parallel()

	tests, err := getTestCases("testdata/random.txt")
	if err != nil {
		t.Fatal(err)
	}

	if testing.Short() {
		tests = tests[:90]
	}

	for _, test := range tests {
		test := test
		t.Run(fmt.Sprintf("%d", test.PayloadSize), func(t *testing.T) {
			t.Parallel()
			pr, pw := io.Pipe()
			var randErr error
			go func() {
				defer pw.Close()

				// This go-routine logic is the same as in
				// jbenet/go-random. It's copied here to allow doing
				// parallel tests, since that library uses a singleton seed
				// for the random source.
				//
				// Recall that go-random is used to deterministically generate
				// the data in Lotus or any other source of truth for these
				// tests. So it's important to have the same logic here for
				// deterministic data generation.
				rand := randmath.New(randmath.NewSource(1337))

				bufsize := int64(1024 * 1024 * 4)
				b := make([]byte, bufsize)

				count := test.PayloadSize
				for count > 0 {
					if bufsize > count {
						bufsize = count
						b = b[:bufsize]
					}

					var n uint32
					for i := int64(0); i < bufsize; {
						n = rand.Uint32()
						for j := 0; j < 4 && i < bufsize; j++ {
							b[i] = byte(n & 0xff)
							n >>= 8
							i++
						}
					}
					count = count - bufsize

					r := bytes.NewReader(b)
					_, err := io.Copy(pw, r)
					if err != nil {
						randErr = err
						return
					}
				}
			}()
			if err := verifyReaderSizeAndCommP(t, pr, test); err != nil {
				t.Fatal(err)
			}
			if randErr != nil {
				t.Fatal(err)
			}
		})
	}

}

type repeatedReader struct {
	b byte
}

func (rr *repeatedReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = rr.b
	}
	return len(p), nil
}

func TestZero(t *testing.T) {
	t.Parallel()

	tests, err := getTestCases("testdata/zero.txt")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		test := test
		t.Run(fmt.Sprintf("%d", test.PayloadSize), func(t *testing.T) {
			t.Parallel()
			r := io.LimitReader(&repeatedReader{b: 0x00}, test.PayloadSize)
			if err := verifyReaderSizeAndCommP(t, r, test); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func Test0b11001100(t *testing.T) {
	t.Parallel()

	tests, err := getTestCases("testdata/0xCC.txt")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		test := test
		t.Run(fmt.Sprintf("%d", test.PayloadSize), func(t *testing.T) {
			t.Parallel()
			r := io.LimitReader(&repeatedReader{b: 0xCC}, test.PayloadSize)
			if err := verifyReaderSizeAndCommP(t, r, test); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func verifyReaderSizeAndCommP(t *testing.T, r io.Reader, test testCase) error {
	cp := &Calc{}
	if _, err := io.Copy(cp, r); err != nil {
		t.Fatal(err)
	}
	rawCommP, paddedSize, err := cp.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if paddedSize != test.PieceSize {
		return fmt.Errorf("produced padded size %d doesn't match expected size %d", paddedSize, test.PieceSize)
	}
	if !bytes.Equal(rawCommP, test.RawCommP) {
		return fmt.Errorf("produced piececid 0x%X doesn't match expected 0x%X", rawCommP, test.RawCommP)
	}

	return nil
}

var b32dec = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func getTestCases(path string) ([]testCase, error) {
	var ret []testCase
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lineScanner := bufio.NewScanner(f)
	for lineScanner.Scan() {
		parts := strings.Split(lineScanner.Text(), ",")
		payloadSize, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, err
		}
		pieceSize, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, err
		}
		rawCid, err := b32dec.DecodeString(parts[2][1:]) // [1:] drops the multibase 'b'
		if err != nil {
			return nil, fmt.Errorf("failed decoding of CID '%s': %s", parts[2][1:], err)
		}
		ret = append(ret, testCase{
			PayloadSize: payloadSize,
			PieceSize:   pieceSize,
			RawCommP:    rawCid[len(rawCid)-32:],
		})
	}

	return ret, nil
}
