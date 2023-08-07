package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	commcid "github.com/filecoin-project/go-fil-commcid"
	commp "github.com/filecoin-project/go-fil-commp-hashhash"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/mattn/go-isatty"
	"github.com/pborman/options"
)

const BufSize = ((16 << 20) / 128 * 127)

func main() {

	opts := &struct {
		DisableStreamScan bool         `getopt:"-d --disable-stream-scan If set do not try to scan the contents of the stream for a potential .car stream"`
		PadPieceSize      uint64       `getopt:"-p --pad-piece-size      Optional target power-of-two piece size, larger than the original input, one would like to pad to"`
		Help              options.Help `getopt:"-h --help                Display help"`
	}{}

	options.RegisterAndParse(opts)

	if isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		log.Println("Reading from STDIN...")
	}

	cp := new(commp.Calc)
	streamBuf := bufio.NewReaderSize(
		io.TeeReader(os.Stdin, cp),
		BufSize,
	)

	var streamLen int64

	var readRes string
	if !opts.DisableStreamScan {
		var n int64
		n, readRes = scanInputStream(streamBuf)
		streamLen += n
	}
	// read out remainder from above into the hasher, if any
	n, err := io.Copy(uDiscard, streamBuf)
	streamLen += n
	if err != nil && err != io.EOF {
		log.Fatalf("unexpected error at offset %d: %s", streamLen, err)
	}

	rawCommP, paddedSize, err := cp.Digest()
	if err != nil {
		log.Fatal(err)
	}

	if opts.PadPieceSize > 0 {
		rawCommP, err = commp.PadCommP(
			rawCommP,
			paddedSize,
			opts.PadPieceSize,
		)
		if err != nil {
			log.Fatal(err)
		}
		paddedSize = opts.PadPieceSize
	}

	commCid, err := commcid.DataCommitmentV1ToCID(rawCommP)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, `
CommPCid: %s
Payload:        % 12d bytes
Unpadded piece: % 12d bytes
Padded piece:   % 12d bytes
`,
		commCid,
		streamLen,
		paddedSize/128*127,
		paddedSize,
	)

	if readRes != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n\n", readRes)
	}
}

type CarHeader struct {
	Roots   []cid.Cid
	Version uint64
}

func scanInputStream(streamBuf *bufio.Reader) (cnt int64, res string) {

	cbor.RegisterCborType(CarHeader{})

	// pretend the stream is a car and try to parse it
	// everything is opportunistic - keep descending on every err == nil
	if maybeHeaderLen, err := streamBuf.Peek(10); err == nil {

		if hdrLen, viLen := binary.Uvarint(maybeHeaderLen); viLen > 0 && hdrLen > 0 {
			actualViLen, err := io.CopyN(uDiscard, streamBuf, int64(viLen))
			cnt += actualViLen
			if err == nil {

				hdrBuf := make([]byte, hdrLen)
				actualHdrLen, err := io.ReadFull(streamBuf, hdrBuf)
				cnt += int64(actualHdrLen)

				if err == nil {

					carHdr := new(CarHeader)
					if cbor.DecodeInto(hdrBuf, carHdr) != nil {
						return
					}

					if carHdr.Version != 1 {
						log.Printf("detected a CARv%d header: using the CommP of such an input is almost certainly a mistake", carHdr.Version)
						res = fmt.Sprintf("*UNEXPECTED* CARv%d detected in stream", carHdr.Version)
						return
					}

					//
					// Assume CARv1: I know how to decode this!
					// Check the *first* block only, if any at all
					//
					maybeNextFrameLen, err := streamBuf.Peek(10)
					if err == io.EOF {
						res = "CARv1 detected in stream"
						return
					}

					if err != nil && err != bufio.ErrBufferFull {
						log.Fatalf("unexpected read error at offset %d: %s", cnt, err)
						return
					}

					// from here on assume everything is malformed, unless we say otherwise
					res = "*MALFORMED* CARv1 detected in stream"

					if len(maybeNextFrameLen) == 0 {
						log.Fatalf("impossible 0-length peek without io.EOF at offset %d", cnt)
						return
					}

					frameLen, viLen := binary.Uvarint(maybeNextFrameLen)
					if viLen <= 0 {
						// car file with trailing garbage behind it
						log.Printf("aborting car stream parse: undecodeable varint at offset %d", cnt)
						return
					}

					actualFrameLen, err := io.CopyN(uDiscard, streamBuf, int64(viLen)+int64(frameLen))
					cnt += actualFrameLen
					if err != nil {
						if err != io.EOF {
							log.Fatalf("unexpected error at offset %d: %s", cnt-actualFrameLen, err)
						}
						log.Printf("aborting car stream parse: truncated frame at offset %d: expected %d bytes but read %d: %s", cnt-actualFrameLen, frameLen, actualFrameLen, err)
						return
					}

					// all looks healthy
					res = "CARv1 detected in stream"
				}
			}
		}
	}
	return
}

// Using io.Discard in the various Copy() invocations above results in invoking
// https://cs.opensource.google/go/go/+/refs/tags/go1.20.7:src/io/io.go;l=647-661
// which in turn is bound by this limit:
// https://cs.opensource.google/go/go/+/refs/tags/go1.20.7:src/io/io.go;l=642
// resulting in micro-writes into the hasher
// Use a dumb discarder instead
type unsmartDiscard struct{}

var uDiscard io.Writer = unsmartDiscard{}

func (unsmartDiscard) Write(p []byte) (int, error)       { return len(p), nil }
func (unsmartDiscard) WriteString(s string) (int, error) { return len(s), nil }
