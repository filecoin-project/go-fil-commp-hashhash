package main

import (
	"io"
	"log"
	"math/bits"
	"os"

	commcid "github.com/filecoin-project/go-fil-commcid"
	commp "github.com/filecoin-project/go-fil-commp-hashhash"
	"github.com/pborman/options"
)

func main() {

	opts := &struct {
		TargetPieceSize uint64       `getopt:"-t --target-piece-size  Optional target size, larger than the original input one would like to pad to"`
		Help            options.Help `getopt:"-h --help               Display help"`
	}{}

	options.RegisterAndParse(opts)

	var targetBits uint
	if opts.TargetPieceSize > 0 {
		if opts.TargetPieceSize < 65 || bits.OnesCount64(opts.TargetPieceSize) != 1 {
			log.Fatalf("supplied --target-piece-size should be a power of 2, larger than 64")
		}
		targetBits = uint(bits.TrailingZeros64(opts.TargetPieceSize))
	}

	cp := commp.NewAccumulator()

	log.Println("Reading from STDIN...")
	n, err := io.Copy(cp, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	rawCommP, paddedSize, err := cp.Digest()
	if err != nil {
		log.Fatal(err)
	}

	paddedSizeBits := uint(bits.TrailingZeros64(paddedSize))

	if targetBits > 0 {
		rawCommP, err = commp.PadCommP(
			rawCommP,
			paddedSizeBits,
			targetBits,
		)
		if err != nil {
			log.Fatal(err)
		}
		paddedSize = 1 << targetBits
	}

	commCid, err := commcid.DataCommitmentV1ToCID(rawCommP)

	log.Printf(`Finished:
CommP:    %x
CommPCid: %s
Raw bytes:      % 12d bytes
Unpadded piece: % 12d bytes
Padded piece:   % 12d bytes
		`,
		rawCommP,
		commCid,
		n,
		paddedSize/128*127,
		paddedSize,
	)
}
