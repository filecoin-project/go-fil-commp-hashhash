package main

import (
	"io"
	"log"
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

	log.Println("Reading from STDIN...")
	cp := new(commp.Calc)
	n, err := io.Copy(cp, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	rawCommP, paddedSize, err := cp.Digest()
	if err != nil {
		log.Fatal(err)
	}

	if opts.TargetPieceSize > 0 {
		rawCommP, err = commp.PadCommP(
			rawCommP,
			paddedSize,
			opts.TargetPieceSize,
		)
		if err != nil {
			log.Fatal(err)
		}
		paddedSize = opts.TargetPieceSize
	}

	commCid, err := commcid.DataCommitmentV1ToCID(rawCommP)
	if err != nil {
		log.Fatal(err)
	}

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
