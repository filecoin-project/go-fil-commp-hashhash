module github.com/filecoin-project/go-fil-commp-hashhash/cmd/stream-commp

go 1.16

require (
	github.com/filecoin-project/go-fil-commcid v0.1.0
	github.com/filecoin-project/go-fil-commp-hashhash v0.1.0
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipld-cbor v0.0.5
	github.com/mattn/go-isatty v0.0.12
	github.com/pborman/options v1.2.0
)

replace github.com/filecoin-project/go-fil-commp-hashhash => ../../
