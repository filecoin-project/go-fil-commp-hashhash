go-fil-commp-hashhash
=======================

> A hash.Hash implementation of [fil-commitment-unsealed](https://github.com/multiformats/multicodec/blob/eb94500c/table.csv#L508)

[![GoDoc](https://godoc.org/github.com/thamaraiselvam/github-api-cli?status.svg)](https://pkg.go.dev/github.com/filecoin-project/go-fil-commp-hashhash)
[![GoReport](https://goreportcard.com/badge/github.com/filecoin-project/go-fil-commp-hashhash)](https://goreportcard.com/report/github.com/filecoin-project/go-fil-commp-hashhash)

Package commp allows calculating a [Filecoin Unsealed Commitment (commP/commD)](https://spec.filecoin.io/#section-systems.filecoin_files.piece.data-representation)
given a bytestream. It is implemented as a standard [hash.Hash() interface](https://pkg.go.dev/hash#Hash),
with the entire padding and treebuilding algorithm written in golang.

The returned digest is a 32-byte raw commitment payload. Use something like [DataCommitmentV1ToCID](https://pkg.go.dev/github.com/filecoin-project/go-fil-commcid#DataCommitmentV1ToCID)
in order to convert it to a proper [cid.Cid](https://pkg.go.dev/github.com/ipfs/go-cid#Cid).

The output of this library is 100% identical to [ffi.GeneratePieceCIDFromFile()](https://github.com/filecoin-project/filecoin-ffi/blob/d82899449741ce19/proofs.go#L177-L196)


## Lead Maintainer
[Peter 'ribasushi' Rabbitson](https://github.com/ribasushi)


## License
[SPDX-License-Identifier: Apache-2.0 OR MIT](LICENSE.md)
