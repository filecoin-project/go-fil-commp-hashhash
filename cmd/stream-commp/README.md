stream-commp
=======================

> A basic utility for calculating [fil-commitment-unsealed](https://github.com/multiformats/multicodec/blob/master/table.csv#L454) of a stream

## Installation

```
go get github.com/filecoin-project/go-fil-commp-hashhash/cmd/stream-commp@latest
```

## Usage Example

```
ipfs dag export bafybeia6po64b6tfqq73lckadrhpihg2oubaxgqaoushquhcek46y3zumm | stream-commp
```

## Output Example

```
CommP:    9bd1dca33cc153e16d7d4472fd5638b0fd457c3c11e8ff9e2ff3cb2e73b40c05
CommPCid: baga6ea4seaqjxuo4um6mcu7bnv6ui4x5ky4lb7kfpq6bd2h7tyx7hszooo2aybi
Raw bytes:              6896 bytes
Unpadded piece:         8128 bytes
Padded piece:           8192 bytes

CARv1 detected in stream:
Blocks:         8
Roots:          1
    1: bafybeia6po64b6tfqq73lckadrhpihg2oubaxgqaoushquhcek46y3zumm

```

## License
[SPDX-License-Identifier: Apache-2.0 OR MIT](../../LICENSE.md)
