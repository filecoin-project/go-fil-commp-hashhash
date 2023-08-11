stream-commp
=======================

> A basic utility for calculating [fil-commitment-unsealed](https://github.com/multiformats/multicodec/blob/master/table.csv#L454) of a stream

## Installation

```
go install github.com/filecoin-project/go-fil-commp-hashhash/cmd/stream-commp@latest
```

## Usage Example

```
ipfs dag export bafybeia6po64b6tfqq73lckadrhpihg2oubaxgqaoushquhcek46y3zumm | stream-commp
```

## Output Example

```
CommPCid: baga6ea4seaqjxuo4um6mcu7bnv6ui4x5ky4lb7kfpq6bd2h7tyx7hszooo2aybi
Payload:                6896 bytes
Unpadded piece:         8128 bytes
Padded piece:           8192 bytes

CARv1 detected in stream
```

## License
[SPDX-License-Identifier: Apache-2.0 OR MIT](../../LICENSE.md)
