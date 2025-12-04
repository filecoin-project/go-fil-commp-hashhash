package main

import (
	commp "github.com/filecoin-project/go-fil-commp-hashhash/internal"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	// Generate tuple-style encoders (list of fields)...
	if err := cbg.WriteTupleEncodersToFile("serialized_gen.go", "internal",
		commp.SerializedState{},
		// Add other types here...
	); err != nil {
		panic(err)
	}
}
