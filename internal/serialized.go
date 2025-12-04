package internal

type SerializedState struct {
	QuadsEnqueued       uint64
	Buffer              []byte
	LayerQueueTwinholds [][]byte // each layer's queued messages concatenated
}
