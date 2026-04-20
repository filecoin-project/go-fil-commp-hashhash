package commp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	randmath "math/rand"
)

const (
	snapshotBenchSize = 31 << 20 // same as BenchmarkCommP for comparison

	// testLayerIdx captures at ~2 KiB granularity per node (layer 6 = 2^6 = 64 leaves * 32 bytes)
	testLayerIdx = 6
	// prodLayerIdx captures at ~4 MiB granularity per node (layer 17 = 2^17 = 131072 leaves * 32 bytes)
	prodLayerIdx = 17
)

func BenchmarkDigest(b *testing.B) {
	src := bytes.NewReader(make([]byte, snapshotBenchSize))
	cp := &Calc{}

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(snapshotBenchSize)
	for i := 0; i < b.N; i++ {
		if _, err := src.Seek(0, 0); err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(cp, src); err != nil {
			b.Fatal(err)
		}
		if _, _, err := cp.Digest(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDigestWithSnapshot(b *testing.B) {
	src := bytes.NewReader(make([]byte, snapshotBenchSize))
	cp := NewCalcWithSnapshot(prodLayerIdx)

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(snapshotBenchSize)
	for i := 0; i < b.N; i++ {
		if _, err := src.Seek(0, 0); err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(cp, src); err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := cp.DigestWithSnapshot(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDigestWithSnapshotFineGrained(b *testing.B) {
	src := bytes.NewReader(make([]byte, snapshotBenchSize))
	cp := NewCalcWithSnapshot(testLayerIdx)

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(snapshotBenchSize)
	for i := 0; i < b.N; i++ {
		if _, err := src.Seek(0, 0); err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(cp, src); err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := cp.DigestWithSnapshot(); err != nil {
			b.Fatal(err)
		}
	}
}

// snapshotFixture holds a test case for snapshot verification. PayloadSize and
// PieceSize come from testdata/random.txt; RawCommP is decoded at test time.
type snapshotFixture struct {
	PayloadSize int64
	PieceSize   uint64
	CommPCID    string // base32 multibase CID from test vectors
}

// Test fixtures selected to exercise snapshot layer capture across a range of
// tree shapes and fill levels. All have known-good CommP values from
// testdata/random.txt, validated against filecoin-ffi.
var snapshotFixtures = []snapshotFixture{
	// Small sizes: few snapshot nodes at testLayerIdx
	{8128, 8192, "baga6ea4seaqotwrimtqoatryhi3zmcjvykr3uyybsx6n5fmdq2wgo6zw7nz3kiq"},
	{65024, 65536, "baga6ea4seaqgjaavyognzadlkkcwaovy4ij7grb3eso65dqvwkiqfg5g3cb3qbi"},
	// Partial fill: exercises null-padded snapshot nodes
	{786432, 1048576, "baga6ea4seaqdqltvzfcyx5nu3o6yazc6ftuxt6xkhwjywatjmjrbj6shwsqlcaq"},
	// Exact fill at production snapshot boundary
	{1040384, 1048576, "baga6ea4seaqio7pi5twddpb4qevcestrwtc77nuou7o2xilhkhkj46irbsolaoq"},
	// Production snapshot boundary (~4 MiB)
	{4161536, 4194304, "baga6ea4seaqoarx7s4i2azmftkspmosawixgqg3frdo3iugalasu5burrgu3qbq"},
	// MinSizeForCache threshold (32 MiB)
	{33292288, 33554432, "baga6ea4seaqgseawqou6toeg5spmgnjsamjiqq2bhbamfjtj5e67ytnncwuasiq"},
	// Medium-large
	{133169152, 134217728, "baga6ea4seaqk3bkri6x5kqcxezyq63v7ct37rhlsb7pgynmtifmwqivbhvq4why"},
	// Largest practical for unit tests (~1 GiB memtree for cross-check)
	{532676608, 536870912, "baga6ea4seaqexfdfvlgmue3jn6wmpyfgqq3itkdyae2vz3bw6tzcsrddlx7x6my"},
}

// generateDeterministicData produces seed-1337 random data matching
// jbenet/go-random, identical to testdata/random.txt generation.
func generateDeterministicData(size int64) []byte {
	rng := randmath.New(randmath.NewSource(1337))
	buf := make([]byte, size)
	for i := int64(0); i < size; {
		n := rng.Uint32()
		for j := 0; j < 4 && i < size; j++ {
			buf[i] = byte(n & 0xff)
			n >>= 8
			i++
		}
	}
	return buf
}

func decodeFixtureCommP(cidStr string) [32]byte {
	rawCid, err := b32dec.DecodeString(cidStr[1:]) // [1:] drops the multibase 'b'
	if err != nil {
		panic(fmt.Sprintf("failed to decode CID %q: %v", cidStr, err))
	}
	var commP [32]byte
	copy(commP[:], rawCid[len(rawCid)-32:])
	return commP
}

// TestSnapshotCommPMatchesFixtures verifies that DigestWithSnapshot produces
// the same CommP as the standard Digest path, anchored against external test
// vectors from testdata/random.txt.
func TestSnapshotCommPMatchesFixtures(t *testing.T) {
	t.Parallel()

	for _, fx := range snapshotFixtures {
		fx := fx
		t.Run(fmt.Sprintf("%d", fx.PayloadSize), func(t *testing.T) {
			t.Parallel()

			if testing.Short() && fx.PayloadSize > 1<<26 {
				t.Skip("skipping large fixture in short mode")
			}

			expectedCommP := decodeFixtureCommP(fx.CommPCID)
			data := generateDeterministicData(fx.PayloadSize)

			cp := NewCalcWithSnapshot(testLayerIdx)
			defer cp.Reset()

			if _, err := io.Copy(cp, bytes.NewReader(data)); err != nil {
				t.Fatalf("Copy failed: %v", err)
			}

			commP, paddedSize, snapshot, err := cp.DigestWithSnapshot()
			if err != nil {
				t.Fatalf("DigestWithSnapshot failed: %v", err)
			}

			if paddedSize != fx.PieceSize {
				t.Errorf("padded size: got %d, want %d", paddedSize, fx.PieceSize)
			}

			var gotCommP [32]byte
			copy(gotCommP[:], commP)
			if gotCommP != expectedCommP {
				t.Errorf("CommP mismatch:\n  got  %x\n  want %x", gotCommP, expectedCommP)
			}

			if snapshot == nil {
				t.Fatal("snapshot is nil")
			}

			expectedLeaves := fx.PieceSize / 32
			expectedNodes := int(expectedLeaves >> uint(snapshot.LayerIndex))
			if len(snapshot.Nodes) != expectedNodes {
				t.Errorf("snapshot node count: got %d, want %d (layer %d, leaves %d)",
					len(snapshot.Nodes), expectedNodes, snapshot.LayerIndex, expectedLeaves)
			}

			// Verify data-region snapshot nodes are non-zero (random data produces non-zero hashes)
			leavesPerNode := int64(1) << uint(snapshot.LayerIndex)
			dataNodes := (int64(fx.PayloadSize)*128/127 + leavesPerNode*32 - 1) / (leavesPerNode * 32)
			if dataNodes > int64(len(snapshot.Nodes)) {
				dataNodes = int64(len(snapshot.Nodes))
			}
			for i := int64(0); i < dataNodes; i++ {
				if snapshot.Nodes[i] == [32]byte{} {
					t.Errorf("snapshot node %d is all-zero but covers data region", i)
				}
			}
		})
	}
}

// TestSnapshotMatchesPlainDigest verifies that the CommP from
// DigestWithSnapshot is identical to the CommP from plain Digest for the same
// data.
func TestSnapshotMatchesPlainDigest(t *testing.T) {
	t.Parallel()

	for _, fx := range snapshotFixtures {
		fx := fx
		t.Run(fmt.Sprintf("%d", fx.PayloadSize), func(t *testing.T) {
			t.Parallel()

			if testing.Short() && fx.PayloadSize > 1<<26 {
				t.Skip("skipping large fixture in short mode")
			}

			data := generateDeterministicData(fx.PayloadSize)

			// Plain digest
			plain := &Calc{}
			defer plain.Reset()
			if _, err := io.Copy(plain, bytes.NewReader(data)); err != nil {
				t.Fatalf("plain Copy failed: %v", err)
			}
			plainCommP, plainSize, err := plain.Digest()
			if err != nil {
				t.Fatalf("plain Digest failed: %v", err)
			}

			// Snapshot digest
			snap := NewCalcWithSnapshot(testLayerIdx)
			defer snap.Reset()
			if _, err := io.Copy(snap, bytes.NewReader(data)); err != nil {
				t.Fatalf("snap Copy failed: %v", err)
			}
			snapCommP, snapSize, snapshot, err := snap.DigestWithSnapshot()
			if err != nil {
				t.Fatalf("snap DigestWithSnapshot failed: %v", err)
			}

			if !bytes.Equal(plainCommP, snapCommP) {
				t.Errorf("CommP divergence:\n  plain %x\n  snap  %x", plainCommP, snapCommP)
			}
			if plainSize != snapSize {
				t.Errorf("padded size divergence: plain %d, snap %d", plainSize, snapSize)
			}

			if snapshot == nil {
				t.Fatal("snapshot is nil")
			}
			if len(snapshot.Nodes) == 0 {
				t.Error("snapshot has zero nodes")
			}
		})
	}
}

// sha254Parent hashes two 32-byte nodes into a parent using SHA-254
// (SHA-256 with top 2 bits of byte 31 zeroed).
func sha254Parent(left, right [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	h := sha256.Sum256(buf[:])
	h[31] &= 0x3F
	return h
}

// rebuildSnapshotRoot hashes the snapshot nodes upward to reconstruct the
// merkle root.
func rebuildSnapshotRoot(snapshot *SnapshotLayer) [32]byte {
	level := snapshot.Nodes
	layerIdx := snapshot.LayerIndex

	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([][32]byte, nextLen)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			var right [32]byte
			if i+1 < len(level) {
				right = level[i+1]
			} else {
				copy(right[:], stackedNulPadding[layerIdx])
			}
			next[i/2] = sha254Parent(left, right)
		}
		level = next
		layerIdx++
	}

	return level[0]
}

// TestSnapshotUpperTreeRebuildsToCommP verifies that hashing the snapshot nodes
// upward through the remaining tree levels produces the externally-anchored
// CommP. This proves the captured nodes are the correct intermediate hashes,
// not just plausible metadata. If any node were wrong, the rebuilt root would
// diverge from the known-good CommP.
func TestSnapshotUpperTreeRebuildsToCommP(t *testing.T) {
	t.Parallel()

	for _, fx := range snapshotFixtures {
		fx := fx
		t.Run(fmt.Sprintf("%d", fx.PayloadSize), func(t *testing.T) {
			t.Parallel()

			if testing.Short() && fx.PayloadSize > 1<<26 {
				t.Skip("skipping large fixture in short mode")
			}

			expectedCommP := decodeFixtureCommP(fx.CommPCID)
			data := generateDeterministicData(fx.PayloadSize)

			cp := NewCalcWithSnapshot(testLayerIdx)
			defer cp.Reset()

			if _, err := io.Copy(cp, bytes.NewReader(data)); err != nil {
				t.Fatalf("Copy failed: %v", err)
			}

			_, _, snapshot, err := cp.DigestWithSnapshot()
			if err != nil {
				t.Fatalf("DigestWithSnapshot failed: %v", err)
			}

			rebuilt := rebuildSnapshotRoot(snapshot)
			if rebuilt != expectedCommP {
				t.Errorf("rebuilt root mismatch:\n  got  %x\n  want %x", rebuilt, expectedCommP)
			}
		})
	}
}

// TestSnapshotProductionMode verifies snapshot capture with production-mode
// granularity (~4 MiB per node).
func TestSnapshotProductionMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping production-mode snapshot test in short mode")
	}
	t.Parallel()

	// Use the 32 MiB fixture with production layer
	fx := snapshotFixtures[5] // 33292288 bytes
	expectedCommP := decodeFixtureCommP(fx.CommPCID)
	data := generateDeterministicData(fx.PayloadSize)

	cp := NewCalcWithSnapshot(prodLayerIdx)
	defer cp.Reset()

	if _, err := io.Copy(cp, bytes.NewReader(data)); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}

	commP, paddedSize, snapshot, err := cp.DigestWithSnapshot()
	if err != nil {
		t.Fatalf("DigestWithSnapshot failed: %v", err)
	}

	if paddedSize != fx.PieceSize {
		t.Errorf("padded size: got %d, want %d", paddedSize, fx.PieceSize)
	}

	var gotCommP [32]byte
	copy(gotCommP[:], commP)
	if gotCommP != expectedCommP {
		t.Errorf("CommP mismatch:\n  got  %x\n  want %x", gotCommP, expectedCommP)
	}

	if snapshot.LayerIndex != prodLayerIdx {
		t.Errorf("expected layer %d, got %d", prodLayerIdx, snapshot.LayerIndex)
	}

	expectedNodes := int(fx.PieceSize / 32 >> prodLayerIdx)
	if len(snapshot.Nodes) != expectedNodes {
		t.Errorf("node count: got %d, want %d", len(snapshot.Nodes), expectedNodes)
	}
}

// TestSnapshotCalcReuse verifies that a Calc with snapshot can be reused after
// DigestWithSnapshot resets internal state.
func TestSnapshotCalcReuse(t *testing.T) {
	t.Parallel()

	fx := snapshotFixtures[3]

	cp := NewCalcWithSnapshot(testLayerIdx)
	defer cp.Reset()

	firstData := generateDeterministicData(fx.PayloadSize)
	if _, err := io.Copy(cp, bytes.NewReader(firstData)); err != nil {
		t.Fatalf("first copy failed: %v", err)
	}

	firstCommP, firstSize, firstSnapshot, err := cp.DigestWithSnapshot()
	if err != nil {
		t.Fatalf("first DigestWithSnapshot failed: %v", err)
	}
	if firstSize != fx.PieceSize {
		t.Fatalf("first padded size: got %d, want %d", firstSize, fx.PieceSize)
	}
	if len(firstSnapshot.Nodes) == 0 {
		t.Fatal("first snapshot has zero nodes")
	}

	secondData := generateDeterministicData(fx.PayloadSize)
	secondData[0] ^= 0xff
	if _, err := io.Copy(cp, bytes.NewReader(secondData)); err != nil {
		t.Fatalf("second copy failed: %v", err)
	}

	secondCommP, secondSize, secondSnapshot, err := cp.DigestWithSnapshot()
	if err != nil {
		t.Fatalf("second DigestWithSnapshot failed: %v", err)
	}
	if secondSize != fx.PieceSize {
		t.Fatalf("second padded size: got %d, want %d", secondSize, fx.PieceSize)
	}

	// Cross-check second run against plain Digest
	plain := &Calc{}
	defer plain.Reset()
	if _, err := io.Copy(plain, bytes.NewReader(secondData)); err != nil {
		t.Fatalf("plain second copy failed: %v", err)
	}
	expectedSecond, expectedSecondSize, err := plain.Digest()
	if err != nil {
		t.Fatalf("plain second Digest failed: %v", err)
	}
	if expectedSecondSize != secondSize {
		t.Fatalf("plain second padded size: got %d, want %d", expectedSecondSize, secondSize)
	}

	if bytes.Equal(firstCommP, secondCommP) {
		t.Fatal("expected reused calculator to produce a different CommP for different input")
	}
	if !bytes.Equal(expectedSecond, secondCommP) {
		t.Fatalf("second CommP mismatch against plain Digest:\n  got  %x\n  want %x", secondCommP, expectedSecond)
	}

	rebuilt := rebuildSnapshotRoot(secondSnapshot)
	var expectedSecondArr [32]byte
	copy(expectedSecondArr[:], expectedSecond)
	if rebuilt != expectedSecondArr {
		t.Fatalf("rebuilt snapshot root mismatch on reuse:\n  got  %x\n  want %x", rebuilt, expectedSecondArr)
	}
}

// TestSnapshotResetClearsCollectedNodes verifies that Reset() clears collected
// snapshot nodes.
func TestSnapshotResetClearsCollectedNodes(t *testing.T) {
	t.Parallel()

	fx := snapshotFixtures[2]
	cp := NewCalcWithSnapshot(testLayerIdx)

	data := generateDeterministicData(fx.PayloadSize)
	if _, err := io.Copy(cp, bytes.NewReader(data)); err != nil {
		t.Fatalf("copy failed: %v", err)
	}

	cp.Reset()

	if len(cp.snapshot.nodes) != 0 {
		t.Fatalf("snapshot nodes not cleared on Reset: got %d", len(cp.snapshot.nodes))
	}
}

// TestSnapshotLayerOOB verifies that DigestWithSnapshot returns CommP but nil
// snapshot when the requested layer index exceeds the tree height.
func TestSnapshotLayerOOB(t *testing.T) {
	t.Parallel()

	// 8128 bytes -> 8192 padded -> 256 leaves -> tree height 8
	// Layer 20 is out of bounds
	expectedCommP := decodeFixtureCommP(snapshotFixtures[0].CommPCID)
	data := generateDeterministicData(8128)

	cp := NewCalcWithSnapshot(20)
	defer cp.Reset()

	if _, err := io.Copy(cp, bytes.NewReader(data)); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}

	commP, paddedSize, snapshot, err := cp.DigestWithSnapshot()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if paddedSize != 8192 {
		t.Errorf("padded size: got %d, want 8192", paddedSize)
	}
	var gotCommP [32]byte
	copy(gotCommP[:], commP)
	if gotCommP != expectedCommP {
		t.Errorf("CommP mismatch:\n  got  %x\n  want %x", gotCommP, expectedCommP)
	}
	if snapshot != nil {
		t.Errorf("expected nil snapshot for OOB layer, got %+v", snapshot)
	}
}

// TestDigestWithSnapshotOnPlainCalc verifies that calling DigestWithSnapshot on
// a Calc not created with NewCalcWithSnapshot returns an error.
func TestDigestWithSnapshotOnPlainCalc(t *testing.T) {
	t.Parallel()

	cp := &Calc{}
	defer cp.Reset()

	data := generateDeterministicData(8128)
	if _, err := io.Copy(cp, bytes.NewReader(data)); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}

	_, _, _, err := cp.DigestWithSnapshot()
	if err == nil {
		t.Fatal("expected error calling DigestWithSnapshot on plain Calc, got nil")
	}
}

func TestSnapshotLayerIndex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		targetPadded uint64
		expectLayer  int
		description  string
	}{
		{32, 1, "single leaf, clamped to minimum"},
		{64, 1, "2 leaves, layer 1"},
		{128, 2, "4 leaves, layer 2"},
		{2048, 6, "64 leaves, ~2 KiB padded"},
		{4 << 20, 17, "~4 MiB padded"},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			got := SnapshotLayerIndex(tc.targetPadded)
			if got != tc.expectLayer {
				t.Errorf("SnapshotLayerIndex(%d): got %d, want %d", tc.targetPadded, got, tc.expectLayer)
			}
		})
	}
}
