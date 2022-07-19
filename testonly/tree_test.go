// Copyright 2022 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testonly

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

func validateTree(t *testing.T, mt *Tree, size uint64) {
	t.Helper()
	if got, want := mt.Size(), size; got != want {
		t.Errorf("Size: %d, want %d", got, want)
	}
	roots := RootHashes()
	if got, want := mt.Hash(), roots[size]; !bytes.Equal(got, want) {
		t.Errorf("Hash(%d): %x, want %x", size, got, want)
	}
	for s := uint64(0); s <= size; s++ {
		if got, want := mt.HashAt(s), roots[s]; !bytes.Equal(got, want) {
			t.Errorf("HashAt(%d/%d): %x, want %x", s, size, got, want)
		}
	}
}

func TestBuildTreeBuildOneAtATime(t *testing.T) {
	mt := newTree(nil)
	validateTree(t, mt, 0)
	for i, entry := range LeafInputs() {
		mt.AppendData(entry)
		validateTree(t, mt, uint64(i+1))
	}
}

func TestBuildTreeBuildTwoChunks(t *testing.T) {
	entries := LeafInputs()
	mt := newTree(nil)
	mt.AppendData(entries[:3]...)
	validateTree(t, mt, 3)
	mt.AppendData(entries[3:8]...)
	validateTree(t, mt, 8)
}

func TestBuildTreeBuildAllAtOnce(t *testing.T) {
	mt := newTree(nil)
	mt.AppendData(LeafInputs()...)
	validateTree(t, mt, 8)
}

func FuzzHashAtAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		t.Logf("index=%d, size=%d", index, size)
		if index >= size {
			return
		}
		entries := genEntries(size)
		mt := newTree(entries)
		got := mt.HashAt(uint64(size))
		want := refRootHash(entries[:size], mt.hasher)
		if !bytes.Equal(got, want) {
			t.Errorf("HashAt(%d): %x, want %x", size, got, want)
		}
	})
}

func FuzzInclusionProofAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		t.Logf("index=%d, size=%d", index, size)
		if index >= size {
			return
		}
		entries := genEntries(size)
		tree := newTree(entries)
		got, err := tree.InclusionProof(index, size)
		t.Logf("proof=%v", got)
		if err != nil {
			t.Error(err)
		}
		want := refInclusionProof(entries, index, tree.hasher)
		if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
			t.Fatalf("InclusionProof(%d, %d): diff (-got +want)\n%s", index, size, diff)
		}
	})
}

func TestTreeConsistencyProof(t *testing.T) {
	entries := LeafInputs()
	mt := newTree(entries)
	validateTree(t, mt, 8)

	if _, err := mt.ConsistencyProof(6, 3); err == nil {
		t.Error("ConsistencyProof(6, 3) succeeded unexpectedly")
	}

	for size1 := uint64(0); size1 <= 8; size1++ {
		for size2 := size1; size2 <= 8; size2++ {
			t.Run(fmt.Sprintf("%d:%d", size1, size2), func(t *testing.T) {
				got, err := mt.ConsistencyProof(size1, size2)
				if err != nil {
					t.Fatalf("ConsistencyProof: %v", err)
				}
				want := refConsistencyProof(entries[:size2], size2, size1, mt.hasher, true)
				if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("ConsistencyProof: diff (-got +want)\n%s", diff)
				}
			})
		}
	}
}

// Make random proof queries and check the reference implementation.
func FuzzConsistencyProofAgainstReferenceImplementation(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for size2 := 0; size2 <= size; size2++ {
			for size1 := 0; size1 <= size2; size1++ {
				f.Add(uint64(size), uint64(size1), uint64(size2))
			}
		}
	}
	f.Fuzz(func(t *testing.T, size, size1, size2 uint64) {
		t.Logf("size=%d, size1=%d, size2=%d", size, size1, size2)
		if size1 > size2 || size2 > size {
			return
		}
		entries := genEntries(size)
		tree := newTree(entries)
		got, err := tree.ConsistencyProof(size1, size2)
		if err != nil {
			t.Fatalf("ConsistencyProof: %v", err)
		}
		want := refConsistencyProof(entries, size2, size1, tree.hasher, true)
		if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("ConsistencyProof: diff (-got +want)\n%s", diff)
		}
	})
}

func FuzzConsistencyProof(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for size2 := 0; size2 <= size; size2++ {
			for size1 := 0; size1 <= size2; size1++ {
				f.Add(uint64(size), uint64(size1), uint64(size2))
			}
		}
	}
	f.Fuzz(func(t *testing.T, size, size1, size2 uint64) {
		t.Logf("size=%d, size1=%d, size2=%d", size, size1, size2)
		if size1 > size2 || size2 > size {
			return
		}
		tree := newTree(genEntries(size))
		p, err := tree.ConsistencyProof(size1, size2)
		t.Logf("proof=%v", p)
		if err != nil {
			t.Error(err)
		}
		err = proof.VerifyConsistency(tree.hasher, size1, size2, p, tree.HashAt(size1), tree.HashAt(size2))
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzInclusionProof(f *testing.F) {
	for size := 0; size <= 8; size++ {
		for index := 0; index <= size; index++ {
			f.Add(uint64(index), uint64(size))
		}
	}
	f.Fuzz(func(t *testing.T, index, size uint64) {
		t.Logf("index=%d, size=%d", index, size)
		if index >= size {
			return
		}
		tree := newTree(genEntries(size))
		p, err := tree.InclusionProof(index, size)
		t.Logf("proof=%v", p)
		if err != nil {
			t.Error(err)
		}
		err = proof.VerifyInclusion(tree.hasher, index, size, tree.LeafHash(index), p, tree.Hash())
		if err != nil {
			t.Error(err)
		}
	})
}

func TestTreeAppend(t *testing.T) {
	entries := genEntries(256)
	mt1 := newTree(entries)

	mt2 := newTree(nil)
	for _, entry := range entries {
		mt2.Append(rfc6962.DefaultHasher.HashLeaf(entry))
	}

	if diff := cmp.Diff(mt1, mt2, cmp.AllowUnexported(Tree{})); diff != "" {
		t.Errorf("Trees built with AppendData and Append mismatch: diff (-mt1 +mt2)\n%s", diff)
	}
}

func TestTreeAppendAssociativity(t *testing.T) {
	entries := genEntries(256)
	mt1 := newTree(nil)
	mt1.AppendData(entries...)

	mt2 := newTree(nil)
	for _, entry := range entries {
		mt2.AppendData(entry)
	}

	if diff := cmp.Diff(mt1, mt2, cmp.AllowUnexported(Tree{})); diff != "" {
		t.Errorf("AppendData is not associative: diff (-mt1 +mt2)\n%s", diff)
	}
}

func newTree(entries [][]byte) *Tree {
	tree := New(rfc6962.DefaultHasher)
	tree.AppendData(entries...)
	return tree
}

// genEntries a slice of entries of the given size.
func genEntries(size uint64) [][]byte {
	entries := make([][]byte, size)
	for i := range entries {
		entries[i] = []byte(strconv.Itoa(i))
	}
	return entries
}
