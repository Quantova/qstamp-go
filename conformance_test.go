// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorRecord struct {
	Alg     string   `json:"alg"`
	Digest  string   `json:"digest"`
	Salt    string   `json:"salt"`
	Index   int      `json:"index"`
	Path    []string `json:"path"`
	Rebuilt string   `json:"rebuilt"`
}

type vectors struct {
	Genesis    string         `json:"genesis"`
	Contract   string         `json:"contract"`
	Sender     string         `json:"sender"`
	Kind       string         `json:"kind"`
	Size       int            `json:"size"`
	Root       string         `json:"root"`
	Commitment string         `json:"commitment"`
	Leaves     []string       `json:"leaves"`
	Records    []vectorRecord `json:"records"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestLeafHashMatchesSDK(t *testing.T) {
	v := loadVectors(t)
	for i, r := range v.Records {
		leaf, err := leafHash(r.Alg, mustHex(t, r.Digest), mustHex(t, r.Salt))
		if err != nil {
			t.Fatalf("record %d leafHash: %v", i, err)
		}
		if got := hex.EncodeToString(leaf); got != v.Leaves[i] {
			t.Fatalf("record %d leaf mismatch\n go %s\n js %s", i, got, v.Leaves[i])
		}
	}
}

func TestRootFromPathMatchesSDK(t *testing.T) {
	v := loadVectors(t)
	for i, r := range v.Records {
		leaf, err := leafHash(r.Alg, mustHex(t, r.Digest), mustHex(t, r.Salt))
		if err != nil {
			t.Fatalf("record %d leafHash: %v", i, err)
		}
		path := make([][]byte, len(r.Path))
		for j, p := range r.Path {
			path[j] = mustHex(t, p)
		}
		root := rootFromPath(leaf, r.Index, v.Size, path)
		if root == nil {
			t.Fatalf("record %d rootFromPath returned nil", i)
		}
		if got := hex.EncodeToString(root); got != v.Root || got != r.Rebuilt {
			t.Fatalf("record %d root mismatch\n go %s\n js %s", i, got, v.Root)
		}
	}
}

func TestCommitmentMatchesSDK(t *testing.T) {
	v := loadVectors(t)
	ctx := CommitmentContext{Genesis: v.Genesis, Contract: v.Contract, Sender: v.Sender, Kind: v.Kind}
	c, err := commitment(mustHex(t, v.Root), v.Size, ctx)
	if err != nil {
		t.Fatalf("commitment: %v", err)
	}
	if got := hex.EncodeToString(c); got != v.Commitment {
		t.Fatalf("commitment mismatch\n go %s\n js %s", got, v.Commitment)
	}
}

func TestAddressDecode(t *testing.T) {
	v := loadVectors(t)
	for _, a := range []string{v.Contract, v.Sender} {
		b, err := addressBytes(a)
		if err != nil {
			t.Fatalf("decode %s: %v", a, err)
		}
		if len(b) != 32 {
			t.Fatalf("decode %s: want 32 bytes got %d", a, len(b))
		}
	}
}

func TestRecomputeEndToEnd(t *testing.T) {
	v := loadVectors(t)
	r := v.Records[2]
	receipt := Receipt{
		Format:   "qstamp-receipt/1",
		Chain:    Chain{ID: "Q-conformance", Genesis: v.Genesis},
		Contract: v.Contract,
		Kind:     v.Kind,
		Record:   Record{Alg: r.Alg, Digest: r.Digest, Salt: r.Salt},
		Proof:    Proof{Index: r.Index, Size: v.Size, Path: r.Path},
		Root:     v.Root,
		Anchor:   Anchor{Sender: v.Sender},
	}
	res, err := Recompute(receipt)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if !res.RootMatches {
		t.Fatal("root did not match for a valid receipt")
	}
	if res.CommitmentHex != v.Commitment {
		t.Fatalf("commitment mismatch\n go %s\n js %s", res.CommitmentHex, v.Commitment)
	}
}

func TestTamperedRecordFailsRoot(t *testing.T) {
	v := loadVectors(t)
	r := v.Records[0]
	bad := mustHex(t, r.Digest)
	bad[0] ^= 0x01
	receipt := Receipt{
		Chain:    Chain{Genesis: v.Genesis},
		Contract: v.Contract,
		Kind:     v.Kind,
		Record:   Record{Alg: r.Alg, Digest: hex.EncodeToString(bad), Salt: r.Salt},
		Proof:    Proof{Index: r.Index, Size: v.Size, Path: r.Path},
		Root:     v.Root,
		Anchor:   Anchor{Sender: v.Sender},
	}
	res, err := Recompute(receipt)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if res.RootMatches {
		t.Fatal("a tampered digest still rebuilt the root")
	}
}
