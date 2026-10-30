// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type corpusCheck struct {
	Index   int      `json:"index"`
	Alg     string   `json:"alg"`
	Digest  string   `json:"digest"`
	Salt    string   `json:"salt"`
	Path    []string `json:"path"`
	Rebuilt string   `json:"rebuilt"`
}

type corpusCase struct {
	ID         int           `json:"id"`
	Size       int           `json:"size"`
	Genesis    string        `json:"genesis"`
	Contract   string        `json:"contract"`
	Sender     string        `json:"sender"`
	Kind       string        `json:"kind"`
	Root       string        `json:"root"`
	Commitment string        `json:"commitment"`
	Checks     []corpusCheck `json:"checks"`
}

func TestCorpusDifferential(t *testing.T) {
	raw, err := os.ReadFile("testdata_corpus.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty corpus")
	}
	total := 0
	for _, c := range cases {
		ctx := CommitmentContext{Genesis: c.Genesis, Contract: c.Contract, Sender: c.Sender, Kind: c.Kind}
		root, err := hex.DecodeString(c.Root)
		if err != nil {
			t.Fatalf("case %d root hex: %v", c.ID, err)
		}
		gotC, err := commitment(root, c.Size, ctx)
		if err != nil {
			t.Fatalf("case %d commitment: %v", c.ID, err)
		}
		if hex.EncodeToString(gotC) != c.Commitment {
			t.Fatalf("case %d (size %d) commitment mismatch\n go %s\n js %s", c.ID, c.Size, hex.EncodeToString(gotC), c.Commitment)
		}
		for _, ch := range c.Checks {
			digest, _ := hex.DecodeString(ch.Digest)
			salt, _ := hex.DecodeString(ch.Salt)
			leaf, err := leafHash(ch.Alg, digest, salt)
			if err != nil {
				t.Fatalf("case %d idx %d leafHash: %v", c.ID, ch.Index, err)
			}
			path := make([][]byte, len(ch.Path))
			for j, p := range ch.Path {
				path[j], _ = hex.DecodeString(p)
			}
			rebuilt := rootFromPath(leaf, ch.Index, c.Size, path)
			if rebuilt == nil {
				t.Fatalf("case %d idx %d rootFromPath nil", c.ID, ch.Index)
			}
			if hex.EncodeToString(rebuilt) != c.Root || hex.EncodeToString(rebuilt) != ch.Rebuilt {
				t.Fatalf("case %d idx %d (size %d) root mismatch\n go %s\n js %s", c.ID, ch.Index, c.Size, hex.EncodeToString(rebuilt), c.Root)
			}
			total++
		}
	}
	t.Logf("differential checks passed cases %d checks %d", len(cases), total)
}

func TestRootFromPathRejectsWrongIndex(t *testing.T) {
	raw, _ := os.ReadFile("testdata_corpus.json")
	var cases []corpusCase
	_ = json.Unmarshal(raw, &cases)
	for _, c := range cases {
		if c.Size < 2 {
			continue
		}
		ch := c.Checks[0]
		digest, _ := hex.DecodeString(ch.Digest)
		salt, _ := hex.DecodeString(ch.Salt)
		leaf, _ := leafHash(ch.Alg, digest, salt)
		path := make([][]byte, len(ch.Path))
		for j, p := range ch.Path {
			path[j], _ = hex.DecodeString(p)
		}
		wrong := (ch.Index + 1) % c.Size
		rebuilt := rootFromPath(leaf, wrong, c.Size, path)
		if rebuilt != nil && hex.EncodeToString(rebuilt) == c.Root {
			t.Fatalf("case %d: path verified under the wrong index %d", c.ID, wrong)
		}
	}
}

func TestOutOfRangeInputs(t *testing.T) {
	leaf := make([]byte, 32)
	if rootFromPath(leaf, 0, 0, nil) != nil {
		t.Fatal("size 0 accepted")
	}
	if rootFromPath(leaf, -1, 4, nil) != nil {
		t.Fatal("negative index accepted")
	}
	if rootFromPath(leaf, 4, 4, nil) != nil {
		t.Fatal("index == size accepted")
	}
	if rootFromPath(make([]byte, 31), 0, 1, nil) != nil {
		t.Fatal("short leaf accepted")
	}
	over := make([][]byte, maxPath+1)
	for i := range over {
		over[i] = make([]byte, 32)
	}
	if rootFromPath(leaf, 0, 1<<20, over) != nil {
		t.Fatal("over-long path accepted")
	}
	if _, err := commitment(make([]byte, 31), 1, CommitmentContext{}); err == nil {
		t.Fatal("short root accepted by commitment")
	}
	if _, err := commitment(make([]byte, 32), 0, CommitmentContext{}); err == nil {
		t.Fatal("size 0 accepted by commitment")
	}
}

func TestMalformedReceiptsRejected(t *testing.T) {
	base := Receipt{
		Chain:    Chain{Genesis: "00"},
		Contract: "notanaddress",
		Kind:     "1",
		Record:   Record{Alg: "sha3-256", Digest: "zz", Salt: "00"},
		Proof:    Proof{Index: 0, Size: 1},
		Root:     "00",
		Anchor:   Anchor{Sender: "notanaddress"},
	}
	if _, err := Recompute(base); err == nil {
		t.Fatal("malformed receipt accepted")
	}
}

func TestUnknownAlgorithmRejected(t *testing.T) {
	if _, err := leafHash("md5", make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}
