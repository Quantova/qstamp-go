// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"encoding/hex"
	"testing"
)

func FuzzAddressBytes(f *testing.F) {
	f.Add("q12mvjn284wk3cq6dnv6ad2kyqmym2kcwj0vvqdmewnetqsgzhfeeqzhhuxy")
	f.Add("")
	f.Add("Q1")
	f.Add("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = addressBytes(s)
	})
}

func FuzzConvertBits(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, raw []byte) {
		data := make([]uint32, len(raw))
		for i, b := range raw {
			data[i] = uint32(b) & 31
		}
		_, _ = convertBitsTo8(data)
	})
}

func FuzzRecompute(f *testing.F) {
	f.Add("sha3-256",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		0, 1)
	f.Fuzz(func(t *testing.T, alg, digest, salt string, index, size int) {
		r := Receipt{
			Chain:    Chain{Genesis: "00"},
			Contract: "q12mvjn284wk3cq6dnv6ad2kyqmym2kcwj0vvqdmewnetqsgzhfeeqzhhuxy",
			Kind:     "1",
			Record:   Record{Alg: alg, Digest: digest, Salt: salt},
			Proof:    Proof{Index: index, Size: size},
			Root:     "0000000000000000000000000000000000000000000000000000000000000000",
			Anchor:   Anchor{Sender: "q1q8lgy86wznduzjyn8v0cetp84erjag09ta24tjvrg4n6ge7fsuvsk60hf3"},
		}
		_, _ = Recompute(r)
	})
}

func FuzzRootFromPath(f *testing.F) {
	f.Add([]byte("seed"), 0, 4, 2)
	f.Fuzz(func(t *testing.T, seed []byte, index, size, steps int) {
		leaf := make([]byte, 32)
		copy(leaf, seed)
		if steps < 0 {
			steps = -steps
		}
		steps %= 40
		path := make([][]byte, steps)
		for i := range path {
			n := make([]byte, 32)
			if len(seed) > 0 {
				n[0] = seed[i%len(seed)]
			}
			path[i] = n
		}
		_ = rootFromPath(leaf, index, size, path)
		_ = hex.EncodeToString(leaf)
	})
}
