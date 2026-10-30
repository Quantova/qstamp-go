// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"encoding/binary"
	"errors"
)

var (
	leafTag    = []byte("QSTAMP/LEAF/V1")
	rootTag    = []byte("QSTAMP/ROOT/V1")
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
	rootPrefix = []byte{0x02}
)

const (
	maxLeaves = 1 << 20
	maxPath   = 20
)

func leafHash(alg string, digest, salt []byte) ([]byte, error) {
	id, err := algorithmID(alg)
	if err != nil {
		return nil, err
	}
	if len(digest) != 32 {
		return nil, errors.New("a digest is 32 bytes")
	}
	if len(salt) != 32 {
		return nil, errors.New("a salt is 32 bytes")
	}
	return sha3Sum(leafPrefix, leafTag, []byte{id}, digest, salt), nil
}

func nodeHash(left, right []byte) []byte {
	return sha3Sum(nodePrefix, left, right)
}

func commitment(root []byte, size int, ctx CommitmentContext) ([]byte, error) {
	if len(root) != 32 {
		return nil, errors.New("a root is 32 bytes")
	}
	if size < 1 || size > maxLeaves {
		return nil, errors.New("a batch size is out of range")
	}
	genesis, err := parseGenesis(ctx.Genesis)
	if err != nil {
		return nil, err
	}
	contract, err := addressBytes(ctx.Contract)
	if err != nil {
		return nil, errors.New("the contract is not a Quantova address")
	}
	sender, err := addressBytes(ctx.Sender)
	if err != nil {
		return nil, errors.New("the sender is not a Quantova address")
	}
	kind, err := kindWord(ctx.Kind)
	if err != nil {
		return nil, err
	}
	s := make([]byte, 8)
	binary.BigEndian.PutUint64(s, uint64(size))
	return sha3Sum(rootPrefix, rootTag, genesis, contract, sender, kind, s, root), nil
}

func rootFromPath(leaf []byte, index, size int, path [][]byte) []byte {
	if len(leaf) != 32 {
		return nil
	}
	if size < 1 || size > maxLeaves {
		return nil
	}
	if index < 0 || index >= size {
		return nil
	}
	if len(path) > maxPath {
		return nil
	}
	fn := index
	sn := size - 1
	r := leaf
	for _, p := range path {
		if len(p) != 32 {
			return nil
		}
		if sn == 0 {
			return nil
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn /= 2
				sn /= 2
			}
		} else {
			r = nodeHash(r, p)
		}
		fn /= 2
		sn /= 2
	}
	if sn != 0 {
		return nil
	}
	return r
}
