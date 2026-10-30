// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"bytes"
	"encoding/hex"
	"errors"
)

// Result is the outcome of the offline recomputation.
type Result struct {
	// RootMatches reports that the record and its Merkle path rebuild the root
	// named in the receipt.
	RootMatches bool
	// Commitment is the 32 byte value that must be anchored on chain for this
	// receipt to be genuine.
	Commitment []byte
	// CommitmentHex is Commitment in lowercase hexadecimal.
	CommitmentHex string
}

// Recompute rebuilds the Merkle root from the record and derives the on chain
// commitment. It performs no network access. A caller confirms the receipt by
// checking that Result.RootMatches is true and that Result.Commitment is the
// value anchored by the receipt transaction.
func Recompute(r Receipt) (Result, error) {
	digest, err := parse32(r.Record.Digest, "a digest")
	if err != nil {
		return Result{}, err
	}
	salt, err := parse32(r.Record.Salt, "a salt")
	if err != nil {
		return Result{}, err
	}
	leaf, err := leafHash(r.Record.Alg, digest, salt)
	if err != nil {
		return Result{}, err
	}
	root, err := parse32(r.Root, "a root")
	if err != nil {
		return Result{}, err
	}
	path := make([][]byte, 0, len(r.Proof.Path))
	for _, step := range r.Proof.Path {
		node, err := parse32(step, "a path node")
		if err != nil {
			return Result{}, err
		}
		path = append(path, node)
	}
	rebuilt := rootFromPath(leaf, r.Proof.Index, r.Proof.Size, path)
	matches := rebuilt != nil && bytes.Equal(rebuilt, root)

	ctx := CommitmentContext{
		Genesis:  r.Chain.Genesis,
		Contract: r.Contract,
		Sender:   r.Anchor.Sender,
		Kind:     r.Kind,
	}
	c, err := commitment(root, r.Proof.Size, ctx)
	if err != nil {
		return Result{}, err
	}
	return Result{
		RootMatches:   matches,
		Commitment:    c,
		CommitmentHex: hex.EncodeToString(c),
	}, nil
}

// ChainReader reads the value anchored by a transaction on the Quantova
// network. A caller supplies an implementation to confirm the commitment
// against the chain. The returned bytes are the 32 byte value placed by the
// transaction named in the receipt.
type ChainReader interface {
	AnchoredCommitment(chainID, txID string) ([]byte, error)
}

// Verify recomputes the commitment and confirms it is the value the receipt
// transaction anchored on chain. It returns an error when the record does not
// rebuild the root, when the reader fails, or when the anchored value differs
// from the recomputed commitment.
func Verify(r Receipt, reader ChainReader) (Result, error) {
	res, err := Recompute(r)
	if err != nil {
		return Result{}, err
	}
	if !res.RootMatches {
		return res, errors.New("the record and its path do not rebuild the receipt root")
	}
	if reader == nil {
		return res, errors.New("a chain reader is required to confirm the anchor")
	}
	anchored, err := reader.AnchoredCommitment(r.Chain.ID, r.Anchor.Tx)
	if err != nil {
		return res, err
	}
	if !bytes.Equal(anchored, res.Commitment) {
		return res, errors.New("the anchored value does not match the recomputed commitment")
	}
	return res, nil
}
