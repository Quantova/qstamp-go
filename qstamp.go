// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package qstamp verifies Qstamp evidence receipts offline. A Qstamp receipt
// binds a record digest to a Merkle root, and the root to a 32 byte commitment
// that is anchored as a transaction on the Quantova network. This package
// recomputes that commitment from the receipt and the record, so a verifier can
// confirm the binding without trusting the issuer and then check the commitment
// against the chain through a ChainReader.
package qstamp

import (
	"encoding/hex"
	"errors"
	"regexp"
)

// CommitmentContext is the chain bound context that fixes a commitment to one
// deployment and one sender.
type CommitmentContext struct {
	Genesis  string
	Contract string
	Sender   string
	Kind     string
}

// Receipt is the Qstamp receipt object in the version one format.
type Receipt struct {
	Format   string `json:"format"`
	Chain    Chain  `json:"chain"`
	Contract string `json:"contract"`
	Kind     string `json:"kind"`
	Record   Record `json:"record"`
	Proof    Proof  `json:"proof"`
	Root     string `json:"root"`
	Anchor   Anchor `json:"anchor"`
	Until    uint64 `json:"until,omitempty"`
}

// Chain names the network a receipt was anchored on.
type Chain struct {
	ID      string `json:"id"`
	Genesis string `json:"genesis"`
}

// Record is the stamped record, carried as the digest and the salt.
type Record struct {
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
	Salt   string `json:"salt"`
}

// Proof is the Merkle position of a record inside its batch.
type Proof struct {
	Index int      `json:"index"`
	Size  int      `json:"size"`
	Path  []string `json:"path"`
}

// Anchor is the on chain placement of the commitment.
type Anchor struct {
	Tx     string `json:"tx"`
	Height uint64 `json:"height"`
	Block  string `json:"block"`
	Time   int64  `json:"time"`
	Sender string `json:"sender"`
}

var (
	genesisPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex64Pattern   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

func parseGenesis(genesis string) ([]byte, error) {
	if !genesisPattern.MatchString(genesis) {
		return nil, errors.New("the genesis hash must be 64 lowercase hexadecimal characters")
	}
	return hex.DecodeString(genesis)
}

func parse32(value, what string) ([]byte, error) {
	if !hex64Pattern.MatchString(value) {
		return nil, errors.New(what + " is 32 bytes written as 64 hexadecimal characters")
	}
	return hex.DecodeString(value)
}
