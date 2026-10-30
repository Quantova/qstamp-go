// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"encoding/hex"
	"errors"
	"testing"
)

type fakeReader struct {
	value []byte
	err   error
}

func (f fakeReader) AnchoredCommitment(chainID, txID string) ([]byte, error) {
	return f.value, f.err
}

func sampleReceipt(t *testing.T) (Receipt, Result) {
	t.Helper()
	v := loadVectors(t)
	r := v.Records[1]
	receipt := Receipt{
		Format:   "qstamp-receipt/1",
		Chain:    Chain{ID: "Q-conformance", Genesis: v.Genesis},
		Contract: v.Contract,
		Kind:     v.Kind,
		Record:   Record{Alg: r.Alg, Digest: r.Digest, Salt: r.Salt},
		Proof:    Proof{Index: r.Index, Size: v.Size, Path: r.Path},
		Root:     v.Root,
		Anchor:   Anchor{Tx: "tx1", Sender: v.Sender},
	}
	res, err := Recompute(receipt)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	return receipt, res
}

func TestVerifyConfirmsAnchoredCommitment(t *testing.T) {
	receipt, res := sampleReceipt(t)
	reader := fakeReader{value: res.Commitment}
	if _, err := Verify(receipt, reader); err != nil {
		t.Fatalf("verify valid receipt: %v", err)
	}
}

func TestVerifyRejectsWrongAnchor(t *testing.T) {
	receipt, res := sampleReceipt(t)
	bad := make([]byte, len(res.Commitment))
	copy(bad, res.Commitment)
	bad[0] ^= 0xff
	if _, err := Verify(receipt, fakeReader{value: bad}); err == nil {
		t.Fatal("verify accepted a mismatched anchor")
	}
}

func TestVerifyPropagatesReaderError(t *testing.T) {
	receipt, _ := sampleReceipt(t)
	if _, err := Verify(receipt, fakeReader{err: errors.New("rpc down")}); err == nil {
		t.Fatal("verify hid a reader error")
	}
}

func TestVerifyRequiresReader(t *testing.T) {
	receipt, _ := sampleReceipt(t)
	if _, err := Verify(receipt, nil); err == nil {
		t.Fatal("verify accepted a nil reader")
	}
}

func TestVerifyRejectsBrokenBinding(t *testing.T) {
	receipt, res := sampleReceipt(t)
	bad := mustHexLocal(t, receipt.Record.Digest)
	bad[0] ^= 0x01
	receipt.Record.Digest = hex.EncodeToString(bad)
	if _, err := Verify(receipt, fakeReader{value: res.Commitment}); err == nil {
		t.Fatal("verify accepted a record that does not rebuild the root")
	}
}

func TestKindWordBounds(t *testing.T) {
	if _, err := kindWord(""); err == nil {
		t.Fatal("empty kind accepted")
	}
	if _, err := kindWord("18446744073709551616"); err == nil {
		t.Fatal("kind above 64 bits accepted")
	}
	if _, err := kindWord("01"); err == nil {
		t.Fatal("kind with leading zero accepted")
	}
	if _, err := kindWord("18446744073709551615"); err != nil {
		t.Fatalf("max 64 bit kind rejected: %v", err)
	}
}

func TestParseGenesisRejectsMalformed(t *testing.T) {
	if _, err := parseGenesis("00"); err == nil {
		t.Fatal("short genesis accepted")
	}
	if _, err := parseGenesis("ZZ"); err == nil {
		t.Fatal("non hex genesis accepted")
	}
}

func TestDecodeAddressRejections(t *testing.T) {
	cases := []string{
		"",
		"Qq",
		"q1",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"Q1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzb",
	}
	for _, c := range cases {
		if _, err := addressBytes(c); err == nil {
			t.Fatalf("decoded an invalid address %q", c)
		}
	}
}

func mustHexLocal(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}
