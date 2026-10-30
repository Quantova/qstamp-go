// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"encoding/binary"
	"errors"
	"math/big"
	"regexp"
)

var kindPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

var maxKind = new(big.Int).SetUint64(^uint64(0))

func kindWord(kind string) ([]byte, error) {
	if !kindPattern.MatchString(kind) {
		return nil, errors.New("the record kind must be a decimal string")
	}
	k, ok := new(big.Int).SetString(kind, 10)
	if !ok || k.Cmp(maxKind) > 0 {
		return nil, errors.New("the record kind must fit in 64 bits")
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, k.Uint64())
	return out, nil
}
