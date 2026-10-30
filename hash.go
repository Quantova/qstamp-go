// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"crypto/sha3"
	"fmt"
)

var algorithmIDs = map[string]byte{
	"sha3-256": 1,
	"sha256":   2,
}

func algorithmID(name string) (byte, error) {
	id, ok := algorithmIDs[name]
	if !ok {
		return 0, fmt.Errorf("unsupported digest algorithm %q", name)
	}
	return id, nil
}

func sha3Sum(parts ...[]byte) []byte {
	h := sha3.New256()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}
