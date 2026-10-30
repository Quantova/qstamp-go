// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package qstamp

import (
	"errors"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const bech32mConst = 0x2bc830a3

var generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

const maxEncoded = 128

var charsetReverse = buildCharsetReverse()

func buildCharsetReverse() [256]int16 {
	var table [256]int16
	for i := range table {
		table[i] = -1
	}
	for i := 0; i < len(charset); i++ {
		table[charset[i]] = int16(i)
	}
	return table
}

func polymod(values []uint32) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for bit := uint(0); bit < 5; bit++ {
			if (top>>bit)&1 == 1 {
				chk ^= generator[bit]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []uint32 {
	out := make([]uint32, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, uint32(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, uint32(hrp[i])&31)
	}
	return out
}

func convertBitsTo8(data []uint32) ([]byte, error) {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(data)*5/8)
	for _, value := range data {
		if value>>5 != 0 {
			return nil, errors.New("value out of range")
		}
		acc = (acc<<5 | value) & 0xfff
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>bits)&0xff))
		}
	}
	if bits >= 5 || (acc<<(8-bits))&0xff != 0 {
		return nil, errors.New("invalid padding")
	}
	return out, nil
}

func decodeAddress(text, expectedHRP string, expectedLength int) ([]byte, error) {
	if len(text) == 0 {
		return nil, errors.New("the identifier is empty")
	}
	if len(text) > maxEncoded {
		return nil, errors.New("the identifier is too long")
	}
	hasLower := strings.ToUpper(text) != text
	hasUpper := strings.ToLower(text) != text
	if hasLower && hasUpper {
		return nil, errors.New("the identifier mixes upper and lower case")
	}
	lowered := strings.ToLower(text)
	separator := strings.LastIndex(lowered, "1")
	if separator < 1 || separator+7 > len(lowered) {
		return nil, errors.New("the identifier has no separator")
	}
	hrp := lowered[:separator]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return nil, errors.New("the identifier prefix holds a bad character")
		}
	}
	if hrp != strings.ToLower(expectedHRP) {
		return nil, errors.New("the identifier carries the wrong prefix")
	}
	tail := lowered[separator+1:]
	groups := make([]uint32, 0, len(tail))
	for i := 0; i < len(tail); i++ {
		v := charsetReverse[tail[i]]
		if v < 0 {
			return nil, errors.New("the identifier holds a character outside the alphabet")
		}
		groups = append(groups, uint32(v))
	}
	if polymod(append(hrpExpand(hrp), groups...)) != bech32mConst {
		return nil, errors.New("the identifier checksum does not verify")
	}
	payload, err := convertBitsTo8(groups[:len(groups)-6])
	if err != nil {
		return nil, errors.New("the identifier does not decode to whole bytes")
	}
	if expectedLength >= 0 && len(payload) != expectedLength {
		return nil, errors.New("the identifier does not hold the expected number of bytes")
	}
	return payload, nil
}

func addressBytes(address string) ([]byte, error) {
	return decodeAddress(address, "Q", 32)
}
