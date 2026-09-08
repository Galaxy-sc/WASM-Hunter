package utils

import "math"

// ShannonEntropy calculates the Shannon entropy of a given string to determine its randomness
func ShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range data {
		counts[r]++
	}
	var entropy float64
	length := float64(len(data))
	for _, count := range counts {
		px := count / length
		entropy -= px * math.Log2(px)
	}
	return entropy
}

// ReadLEB128 parses an Unsigned Little Endian Base 128 integer from a byte slice
func ReadLEB128(data []byte) (uint32, int) {
	var result uint32
	var shift uint
	var bytesRead int
	for {
		if bytesRead >= len(data) {
			break
		}
		b := data[bytesRead]
		bytesRead++
		result |= uint32(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	return result, bytesRead
}

// ReadSLEB128 parses a Signed Little Endian Base 128 integer from a byte slice
func ReadSLEB128(data []byte) (int64, int) {
	var result int64
	var shift uint
	var bytesRead int
	var b byte
	for {
		if bytesRead >= len(data) {
			break
		}
		b = data[bytesRead]
		bytesRead++
		result |= (int64(b&0x7f) << shift)
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	if (shift < 64) && (b&0x40 != 0) {
		result |= -(1 << shift)
	}
	return result, bytesRead
}