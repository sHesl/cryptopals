package cryptocrack

import "errors"

var (
	ErrorNegativeBlockLength   = errors.New("negative block length specified")
	ErrorBlockStartOutOfBounds = errors.New("block start index exceeds length of content")
)

func NthBlock(b []byte, blockLen, n int) ([]byte, error) {
	if blockLen < 1 {
		return nil, ErrorNegativeBlockLength
	}

	si := (blockLen * n) - blockLen
	if si > len(b) {
		return nil, ErrorBlockStartOutOfBounds
	}

	ei := blockLen * n
	if ei > len(b) {
		return b[si:], nil
	}

	return b[si:ei], nil
}

func LastBlockIndex(b []byte, blockLen int) int {
	if len(b)%blockLen == 0 {
		return len(b) - blockLen
	}

	i := (len(b) / blockLen) * blockLen
	return i
}

func LastBlock(b []byte, blockLen int) []byte {
	if blockLen > len(b) {
		return b
	}

	return b[LastBlockIndex(b, blockLen):]
}
