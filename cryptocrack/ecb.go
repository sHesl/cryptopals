package cryptocrack

import "bytes"

// DetectDuplicateBlock scans through it's input to determine whether there are two identical blocks inside.
// This is useful for detecting whether or not the given input is ECB encrypted, or for checking for aligning
// blocks in ECB.
func DetectDuplicateBlock(b []byte, blockLen int) bool {
	blocks := make([][]byte, len(b)/blockLen)
	for i := 0; i < len(b)/blockLen; i++ {
		blocks[i], _ = NthBlock(b, blockLen, i+1)
	}

	result := false
	for _, block := range blocks {
		result = bytes.Count(b, block) > 1

		if result {
			return true
		}
	}

	return false
}
