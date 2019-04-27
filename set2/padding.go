package set2

import "bytes"

func PKCS7(b []byte, blockLen int) []byte {
	if b == nil {
		return b
	}

	if blockLen < 1 {
		return b
	}

	if len(b)%blockLen == 0 {
		return b
	}

	toPad := blockLen - (len(b) % blockLen)
	padding := bytes.Repeat([]byte{byte(toPad)}, toPad)

	return append(b, padding...)
}

func PKCS7Validate(p []byte, blockLen int) bool {
	if len(p)%blockLen != 0 {
		return false
	}

	lastByte := p[len(p)-1]
	paddingBytes := 1

	// Add an extra test case to see if this entire block is padding
	if bytes.Count(p, []byte{lastByte}) == len(p) {
		return true
	}

	for i := paddingBytes; i <= len(p); i++ {
		if p[len(p)-i] == lastByte {
			continue
		}

		paddingBytes = i - 1
		break
	}

	x := int(lastByte) == paddingBytes

	return x
}
