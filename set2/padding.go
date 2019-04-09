package set2

func pkcs7(b []byte, blockLen int) []byte {
	if b == nil {
		return b
	}

	var n int
	if len(b) > blockLen {
		n = blockLen - (len(b) % blockLen)
	} else {
		n = blockLen % len(b)
	}

	if n == 0 {
		return b
	}

	for i := 0; i < n; i++ {
		b = append(b, byte(n))
	}

	return b
}

func pkcs7Validate(p []byte, blockLen int) bool {
	if len(p) != blockLen {
		return false
	}

	lastByte := p[len(p)-1]
	paddingBytes := 1

	for i := paddingBytes; i < len(p)-1; i++ {
		if p[len(p)-i] == lastByte {
			continue
		}

		paddingBytes = i - 1
		break
	}

	x := int(lastByte) == paddingBytes

	return x
}
