package set4

import (
	"bytes"
	"crypto/sha1"
)

func SHA1MAC(key, input []byte) []byte {
	s := sha1.New()
	s.Write(key)
	s.Write(input)
	return s.Sum(nil)
}

func messagePadding(input []byte) []byte {
	padding := []byte{0x80} // firstly, we must stick a '1' bit as the first character of padding

	// Then, we must calculate how many zero bits we need to add so that:
	// message length + 1 bit + zero bits = 448
	lenZeroBytes := 56 - ((len(input) + 1) % 64)
	if (len(input) % 64) > 56 {
		lenZeroBytes += 64
	}

	padding = append(padding, bytes.Repeat([]byte{0x00}, lenZeroBytes)...) // add our zero bytes

	// calculate our message length in bits...
	messageLen := make([]byte, 8)
	putUint64(messageLen, uint64(len(input)<<3))

	return append(padding, messageLen...) // ... add our message length at the end of our padding
}
