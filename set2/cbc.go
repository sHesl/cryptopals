package set2

import (
	"bytes"
	"strings"
)

func cbcEncryptUserData(s string, key []byte, iv []byte) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	append := ";comment2=%20like%20a%20pound%20of%20bacon"

	// Quote reserved characters
	s = strings.Replace(s, ";", "';'", -1)
	s = strings.Replace(s, "=", "'='", -1)

	p := []byte(prefix + s + append)

	return aesCBCEncrypt(p, key, iv)
}

func isAdmin(p []byte) bool {
	return bytes.Contains(p, []byte(";admin=true"))
}
