package set4

import "golang.org/x/crypto/md4"

func MD4MAC(key, input []byte) []byte {
	m := md4.New()
	m.Write(key)
	m.Write(input)
	return m.Sum(nil)
}
