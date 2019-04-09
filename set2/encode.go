package set2

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/sHesl/cryptopals/set1"
)

type userECBEncrypter struct {
	key []byte
}

func newUserECBEncrypter() *userECBEncrypter {
	k := make([]byte, 32)
	rand.Read(k)

	return &userECBEncrypter{key: k}
}

func (e *userECBEncrypter) encrypt(email string) []byte {
	prof := []byte(profileFor(email))
	p := pkcs7(prof, len(e.key))

	return set1.AESECBEncrypt(p, e.key)
}

func (e *userECBEncrypter) decrypt(c []byte) []byte {
	return set1.AESECBDecrypt(c, e.key)
}

func profileFor(email string) string {
	email = strings.Replace(email, "&", "§", -1)
	email = strings.Replace(email, "=", "§", -1)

	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}
