package set5

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

func RSAKeyGen() rsa.PrivateKey {
	p, _ := rand.Prime(rand.Reader, 1024)
	q, _ := rand.Prime(rand.Reader, 1024)

	if p.Cmp(q) == 0 {
		return RSAKeyGen() // If our primes magically happen to be the same, try again
	}

	// Make our modulus
	n := new(big.Int).Mul(p, q)

	// Set our totient (et)
	pMinus1, qMinus1 := new(big.Int), new(big.Int)
	pMinus1.Sub(p, big.NewInt(1))
	qMinus1.Sub(q, big.NewInt(1))
	et := new(big.Int).Mul(pMinus1, qMinus1)

	// Set our exponent. Note that e=3 is weak af, Fermat
	e := big.NewInt(3)

	// d = invmod(e, et)
	d := new(big.Int).ModInverse(e, et)
	if d == nil {
		return RSAKeyGen()
	}

	// Now we've got everything we need to form a pub/private key pair!
	priv := rsa.PrivateKey{
		D:         d,
		PublicKey: rsa.PublicKey{N: n, E: 3},
	}

	return priv
}

func RSAEncrypt(pub rsa.PublicKey, plaintext []byte) []byte {
	m := new(big.Int).SetBytes(plaintext)

	c := new(big.Int)
	c.Exp(m, big.NewInt(int64(pub.E)), pub.N)

	return c.Bytes()
}

func RSADecrypt(priv rsa.PrivateKey, ciphertext []byte) []byte {
	c := new(big.Int).SetBytes(ciphertext)

	p := new(big.Int)
	p.Exp(c, priv.D, priv.N)

	return p.Bytes()
}
