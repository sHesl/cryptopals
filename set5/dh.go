package set5

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var (
	p = new(big.Int)
	g = big.NewInt(2)
)

type DiffieHellman struct {
	P, G, Pub, priv, s *big.Int
}

func init() {
	p, _ = p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
}

func NewDiffieHellman() DiffieHellman {
	x := DiffieHellman{
		P: p,
		G: g,
	}

	priv, _ := rand.Int(rand.Reader, p)
	x.priv = priv

	x.Pub = new(big.Int).Exp(x.G, x.priv, x.P)

	return x
}

func NewDiffieHellmanWithPG(P, G *big.Int) DiffieHellman {
	x := DiffieHellman{
		P: P,
		G: G,
	}

	priv, _ := rand.Int(rand.Reader, P)
	x.priv = priv

	x.Pub = new(big.Int).Exp(x.G, x.priv, x.P)

	return x
}

func (d *DiffieHellman) Key(B *big.Int) []byte {
	// B is the product of raising g^^b mod P
	// So if we raise B^^a, that is the same as G^^ab mod P
	// And of course the inverse is true (A == G^^ba mod P)
	// Determining a, b or ab from their g expmod P values is 'difficult' (discrete log problem)
	// For those who know one private element, calculate s is easy!
	s := new(big.Int).Exp(B, d.priv, d.P)
	x := sha256.Sum256(s.Bytes())

	return x[:]
}
