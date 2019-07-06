package set5

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/sHesl/cryptopals/set4"
)

type Server struct {
	Salt     []byte
	password []byte
	v        *big.Int
	Pub      *big.Int
	K        *big.Int

	dh DiffeHellman

	// per attempt
	Email     string
	ClientPub *big.Int
}

var k = big.NewInt(3)

func NewServer(password []byte) Server {
	s := Server{
		password: password,
		dh:       NewDiffeHellman(),
	}

	// A random salt is generated, and concatenated with the password to prevent dict/rainbow table attacks
	// It is stored for future use, as it must be sent to the client during negotiation
	salt := make([]byte, 16)
	rand.Read(salt)
	s.Salt = salt

	// Our first job is to turn this salt/password combo into a big.Int; we do so via sha256
	sp := append(s.Salt, password...)
	xH := sha256.Sum256(sp)
	x := new(big.Int).SetBytes(xH[:])

	// Use exponential modulo math (same that drives DHs), with our 'salted password' as the exponential
	s.v = new(big.Int).Exp(g, x, p)

	// Instead of just returning our DH public big.Int, we integrate v into our public component
	s.Pub = new(big.Int)
	s.Pub.Mul(k, s.v)
	s.Pub.Add(s.Pub, s.dh.Pub)
	s.Pub.Mod(s.Pub, p)

	return s
}

func (s *Server) Verify(hmac []byte) bool {
	// Derive a hash composed from the two public keys shared during negotiation
	uH := sha256.Sum256(append(s.ClientPub.Bytes(), s.Pub.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	S := new(big.Int)
	S.Exp(s.v, u, p)
	S.Mul(S, s.ClientPub)
	S.Exp(S, s.dh.priv, p)

	result := sha256.Sum256(S.Bytes())
	got := set4.SHA1MAC(result[:], s.Salt)

	return bytes.Equal(got, hmac)
}

type Client struct {
	Email string
	DiffeHellman

	// per attempt
	Salt      []byte
	ServerPub *big.Int
	result    []byte
}

func NewClient(email string) Client {
	c := Client{
		Email:        email,
		DiffeHellman: NewDiffeHellman(),
	}

	return c
}

func (c *Client) Compute(password []byte) []byte {
	// Derive our own version of x via password and previously shared salt
	sp := append(c.Salt, password...)
	xH := sha256.Sum256(sp)
	x := new(big.Int).SetBytes(xH[:])

	// Also derive a hash composed from the two public keys shared during negotiation
	uH := sha256.Sum256(append(c.Pub.Bytes(), c.ServerPub.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	// Now, do fancy exp modulo math
	//
	// S = (B - k * g**x) ** (a + u * x) % N
	// S = base**exp % N

	// base = (B - k * g**x)
	base := new(big.Int)
	base.Exp(g, x, p)
	base.Mul(base, k)
	base.Sub(c.ServerPub, base)

	// exp = (a + u * x) % N
	exp := new(big.Int)
	exp.Mul(x, u)
	exp.Add(exp, c.DiffeHellman.priv)
	exp.Mod(exp, p)

	S := new(big.Int)
	S.Exp(base, exp, p)

	result := sha256.Sum256(S.Bytes())

	return set4.SHA1MAC(result[:], c.Salt)
}
