package set5

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	mrand "math/rand"

	"github.com/sHesl/cryptopals/set4"
)

type SimpleSRPServer struct {
	Salt     []byte
	password []byte
	v        *big.Int
	Pub      *big.Int
	K        *big.Int
	U        *big.Int

	dh DiffieHellman

	// per attempt
	Email     string
	ClientPub *big.Int
}

func NewSimpleServer(password []byte) SimpleSRPServer {
	s := SimpleSRPServer{
		password: password,
		dh:       NewDiffieHellman(),
	}

	// A random salt is generated, and concatenated with the password to prevent dict/rainbow table attacks
	// It is stored for future use, as it must be sent to the client during negotiation
	salt := make([]byte, 16)
	rand.Read(salt)
	s.Salt = salt

	// If we know the password, this 'v' is correct. If not, we need to set it per attempt when brute forcing!
	sp := append(s.Salt, password...)
	xH := sha256.Sum256(sp)
	x := new(big.Int).SetBytes(xH[:])

	s.v = new(big.Int).Exp(g, x, p)

	// A secure implemention integrates v into the public key, but this 'simple' implementation just returns
	// the Diffie-Hellman public component
	s.Pub = s.dh.Pub

	// Also use a random number for our U, instead of hashing public keys together
	s.U = big.NewInt(mrand.Int63())

	return s
}

func (s *SimpleSRPServer) Verify(hmac []byte) bool {
	// Derive a hash composed from the two public keys shared during negotiation
	S := new(big.Int)

	S.Exp(s.v, s.U, p) // using our random U instead of pub key hashes
	S.Mul(S, s.ClientPub)
	S.Exp(S, s.dh.priv, p)

	result := sha256.Sum256(S.Bytes())
	got := set4.SHA1MAC(result[:], s.Salt)

	return bytes.Equal(got, hmac)
}

func (s *SimpleSRPServer) HMACAttempt(attempt []byte) []byte {
	// None of these values change between attempts, so we can just feed 'attempts' from our dictionary
	// and see which one matches the client's HMAC!

	// But first, we need to set v to be whatever the client included
	sp := append(s.Salt, attempt...)
	xH := sha256.Sum256(sp)
	x := new(big.Int).SetBytes(xH[:])

	s.v = new(big.Int).Exp(g, x, p)

	S := new(big.Int)
	S.Exp(s.v, s.U, p) // using our random U instead of pub key hashes
	S.Mul(S, s.ClientPub)
	S.Exp(S, s.dh.priv, p)

	result := sha256.Sum256(S.Bytes())

	return set4.SHA1MAC(result[:], s.Salt)
}

type SimpleSRPClient struct {
	Email string
	DiffieHellman

	// per attempt
	Salt      []byte
	ServerPub *big.Int
	U         *big.Int
	result    []byte
}

func NewSimpleClient(email string) SimpleSRPClient {
	c := SimpleSRPClient{
		Email:         email,
		DiffieHellman: NewDiffieHellman(),
	}

	return c
}

func (c *SimpleSRPClient) Compute(password []byte) []byte {
	sp := append(c.Salt, password...)
	xH := sha256.Sum256(sp)
	x := new(big.Int).SetBytes(xH[:])

	exp := new(big.Int)
	exp.Mul(x, c.U) // use the 'random' U decreed by the server
	exp.Add(exp, c.DiffieHellman.priv)
	exp.Mod(exp, p)

	S := new(big.Int)
	S.Exp(c.ServerPub, exp, p) // Use the server pub as the base, rather than integrating the password

	result := sha256.Sum256(S.Bytes())

	return set4.SHA1MAC(result[:], c.Salt)
}
