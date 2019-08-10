package set6

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
)

var dsaP, dsaQ, dsaG, bigZero, bigOne *big.Int

func init() {
	dsaP, _ = new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	dsaQ, _ = new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	dsaG, _ = new(big.Int).SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
}

type DSAKey struct {
	Pub  *big.Int
	Priv *big.Int
}

func NewDSAKey() *DSAKey {
	x, _ := rand.Int(rand.Reader, dsaQ)
	y := new(big.Int).Exp(dsaG, x, dsaP)

	return &DSAKey{Pub: y, Priv: x}
}

func (key *DSAKey) Sign(m []byte) (*big.Int, *big.Int) {
	k, _ := rand.Int(rand.Reader, dsaQ)

	// r = (g^^k mod p) mod q
	gkp := new(big.Int).Exp(dsaG, k, dsaP)
	r := new(big.Int).Mod(gkp, dsaQ)

	if r.Int64() == 0 {
		return key.Sign(m)
	}

	// s = (k^^-1 (H(m)+xr)) mod q
	h := sha256.Sum256(m)
	hm := new(big.Int).SetBytes(h[:])

	xr := new(big.Int).Mul(key.Priv, r)
	hxr := new(big.Int).Add(hm, xr)

	kInv := new(big.Int).ModInverse(k, dsaQ)
	kInvHMXR := new(big.Int).Mul(kInv, hxr)

	s := new(big.Int).Mod(kInvHMXR, dsaQ)

	if s.Int64() == 0 {
		return key.Sign(m)
	}

	return r, s
}

func (key *DSAKey) Verify(m []byte, r, s *big.Int) bool {
	if r.Cmp(dsaQ) != -1 || s.Cmp(dsaQ) != -1 {
		return false
	}

	w := new(big.Int).ModInverse(s, dsaQ)

	h := sha256.Sum256(m)
	hm := new(big.Int).SetBytes(h[:])

	u1 := new(big.Int).Mul(hm, w)
	u1.Mod(u1, dsaQ)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, dsaQ)

	gu1 := new(big.Int).Exp(dsaG, u1, dsaP)
	yu2 := new(big.Int).Exp(key.Pub, u2, dsaP)
	gu1yu2 := new(big.Int).Mul(gu1, yu2)
	v := new(big.Int).Mod(gu1yu2, dsaP)
	v.Mod(v, dsaQ)

	return v.Cmp(r) == 0
}

// BruteForceViaWeakK assumes k is < 65536 (2^^16) and brute forces k values to find a k that reveals an X
// that satisfies g^^x mod P == y (same exp that is performed during key gen for that X).
func BruteForceViaWeakK(m []byte, r, sig, y *big.Int) *big.Int {
	h := sha1.Sum(m)
	hm := new(big.Int).SetBytes(h[:])
	rInv := new(big.Int).ModInverse(r, dsaQ)

	for i := int64(1); i < 65536; i++ {
		k := new(big.Int).SetInt64(i)
		sk := new(big.Int).Mul(sig, k)
		sk.Mod(sk, dsaQ)

		x := new(big.Int).Sub(sk, hm)
		x.Mul(x, rInv)
		x.Mod(x, dsaQ)

		// Perform the same step we do during key generation using this 'x' value.
		// If the resulting Y is the same, we've cracked the private component
		result := new(big.Int).Exp(dsaG, x, dsaP)
		if y.Cmp(result) == 0 {
			return x
		}
	}

	return nil
}

// CrackPrivKeyFromReusedK takes two messages that had a reused K and determines the priv component via math.
//     (H(m1) - H(m2))
// k = --------------- mod q
//        (s1 - s2)
func CrackPrivKeyFromReusedK(m1, m2 []byte, s1, s2, r *big.Int) *big.Int {
	h1, h2 := sha1.Sum(m1), sha1.Sum(m2)
	hm1, hm2 := new(big.Int).SetBytes(h1[:]), new(big.Int).SetBytes(h2[:])

	m, mq := new(big.Int), new(big.Int)
	m.Sub(hm1, hm2)
	mq.Mod(m, dsaQ)

	s, sq, sqInv := new(big.Int), new(big.Int), new(big.Int)
	s.Sub(s1, s2)
	sq.Mod(s, dsaQ)
	sqInv.ModInverse(sq, dsaQ)

	k := new(big.Int)
	k.Mul(sqInv, mq).Mod(k, dsaQ)

	rInv := new(big.Int).ModInverse(r, dsaQ)

	// We only need to solve for one message, let's just use s1
	x := new(big.Int).Mul(s1, k)
	x.Mod(x, dsaQ)
	x.Sub(x, hm1)
	x.Mul(x, rInv)
	x.Mod(x, dsaQ)

	return x
}

func (key *DSAKey) SignWithCustomParams(m []byte, p, q, g *big.Int) (*big.Int, *big.Int) {
	k, _ := rand.Int(rand.Reader, q)

	// r = (g^^k mod p) mod q
	gkp := new(big.Int).Exp(g, k, p)
	r := new(big.Int).Mod(gkp, q)

	// s = (k^^-1 (H(m)+xr)) mod q
	h := sha256.Sum256(m)
	hm := new(big.Int).SetBytes(h[:])

	xr := new(big.Int).Mul(key.Priv, r)
	hxr := new(big.Int).Add(hm, xr)

	kInv := new(big.Int).ModInverse(k, q)
	kInvHMXR := new(big.Int).Mul(kInv, hxr)

	s := new(big.Int).Mod(kInvHMXR, q)

	return r, s
}

func (key *DSAKey) VerifyWithCustomParams(m []byte, r, s, p, q, g *big.Int) bool {
	w := new(big.Int).ModInverse(s, q)

	h := sha256.Sum256(m)
	hm := new(big.Int).SetBytes(h[:])

	u1 := new(big.Int).Mul(hm, w)
	u1.Mod(u1, q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, q)

	gu1 := new(big.Int).Exp(g, u1, p)
	yu2 := new(big.Int).Exp(key.Pub, u2, p)
	gu1yu2 := new(big.Int).Mul(gu1, yu2)
	v := new(big.Int).Mod(gu1yu2, p)
	v.Mod(v, q)

	return v.Cmp(r) == 0
}

func (key *DSAKey) MagicSignature() (*big.Int, *big.Int) {
	z, _ := rand.Int(rand.Reader, dsaQ)

	// r = ((y**z) % p) % q
	yz := new(big.Int).Exp(key.Pub, z, dsaP)

	r := new(big.Int)
	r.Mod(yz, dsaQ)

	//       r
	// s =  --- % q
	//       z
	// aka
	//
	// s =  ((r % q) * modInv(z, q)) % q
	//
	s := new(big.Int)
	rq := new(big.Int).Mod(r, dsaQ)
	zq := new(big.Int).ModInverse(z, dsaQ)
	s.Mul(rq, zq).Mod(s, dsaQ)

	return r, s
}
