package set6

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/sHesl/cryptopals/set5"
)

func Test_Challenge41_RSAUnpaddedMessageRecovery(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	// DecryptOracle pretends to be a server that RSA decrypts the incoming ciphertext. Imagine it defends
	// against message replay via a hash of the ciphertext. The only way to get it to decrypt the message is if
	// is the first time we've seen that message.
	decryptOracle := func(c []byte) []byte {
		return set5.RSADecrypt(*privKey, c)
	}

	// Imagine we've captured this ciphertext in transit, but the server has already decrypted it. If we want it
	// to decrypt it once more, we need to change the ciphertext.
	ciphertext := set5.RSAEncrypt(privKey.PublicKey, []byte(`recover me!!!!`))

	// In this scenario, we can 're-encrypt' the ciphertext using the public key
	pubKey := privKey.PublicKey
	c1 := new(big.Int).SetBytes(ciphertext)

	// se = S**Em od N
	// C2 = (se * C1) mod N
	s := big.NewInt(25) // s can be anything > 1 mod N
	se := new(big.Int).Exp(s, big.NewInt(int64(pubKey.E)), pubKey.N)

	c2 := new(big.Int)
	c2.Mul(se, c1)
	c2.Mod(c2, pubKey.N)

	p2 := new(big.Int).SetBytes(decryptOracle(c2.Bytes()))

	// P1 = P2/S mod N
	p1 := new(big.Int).Mul(p2, new(big.Int).ModInverse(s, pubKey.N))
	p1.Mod(p1, pubKey.N).Bytes()

	if bytes.Equal(p1.Bytes(), []byte(`recover me!!!!`)) {
		fmt.Printf("Challenge 41: Recovered plaintext by re-encrypting RSA ciphertext + decrypt oracle\n")
	}
}

func Test_Challenge42_BleichenbacherE3Attack(t *testing.T) {
	weakKey := set5.RSAKeyGen() // We need a key with e=3
	message := []byte(`this is the message we are forging the signature for`)

	validSig := RSASignSHA256(&weakKey, message)

	hm := sha256.Sum256(message)
	goImplSig, _ := rsa.SignPKCS1v15(rand.Reader, &weakKey, crypto.SHA256, hm[:])

	if !bytes.Equal(validSig, goImplSig) {
		t.Fatalf("Your RSA PKCS1v15 signing implemention is not correct!")
	}

	if err := rsa.VerifyPKCS1v15(&weakKey.PublicKey, crypto.SHA256, hm[:], validSig); err != nil {
		t.Fatalf("Your RSA signature was not verified by official go implemention")
	}

	if !DodgeyRSAVerifySHA256(&weakKey.PublicKey, message, validSig) {
		t.Fatalf("Your DodgeyRSAVerifySHA256 did not respect a valid sig")
	}

	if DodgeyRSAVerifySHA256(&weakKey.PublicKey, message, validSig[1:]) {
		t.Fatalf("Your DodgeyRSAVerifySHA256 did not reject an invalid sig")
	}

	fakeSig := []byte{0x00, 0x01, 0x00}
	fakeSig = append(fakeSig, sha256ANS1...)
	fakeSig = append(fakeSig, hm[:]...)

	// fill the block with 0xffs. It must be the highest byte to ensure the cube root value is sufficiently
	// large enough for all of the corruption (aka the bytes of discrepency between the valid sig and our fake)
	// occur AFTER the message hash, which a bad implementation will not verify!
	padLen := weakKey.Size() - len(fakeSig)
	fakeSig = append(fakeSig, bytes.Repeat([]byte{0xff}, padLen)...)

	// Instead of doing RSAEncrypt on our signature, we just cube root it. This value will be much larger than
	// the valid signature, but as the verifier is not checking the contents beyond the hash, they will not
	// realise this!
	root := CubeRoot(new(big.Int).SetBytes(fakeSig))

	// VALID:   00 01 | 0xff... | ANSI | HASH
	// INVALID: 00 01 01 | ANSI | HASH | 0xff...
	// CHECK:  |_______________________|         // a bad implementation only checks up to hash, and not beyond

	if DodgeyRSAVerifySHA256(&weakKey.PublicKey, message, root.Bytes()) {
		fmt.Printf("Challenge 42: Forged an RSA signature via Bleichenbacher e=3 attack!\n")
	}
}

func Test_Challenge43_DSAKeyRecoveryFromNonce(t *testing.T) {
	key := NewDSAKey()
	m := []byte(`testing DSA signing and verifying works`)
	r, sig := key.Sign(m)

	if !key.Verify(m, r, sig) {
		t.Fatal("DSA signing and verification not implemented correctly")
	}

	if key.Verify(m[1:], r, sig) {
		t.Fatal("DSA signing and verification not implemented correctly")
	}

	// Now we've verified our DSA is implemented correctly, let's try and crack a weak K
	y, _ := new(big.Int).SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	r, _ = new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)

	m = []byte(`For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
`)

	x := BruteForceViaWeakK(m, r, s, y)
	xHex := fmt.Sprintf("%x", x)
	xDigest := fmt.Sprintf("%x", sha1.Sum([]byte(xHex)))

	if xDigest == "0954edd5e0afe5542a4adf012611a91912a3ec16" {
		fmt.Printf("Challenge 43: Cracked a DSA private component via weak K! x = %X", x.Bytes())
	}
}
