package set5

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/sHesl/cryptopals/set4"
)

func Test_Challenge33_DiffeHellman(t *testing.T) {
	a := NewDiffeHellman()
	b := NewDiffeHellman()

	aKey := a.Key(b.Pub)
	bKey := b.Key(a.Pub)

	if !bytes.Equal(aKey, bKey) {
		t.Fatalf("Diffe-Hellman secret generated did not match across participants")
	}

	fmt.Printf("Challenge 33: Diffe-Hellman shared secret generated!\n")
}

func Test_Challenge34_DiffeHellmanMITMKeyFixing(t *testing.T) {
	alice := NewDiffeHellman()
	bob := NewDiffeHellman()
	eve := NewDiffeHellman()

	alicesKey := alice.Key(p)
	bobsKey := bob.Key(p)
	evesKey := eve.Key(p)

	if !bytes.Equal(alicesKey, bobsKey) || !bytes.Equal(alicesKey, evesKey) {
		t.Fatalf("Key fixed Diffe-Hellman should produce identical secret between participants")
	}

	fmt.Printf("Challenge 34: Diffe-Hellman key fixing successful!\n")
}

func Test_Challenge35_DiffeHellmanMaliciousG(t *testing.T) {
	// First, let us experiment with setting G to be 1
	alice := NewDiffeHellmanWithPG(p, big.NewInt(1))
	bob := NewDiffeHellmanWithPG(p, big.NewInt(1))

	// priv = rand % p
	// pub = (1^^priv) % p == 1 % p == p
	// s   = (pub^^priv) % p == (1^^priv) % p == 1
	// If g is 1, the session key is always guaranteed to be 1
	alicesKey := alice.Key(bob.Pub)
	bobsKey := bob.Key(alice.Pub)

	hash1 := sha256.Sum256(big.NewInt(1).Bytes()) // SHA256 on '1' to prove that key is formed from 1

	if !bytes.Equal(alicesKey, bobsKey) || !bytes.Equal(alicesKey, hash1[:]) {
		t.Fatalf("Malicious Diffe-Hellman should produce identical and predictable secret between participants")
	}

	// Let's also take a look what happens when g=p
	alice = NewDiffeHellmanWithPG(p, p)
	bob = NewDiffeHellmanWithPG(p, p)

	// priv = rand % p
	// pub = (p^^priv) % p == 0
	// s   = (0^^priv) % p == 0
	// If g = p, the session key is always guaranteed to be 0
	alicesKey = alice.Key(bob.Pub)
	bobsKey = bob.Key(alice.Pub)

	hash0 := sha256.Sum256(big.NewInt(0).Bytes()) // SHA256 on '0' to prove that key is formed from 0

	if !bytes.Equal(alicesKey, bobsKey) || !bytes.Equal(alicesKey, hash0[:]) {
		t.Fatalf("Malicious Diffe-Hellman should produce identical and predictable secret between participants")
	}

	// Finally, let's check out  g=p-1
	pMinus1 := new(big.Int)
	pMinus1.Sub(p, big.NewInt(1))

	alice = NewDiffeHellmanWithPG(p, pMinus1)
	bob = NewDiffeHellmanWithPG(p, pMinus1)

	// priv = rand % p
	// pub = ((p-1)^^priv) % p == 1 OR p-1
	// s   = (1^^priv) % p == 0 or p-1
	// If g = p-1, the session key either 1, or p-1
	alicesKey = alice.Key(bob.Pub)
	bobsKey = bob.Key(alice.Pub)

	hashP := sha256.Sum256(pMinus1.Bytes())

	if (!bytes.Equal(alicesKey, hashP[:]) && !bytes.Equal(alicesKey, hash1[:])) || !bytes.Equal(alicesKey, bobsKey) {
		t.Fatalf("Malicious Diffe-Hellman should produce identical and predictable secret between participants")
	}

	fmt.Printf("Challenge 35: Diffe-Hellman exploited via malicious G params!\n")
}

func Test_Challenge36_SecureRemotePassword(t *testing.T) {
	server := NewServer([]byte(`nobodywillguessthispassphrase!`))
	client := NewClient("shesl+cryptopals@email.com")

	// Client sends email and pub to server
	server.Email = client.Email
	server.ClientPub = client.Pub

	// Server sends salt and pub to client
	client.Salt = server.Salt
	client.ServerPub = server.Pub

	// Let's see if this works!
	correct := client.Compute([]byte(`nobodywillguessthispassphrase!`))

	if !server.Verify(correct) {
		t.Fatalf("Server did not corroborate password negotiation")
	}

	// Let's check it fails on an incorrect password
	incorrect := client.Compute([]byte(`qwerty123`))

	if server.Verify(incorrect) {
		t.Fatalf("Server failed to detect incorrect password!")
	}

	fmt.Printf("Challenge 36: SRP implemented successfully!\n")
}

func Test_Challenge37_BreakSecureRemotePassword(t *testing.T) {
	server := NewServer([]byte(`nobodywillguessthispassphrase!`))
	client := NewClient("shesl+cryptopals@email.com")
	server.Email = client.Email

	// Client sends a bogus pub key to the server
	server.ClientPub = big.NewInt(0)

	// We don't even need to calculate S, because we know it will be zero'd, so just hash a zero'd big.Int
	result := sha256.Sum256(big.NewInt(0).Bytes())
	zerodHMAC := set4.SHA1MAC(result[:], server.Salt) // Don't forget we still need to salt!

	// The zero'd public key from the client should force the server to compute s=0
	if !server.Verify(zerodHMAC) {
		t.Fatalf("Server did not corroborate password negotiation")
	}

	fmt.Printf("Challenge 37: SRP broken via zero key!\n")
}

func Test_Challenge38_DictionaryAttackSimplifiedSRP(t *testing.T) {
	server := NewSimpleServer([]byte(`anotherverysecurepassphrase!!!!!!`))
	client := NewSimpleClient("shesl+cryptopals@email.com")

	// Client sends email and pub to server
	server.Email = client.Email
	server.ClientPub = client.Pub

	// Server sends salt, pub and U to client
	client.Salt = server.Salt
	client.ServerPub = server.Pub
	client.U = server.U

	// Let's prove our simple SRP still works
	correct := client.Compute([]byte(`anotherverysecurepassphrase!!!!!!`))

	if !server.Verify(correct) {
		t.Fatalf("Server did not corroborate simple SRP password negotiation")
	}

	incorrect := client.Compute([]byte(`wrong password -_-`))

	if server.Verify(incorrect) {
		t.Fatalf("Server accepted an invalid password during simple SRP!")
	}

	// Now, we use a malicious B to help us crack the password of an unsuspecting client
	maliciousServer := NewSimpleServer([]byte(`I don't actually know the password :(, must crack it!`))
	unsuspectingClient := NewSimpleClient("shesl+cryptopals@email.com")

	// As with 'full' SRP, the client sends it's pub and email
	maliciousServer.Email = unsuspectingClient.Email
	maliciousServer.ClientPub = unsuspectingClient.Pub

	// The values for pub, salt, and U are the same for every attempt because we don't need to integrate the
	// correct password into the negotiation! This means we can communicate to the client once, retrieve their
	// hashed password, and then start attempting to dictionary attack if offline, using the agreed values for
	// U, salt, and the client's public key!
	unsuspectingClient.ServerPub = maliciousServer.Pub
	unsuspectingClient.Salt = maliciousServer.Salt
	unsuspectingClient.U = maliciousServer.U

	dictionary := [][]byte{
		[]byte(`attempt1`),
		[]byte(`attempt2`),
		[]byte(`attempt3`),
		[]byte(`attempt4`),
		[]byte(`the_actual_passphrase`), // imagine our dictionary/rainbow was huge enough to contain all elements
	}

	// Here, we are demonstrating that we can attempt to determine the value the client provided as their
	// passphrase, without actually communicating/renegotiating with the client again. This 'offline' attack
	// means only a single, seemingly innocuous 'invalid login' attempt is required to begin brute forcing!
	clientHMAC := unsuspectingClient.Compute([]byte(`the_actual_passphrase`))

	for i, attempt := range dictionary {
		attemptHMAC := maliciousServer.HMACAttempt(attempt)
		isPassword := bytes.Equal(clientHMAC, attemptHMAC)

		if i <= 3 && isPassword {
			t.Fatalf("Malicious simple SRP server incorrectly determined client's password")
		}

		if i == 4 && !isPassword {
			t.Fatalf("Malicious simple SRP server failed to acknowledge correct client password")
		}

		if i == 4 && isPassword {
			fmt.Printf("Challenge 38: Successfully brute forced client's password using malicious simple SRP!\n")
		}
	}
}

func Test_Challenge39_RSA(t *testing.T) {
	priv := RSAKeyGen()

	plaintext := []byte(`this was too easy!`)

	ciphertext := RSAEncrypt(priv.PublicKey, plaintext)
	result := RSADecrypt(priv, ciphertext)

	if bytes.Equal(plaintext, result) {
		fmt.Printf("Challenge 39: RSA with KeyGen implemented! \n\tCiphertext was '%X'\n\tPlaintext was '%s'\n", ciphertext, plaintext)
	}
}

func Test_Challenge40_RSABroadcastE3Attack(t *testing.T) {
	p := []byte(`gosh, I hope this message is kept secure!`)

	k1, k2, k3 := RSAKeyGen(), RSAKeyGen(), RSAKeyGen()
	ct1, ct2, ct3 := RSAEncrypt(k1.PublicKey, p), RSAEncrypt(k2.PublicKey, p), RSAEncrypt(k3.PublicKey, p)

	crtResult := CRT3(new(big.Int).SetBytes(ct1), new(big.Int).SetBytes(ct2), new(big.Int).SetBytes(ct3), k1.N, k2.N, k3.N)

	// To finish this all off, we need the cube root of this value!
	result := new(big.Int).Rsh(crtResult, uint(crtResult.BitLen())/3*2)

	// Shameless copy-paste from https://github.com/FiloSottile/mostly-harmless/blob/master/cryptopals/set5.go
	// This is just a cube-root implementation for big nums.
	// Cube root is needed because e=3!
	for {
		d := new(big.Int).Exp(result, big.NewInt(3), nil)
		d.Sub(d, crtResult)
		d.Div(d, big.NewInt(3))
		d.Div(d, result)
		d.Div(d, result)
		if d.Sign() == 0 {
			break
		}
		result.Sub(result, d)
	}

	for new(big.Int).Exp(result, big.NewInt(3), nil).Cmp(crtResult) < 0 {
		result.Add(result, big.NewInt(1))
	}
	for new(big.Int).Exp(result, big.NewInt(3), nil).Cmp(crtResult) > 0 {
		result.Sub(result, big.NewInt(1))
	}

	// Our D isn't the 'D' from any of our keys, instead it represents a 'middle' D from of our keys
	// combined, then cube rooted. As a result, we *don't* want to apply the final modulo. An easy way to
	// achieve that, is to take our D and add one, and use that as the mod, D mod D+1 = D =/= D
	attackKey := rsa.PrivateKey{D: result}
	attackKey.N = new(big.Int).Add(attackKey.D, big.NewInt(1))

	recoveredPlaintext := RSADecrypt(attackKey, ct1)

	if bytes.Equal(recoveredPlaintext, p) {
		fmt.Printf("Challenge 40: RSA e=3 CRT attack successful!\n\tPlaintext was '%s'\n", recoveredPlaintext)
	}
}
