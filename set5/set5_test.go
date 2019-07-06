package set5

import (
	"bytes"
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
