package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/sHesl/cryptopals/cryptocrack"
)

func main() {
	hashFn := func(m, h []byte, byteLen int) []byte {
		buf := make([]byte, 16)
		copy(buf, m)

		b, _ := aes.NewCipher(h) // h (aka digest) is used as the key
		b.Encrypt(buf, buf)      // message block encrypted under h gives us another digest

		// We're dealing with a 16 byte block size here, which gives us 256^16 possible outcomes, waaaay to many.
		// In order to reduce the space, truncate the result to byteLen, and reduce the charset to base 64
		for i := range m {
			buf[i] = buf[i]/4 + 31 // 256/4 for base 64, +31 so we fall between alphanumeric chars
		}

		return append(buf[:byteLen], bytes.Repeat([]byte{0}, 16-byteLen)...) // repad back to 16 bytes
	}

	// iterativeHashFn takes a long message 'm' and repeatedly hashes 16 byte blocks, each iteration using
	// the digest produced by the previous step.
	iterativeHashFn := func(m []byte, h []byte, byteLen int) []byte {
		block := make([]byte, 16)
		digest := make([]byte, len(h))
		copy(digest, h)

		for i := 0; i < len(m); i += 16 {
			copy(block, m[i:i+16])
			digest = hashFn(block, digest, byteLen)
		}
		return digest
	}

	colGenFn := func(h, t []byte, byteLen int) func(m []byte) bool {
		return func(m []byte) bool { return bytes.Equal(t, hashFn(m, h, byteLen)) }
	}

	// We start with any given initial state, and we're looking for any single collision against a given message
	charset := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890=+")
	initialH := []byte("preseeded digest")
	initialByteLen := 3

	// Now we begin the main part of the challenge! We need to find loads of collisions in the weakest hash of a
	// combinative hash function, so that the stronger hash also contains a collision within that space:
	// h := weakerHash(m) || strongerHash(m)

	// In order to generate collisions faster, we're going to use the info we learnt earlier in the challenge:
	// Let's start with a pool of initial collisions, and then find iterative collisions from that pool. Start
	// with a single collision, and then iterate to find the next set of blocks that collide. To get n
	// collisions this way, we will need to find n/2 pairs that we can rejig into n collisions (rule of products
	// tells us that from set of pairs, the number of combinations we can make is 2*no of pairs, hence n/2).
	// We would usually be doing 256^byteLen (or 2^bitLen) for our collision space, but we've also limited our
	// digest space to only alphanumeric chars, so it would be more like (256/4)^byteLen, but I know for sure
	// even that is overkill, 500 is enough.
	weakCollisionsTarget := 500
	weakCollisionPool := make([][][]byte, weakCollisionsTarget/2)
	previousState := initialH

	for i := 0; i < len(weakCollisionPool); i++ {
		// Use the previous state as the h for our next iteration. We also re-use it as the message we're
		// looking to get another collision from (though we could have used literally any string here)
		outputState := hashFn(previousState, previousState, initialByteLen)

		// ... now we just need to find any given message that collides with this random message
		iter := make([][]byte, 3) // record both m1, m2 and hash(m1)
		iter[0] = previousState
		iter[1] = <-cryptocrack.BruteForce(charset, 16, colGenFn(previousState, outputState, initialByteLen), 1)
		iter[2] = outputState

		weakCollisionPool[i] = iter
		previousState = outputState
		fmt.Printf("collision %d\n", i)
	}

	// For each block, we have two options we can pick to get the same output digest. This allows us to make
	// manyfold more messages that all produce the same _final_ digest.
	setA, setB := make([][]byte, len(weakCollisionPool)), make([][]byte, len(weakCollisionPool))
	for i, pair := range weakCollisionPool {
		setA[i] = pair[0]
		setB[i] = pair[1]
	}

	collidingMessages := cryptocrack.CombinationsFromSets(setA, setB)

	// Now we can make our colliding messages with h1, there is a decent chance two of those messages will also
	// collide when passed into h2!
	strongHashByteLen := 4
	strongHashPool := make(map[string]string)

	for _, col := range collidingMessages {
		strongHash := string(iterativeHashFn(col, initialH, strongHashByteLen))
		if _, ok := strongHashPool[strongHash]; ok {
			fmt.Printf("Challenge 52: Collision within iterative hash func found sublinearly!\n")
		}
		strongHashPool[strongHash] = string(col)
	}
}
