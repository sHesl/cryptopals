package set1

var hammingTable = [256]byte{
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
}

func hammingBytes(a, b []byte) int {
	aIsLongest := len(a) > len(b)
	var longest []byte
	var shortest []byte

	if aIsLongest {
		longest = a
		shortest = b
	} else {
		shortest = a
		longest = b
	}

	hamming := 0
	for i, lr := range longest {
		hamming += int(hammingTable[lr^shortest[i]])
	}

	return hamming
}

// hammingBlock uses the hamming distance to attempt to formulate the block length of a given input,
// sampling blocks of different lengths and calculating the hamming distance for said block. The most likely
// block length is the length for which the sampled blocks have the shortest average hamming distance.
func hammingBlock(b []byte, sampleRate int) int {
	mostProbableKeyLen := -1
	smallestDistance := float32(-1)

	for keyLen := 2; keyLen < 40; keyLen++ {
		sum := float32(0)
		for sampleCount := 0; sampleCount < sampleRate; sampleCount++ {
			if len(b) < keyLen*2+(sampleCount*keyLen) {
				sampleRate = sampleCount
				break
			}

			s1 := b[keyLen*sampleCount : keyLen+(sampleCount*keyLen)]
			s2 := b[keyLen+(sampleCount*keyLen) : keyLen*2+(sampleCount*keyLen)]
			d := hammingBytes(s1, s2)
			df := float32(d) / float32(keyLen)

			sum += df
		}

		avgDistance := sum / float32(sampleRate)

		if avgDistance < smallestDistance || mostProbableKeyLen == -1 {
			smallestDistance = avgDistance
			mostProbableKeyLen = keyLen
		}
	}

	return mostProbableKeyLen
}
