package cryptocrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCombinations(t *testing.T) {
	setA, setB := make([][]byte, 5), make([][]byte, 5)

	setA[0] = []byte("a")
	setA[1] = []byte("b")
	setA[2] = []byte("c")
	setA[3] = []byte("d")
	setA[4] = []byte("e")

	setB[0] = []byte("1")
	setB[1] = []byte("2")
	setB[2] = []byte("3")
	setB[3] = []byte("4")
	setB[4] = []byte("5")

	result := CombinationsFromSets(setA, setB)

	seen := make(map[string]string)
	for _, r := range result {
		if _, seenBefore := seen[string(r)]; seenBefore {
			t.Fatalf("should be no duplicates")
		}
		seen[string(r)] = "x"
	}

	assert.Len(t, seen, 25)
}
