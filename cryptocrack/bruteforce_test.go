package cryptocrack

import (
	"math"
	"sync"
	"testing"
)

func TestBruteForce(t *testing.T) {
	charset := []byte("abcd")
	l := 10

	var mut sync.Mutex
	i := float64(0)
	matchFn := func(b []byte) bool {
		if b != nil {
			mut.Lock()
			i++
			mut.Unlock()
		}
		return false
	}

	for range BruteForce(charset, l, matchFn, -1) {
	}

	n := float64(len(charset))
	r := float64(l)

	exp := math.Pow(n, r) // n^r

	if i != exp {
		t.Fatalf("wrong. exp %f, got %f", exp, float64(i))
	}
}

func BenchmarkBruteForce(b *testing.B) {
	charset := []byte("abcdefghi")
	matchFn := func(b []byte) bool { return false }

	for i := 0; i < b.N; i++ {
		for range BruteForce(charset, 10, matchFn, -1) {
		}
	}
}
