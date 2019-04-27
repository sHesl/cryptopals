package cryptocrack

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNthBlock(t *testing.T) {
	type testCase struct {
		b        []byte
		blockLen int
		n        int
		exp      []byte
	}

	testCases := []testCase{
		{[]byte("1stb"), 4, 1, []byte("1stb")},
		{[]byte("1st block. short block"), 32, 1, []byte("1st block. short block")},
		{[]byte("1st block. input is block len..."), 32, 1, []byte("1st block. input is block len...")},
		{[]byte("block 1. input is longer than a single block"), 8, 1, []byte("block 1.")},
		{[]byte("2nd block is longer than a block len but not 2 long"), 32, 2, []byte(" len but not 2 long")},
	}

	for i, tc := range testCases {
		testName := fmt.Sprintf("Test case: %d", i)
		t.Run(testName, func(t *testing.T) {
			result, err := NthBlock(tc.b, tc.blockLen, tc.n)

			if err != nil {
				t.Fatalf("Unexpected error %s", err.Error())
			}

			if !bytes.Equal(result, tc.exp) {
				t.Fatalf("Expected nth block to equal %s. Got %s", tc.exp, result)
			}
		})
	}
}
