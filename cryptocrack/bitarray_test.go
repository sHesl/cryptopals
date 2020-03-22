package cryptocrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitArray(t *testing.T) {
	testCases := map[int][]int{
		0:    []int{},
		1:    []int{1},
		2:    []int{1, 0},
		3:    []int{1, 1},
		4:    []int{1, 0, 0},
		5:    []int{1, 0, 1},
		6:    []int{1, 1, 0},
		7:    []int{1, 1, 1},
		8:    []int{1, 0, 0, 0},
		9:    []int{1, 0, 0, 1},
		11:   []int{1, 0, 1, 1},
		15:   []int{1, 1, 1, 1},
		55:   []int{1, 1, 0, 1, 1, 1},
		123:  []int{1, 1, 1, 1, 0, 1, 1},
		554:  []int{1, 0, 0, 0, 1, 0, 1, 0, 1, 0},
		2099: []int{1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1},
	}

	for i, exp := range testCases {
		assert.EqualValues(t, exp, BitArray(i))
	}
}
