package set3

const (
	w = 64  // 64 bits
	n = 312 // call twist() every 312 numbers

	// To seed...
	f = 6364136223846793005

	// To twist...
	m               = 156 // middle point (n/2)
	highMask uint64 = 0xffffffff80000000
	lowMask  uint64 = 0x000000007fffffff
	a        uint64 = 0xB5026F5AA96619E9

	// To generate
	u, d = uint64(29), 0x5555555555555555
	s, b = uint64(17), 0x71D67FFFEDA60000
	t, c = uint64(37), 0xFFF7EEE000000000
	l    = uint64(43)
)

type MersenneTwister struct {
	state [n]uint64
	i     int
}

func NewMersenneTwister(seed int) *MersenneTwister {
	mt := MersenneTwister{i: n, state: [312]uint64{}}
	mt.state[0] = uint64(seed)

	for i := 1; i < n; i++ {
		mt.state[i] = f*(mt.state[i-1]^(mt.state[i-1]>>(w-2))) + uint64(i)
	}

	return &mt
}

func (mt *MersenneTwister) Rand() uint64 {
	if mt.i == n {
		mt.twist()
	}

	result := mt.state[mt.i]
	result ^= (result >> u) & d
	result ^= (result << s) & b
	result ^= (result << t) & c
	result ^= (result >> l)
	mt.i++

	return result
}

// twist continues the series for this seed, providing the next n values to generate against
func (mt *MersenneTwister) twist() {
	for i := 0; i < n-1; i++ {
		x := (mt.state[i] & highMask) + (mt.state[(i+1)%n] & lowMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA ^= a
		}
		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}

	mt.i = 0
}
