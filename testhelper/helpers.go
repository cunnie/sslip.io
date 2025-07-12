package testhelper

import (
	"encoding/binary"
	"math/rand"
	"net"
)

// RandomIPv6Address is used for fuzz testing
func RandomIPv6Address() net.IP {
	upperHalf := make([]byte, 8)
	lowerHalf := make([]byte, 8)
	binary.LittleEndian.PutUint64(upperHalf, rand.Uint64())
	binary.LittleEndian.PutUint64(lowerHalf, rand.Uint64())
	ipv6 := net.IP(append(upperHalf, lowerHalf...))
	// IPv6 addrs have a lot of all-zero two-byte sections
	// So we zero-out ~50% of the sections
	for i := 0; i < 8; i++ {
		if rand.Int()%2 == 0 {
			for j := 0; j < 2; j++ {
				ipv6[i*2+j] = 0
			}
		}
	}
	// avoid pathological case: an IPv4 address []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ?, ?, ?, ?})
	ipv6[10] &= 0xfe
	return ipv6
}

// Random8ByteString() returns an 8-char mixed-case string consisting solely of the letters a-z.
// the first & last characters are non-hexadecimal to avoid confusion with hexadecimal notation
func Random8ByteString() string {
	var randomString []byte
	// 71 == ascii 'G', +32 (103) == ascii 'g'
	randomString = append(randomString, byte(71+32*rand.Intn(2)+rand.Intn(20)))
	for range 6 {
		// 65 == ascii 'A', +32 (96) == ascii 'a', there are 26 letters in the alphabet. Mix upper case, too.
		randomString = append(randomString, byte(65+32*rand.Intn(2)+rand.Intn(26)))
	}
	randomString = append(randomString, byte(71+32*rand.Intn(2)+rand.Intn(20)))
	return string(randomString)
}
