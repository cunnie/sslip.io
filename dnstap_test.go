package main

import (
	"encoding/binary"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("ResponseHasAorAAAA", func() {
	When("the response contains an A record answer", func() {
		It("returns true", func() {
			Expect(ResponseHasAorAAAA(dnsAResponse())).To(BeTrue())
		})
	})
	When("the response contains an AAAA record answer", func() {
		It("returns true", func() {
			Expect(ResponseHasAorAAAA(dnsAAAAResponse())).To(BeTrue())
		})
	})
	When("the response contains only NS records in the authority section", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA(dnsNSAuthorityResponse())).To(BeFalse())
		})
	})
	When("the response has an empty answer section", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA(dnsEmptyAnswerResponse())).To(BeFalse())
		})
	})
	When("given invalid DNS bytes", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA([]byte{0xff, 0x00, 0x01})).To(BeFalse())
		})
	})
	When("given empty bytes", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA([]byte{})).To(BeFalse())
		})
	})
})

var _ = Describe("encodeDnstapMsg", func() {
	It("includes the query and response bytes verbatim in the encoded message", func() {
		queryBytes := []byte{0x12, 0x34, 0x01, 0x00}
		responseBytes := dnsAResponse()
		src := net.ParseIP("192.168.1.50")
		qt := time.Unix(1700000000, 123456789)
		rt := time.Unix(1700000001, 987654321)

		encoded := encodeDnstapMsg(queryBytes, responseBytes, src, 5353, true, qt, rt)

		Expect(pbTestExtract(encoded, 10)).To(Equal(queryBytes))    // Message.query_message
		Expect(pbTestExtract(encoded, 14)).To(Equal(responseBytes)) // Message.response_message
	})

	It("sets socket_family to INET for IPv4 sources", func() {
		encoded := encodeDnstapMsg([]byte{0}, dnsAResponse(), net.ParseIP("1.2.3.4"), 53, true, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 2)).To(Equal(uint64(dtSocketFamilyINET)))
	})

	It("sets socket_family to INET6 for IPv6 sources", func() {
		encoded := encodeDnstapMsg([]byte{0}, dnsAAAAResponse(), net.ParseIP("2001:db8::1"), 53, true, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 2)).To(Equal(uint64(dtSocketFamilyINET6)))
	})

	It("sets socket_protocol to UDP when isUDP is true", func() {
		encoded := encodeDnstapMsg([]byte{0}, dnsAResponse(), net.ParseIP("1.2.3.4"), 53, true, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 3)).To(Equal(uint64(dtSocketProtocolUDP)))
	})

	It("sets socket_protocol to TCP when isUDP is false", func() {
		encoded := encodeDnstapMsg([]byte{0}, dnsAResponse(), net.ParseIP("1.2.3.4"), 53, false, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 3)).To(Equal(uint64(dtSocketProtocolTCP)))
	})
})

// --- DNS message builders ---

func dnsAResponse() []byte {
	name, _ := dnsmessage.NewName("127-0-0-1.sslip.io.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
	)
	_ = b.StartAuthorities()
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

func dnsAAAAResponse() []byte {
	name, _ := dnsmessage.NewName("fc00--.sslip.io.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AAAAResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.AAAAResource{AAAA: [16]byte{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	)
	_ = b.StartAuthorities()
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

func dnsNSAuthorityResponse() []byte {
	name, _ := dnsmessage.NewName("sslip.io.")
	nsName, _ := dnsmessage.NewName("ns.sslip.io.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.StartAuthorities()
	_ = b.NSResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.NSResource{NS: nsName},
	)
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

func dnsEmptyAnswerResponse() []byte {
	name, _ := dnsmessage.NewName("nonexistent.example.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.StartAuthorities()
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

// --- Minimal protobuf field extractor for tests ---

// pbTestExtract returns the raw bytes of the first length-delimited (wire type 2) field
// with the given field number.
func pbTestExtract(data []byte, fieldNum uint64) []byte {
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return nil
		}
		data = data[n:]
		fn, wt := tag>>3, tag&7
		switch wt {
		case 0: // varint
			_, n := binary.Uvarint(data)
			if n <= 0 {
				return nil
			}
			data = data[n:]
		case 2: // length-delimited
			length, n := binary.Uvarint(data)
			if n <= 0 {
				return nil
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return nil
			}
			if fn == fieldNum {
				result := make([]byte, length)
				copy(result, data[:length])
				return result
			}
			data = data[length:]
		case 5: // 32-bit
			if len(data) < 4 {
				return nil
			}
			data = data[4:]
		default:
			return nil
		}
	}
	return nil
}

// pbTestExtractUint returns the varint value of the first wire-type-0 field with the given number.
func pbTestExtractUint(data []byte, fieldNum uint64) uint64 {
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return 0
		}
		data = data[n:]
		fn, wt := tag>>3, tag&7
		switch wt {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return 0
			}
			if fn == fieldNum {
				return v
			}
			data = data[n:]
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 {
				return 0
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return 0
			}
			data = data[length:]
		case 5:
			if len(data) < 4 {
				return 0
			}
			data = data[4:]
		default:
			return 0
		}
	}
	return 0
}
