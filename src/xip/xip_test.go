package xip_test

import (
	"errors"
	"github.com/cunnie/sslip.io/src/xip"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
	"math/rand"
)

var _ = Describe("Xip", func() {
	var (
		err            error
		name           = "127.0.0.1.sslip.io."
		nameData       [255]byte
		packedQuery    []byte
		packedResponse []byte
		response       dnsmessage.Message
		headerId       uint16
		query          = dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               headerId,
				RecursionDesired: true,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.Name{Length: uint8(len(name)), Data: nameData},
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
			Answers:     nil,
			Authorities: nil,
			Additionals: nil,
		}
		expectedResponse = dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 1636,
				Response:           true,
				OpCode:             0,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   true,
				RecursionAvailable: false,
			},
			Answers: []dnsmessage.Resource{},
			//Answers: []dnsmessage.Resource{
			//	{
			//		Header: dnsmessage.ResourceHeader{
			//			Name: dnsmessage.Name{
			//				Data:   [255]byte{97, 98, 99, 46},
			//				Length: 4,
			//			},
			//		},
			//		Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			//	},
			//},
			Authorities: []dnsmessage.Resource{},
			Additionals: []dnsmessage.Resource{},
		}
	)
	Describe("QueryResponse()", func() {
		BeforeEach(func() {
			headerId = uint16(rand.Int31())
		})
		JustBeforeEach(func() {
			// Initializing query.Questions _should_ be above, in the `var` section, but there's
			// no readable way to initialize Data ([255]byte); `copy()`, however, is readable
			copy(nameData[:], name)
			query.Questions[0].Name = dnsmessage.Name{Length: uint8(len(name)), Data: nameData}
			query.ID = headerId
			expectedResponse.ID = headerId
			expectedResponse.Questions = query.Questions
			//expectedResponse.Answers[0].Header.Name = query.Questions[0].Name
			//expectedResponse.Answers[0].Header.Type = query.Questions[0].Type
			//expectedResponse.Answers[0].Header.Class = query.Questions[0].Class
			//
			packedQuery, err = query.Pack()
			Expect(err).To(Not(HaveOccurred()))
			packedResponse, err = xip.QueryResponse(packedQuery)
			Expect(err).To(Not(HaveOccurred()))
			err = response.Unpack(packedResponse)
			Expect(err).To(Not(HaveOccurred()))
		})
		When("It cannot Unpack() the query", func() {
			It("returns an error", func() {
				_, err = xip.QueryResponse([]byte{})
				// I suspect the following may be brittle, and I would have been
				// better off with Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("unpacking header: id: insufficient data for base length type"))
			})
		})
		It("should return the correct expectedResponse", func() {
			Expect(err).To(Not(HaveOccurred()))
			Expect(response).To(Equal(expectedResponse))
		})
	})

	Describe("responseHeader()", func() {
		It("returns a header with the ID", func() {
			query.ID = uint16(rand.Int31())
			Expect(xip.ResponseHeader(query)).To(Equal(dnsmessage.Header{
				ID:                 query.ID,
				Response:           true,
				OpCode:             0,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   query.RecursionDesired,
				RecursionAvailable: false,
				RCode:              0,
			}))
		})
	})

	Describe("NameToA()", func() {
		DescribeTable("when it succeeds",
			func(fqdn string, expectedA dnsmessage.AResource) {
				ipv4Answer, err := xip.NameToA(fqdn)
				Expect(err).To(Not(HaveOccurred()))
				Expect(ipv4Answer).To(Equal(expectedA))
			},
			// dots
			Entry("loopback", "127.0.0.1", dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
			Entry("255 with domain", "255.254.253.252.com", dnsmessage.AResource{A: [4]byte{255, 254, 253, 252}}),
			Entry(`"This" network, pre-and-post`, "nono.io.0.1.2.3.sslip.io", dnsmessage.AResource{A: [4]byte{0, 1, 2, 3}}),
			Entry("private network, two IPs, grabs the leftmost", "nono.io.172.16.0.30.172.31.255.255.sslip.io", dnsmessage.AResource{A: [4]byte{172, 16, 0, 30}}),
			// dashes
			Entry("shared address with dashes", "100-64-1-2", dnsmessage.AResource{A: [4]byte{100, 64, 1, 2}}),
			Entry("link-local with domain", "169-254-168-253-com", dnsmessage.AResource{A: [4]byte{169, 254, 168, 253}}),
			Entry("IETF protocol assignments with domain and www", "www-192-0-0-1-com", dnsmessage.AResource{A: [4]byte{192, 0, 0, 1}}),
			// dots-and-dashes, mix-and-matches
			Entry("test-net address with dots-and-dashes", "www-192.0-2.3.example-me.com", dnsmessage.AResource{A: [4]byte{192, 0, 2, 3}}),
		)
		DescribeTable("when it does not match an IP address",
			func(fqdn string) {
				_, err := xip.NameToA(fqdn)
				Expect(err).To(MatchError(errors.New("ENOTFOUND")))
			},
			Entry("empty string", ""),
			Entry("bare domain", "nono.io"),
			Entry("canonical domain", "sslip.io"),
			Entry("www", "www.sslip.io"),
			Entry("a lone number", "538.sslip.io"),
			Entry("too big", "256.254.253.252"),
		)
	})

	Describe("NameToAAAA()", func() {
		DescribeTable("when it succeeds",
			func(fqdn string, expectedAAAA dnsmessage.AAAAResource) {
				ipv6Answer, err := xip.NameToAAAA(fqdn)
				Expect(err).To(Not(HaveOccurred()))
				Expect(ipv6Answer).To(Equal(expectedAAAA))
			},
			// dashes only
			Entry("loopback", "--1", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("ff with domain", "fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("ff with domain and pre", "www.fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("ff with domain dashes", "1.www-fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0-1.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
		)
		DescribeTable("when it does not match an IP address",
			func(fqdn string) {
				_, err := xip.NameToAAAA(fqdn)
				//ipv4Answer, err := xip.NameToA(fqdn)
				Expect(err).To(MatchError(errors.New("ENOTFOUND")))
				//Expect(ipv4Answer).To(Equal(dnsmessage.AAAAResource{})) // is this important to test?
			},
			Entry("empty string", ""),
			Entry("bare domain", "nono.io"),
			Entry("canonical domain", "sslip.io"),
			Entry("www", "www.sslip.io"),
			Entry("a 1 without double-dash", "-1"),
			Entry("too big", "--g"),
		)
	})
})
