package xip_test

import (
	"errors"
	"github.com/cunnie/sslip.io/src/xip"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("Xip", func() {
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
