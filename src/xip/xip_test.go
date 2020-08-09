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
			Entry("loopback", "127.0.0.1", dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
			Entry("loopback with domain", "127.0.0.1.com", dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
			Entry("loopback with domain and www", "www.127.0.0.1.com", dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
			Entry("pre and post", "nono.io.10.0.9.30.sslip.io", dnsmessage.AResource{A: [4]byte{10, 0, 9, 30}}),
			Entry("pre and post", "nono.io.10.0.9.30.sslip.io", dnsmessage.AResource{A: [4]byte{10, 0, 9, 30}}),
			Entry("two IPs, grabs the leftmost", "nono.io.10.0.9.30.172.16.0.30.sslip.io", dnsmessage.AResource{A: [4]byte{10, 0, 9, 30}}),
			Entry("two IPs, grabs the leftmost", "nono.io.10.0.9.30.172.16.0.30.sslip.io", dnsmessage.AResource{A: [4]byte{10, 0, 9, 30}}),
		)
		DescribeTable("when it does not match an IP address",
			func(fqdn string) {
				_, err := xip.NameToA(fqdn)
				//ipv4Answer, err := xip.NameToA(fqdn)
				Expect(err).To(MatchError(errors.New("ENOTFOUND")))
				//Expect(ipv4Answer).To(Equal(dnsmessage.AResource{})) // is this important to test?
			},
			Entry("empty string", ""),
			Entry("bare domain", "nono.io"),
			Entry("canonical domain", "sslip.io"),
			Entry("www", "www.sslip.io"),
			Entry("a lone number", "538.sslip.io"),
		)
	})
})