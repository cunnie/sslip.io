package xip_test

import (
	"math/rand"

	"github.com/cunnie/sslip.io/src/xip"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("Xip", func() {
	var (
		err              error
		queryBuilder     dnsmessage.Builder
		name             string
		nameArray        [255]byte
		packedQuery      []byte
		packedResponse   []byte
		response         dnsmessage.Message
		expectedResponse dnsmessage.Message
		headerId         uint16
		question         dnsmessage.Question
	)
	Describe("QueryResponse()", func() {
		BeforeEach(func() {
			name = "127.0.0.1.sslip.io."
			copy(nameArray[:], name)
			// Set the query's header ID
			headerId = uint16(rand.Int31())
			question = dnsmessage.Question{
				Name:  dnsmessage.Name{Length: uint8(len(name)), Data: nameArray},
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}
			expectedResponse = dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 headerId,
					Response:           true,
					OpCode:             0,
					Authoritative:      true,
					Truncated:          false,
					RecursionDesired:   true,
					RecursionAvailable: false,
				},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:   question.Name,
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							TTL:    604800,
							Length: 4,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					},
				},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			}
		})
		JustBeforeEach(func() {
			// Warning: this JustBeforeEach is way too long; I know.
			// Initializing query.Questions _should_ be above, in the `var` section, but there's
			// no readable way to initialize Data ([255]byte); `copy()`, however, is readable

			// Set up the DNS query
			queryBuilder = dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID:                 headerId,
				Response:           false,
				OpCode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   true,
				RecursionAvailable: false,
				RCode:              0,
			})
			queryBuilder.EnableCompression()
			question := dnsmessage.Question{
				Name: dnsmessage.Name{
					Data:   nameArray,
					Length: uint8(len(name)),
				},
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}
			err = queryBuilder.StartQuestions()
			Expect(err).ToNot(HaveOccurred())
			err = queryBuilder.Question(question)
			Expect(err).ToNot(HaveOccurred())
			packedQuery, err = queryBuilder.Finish()
			Expect(err).ToNot(HaveOccurred())

			var deleteMe dnsmessage.Message
			err = deleteMe.Unpack(packedQuery)

			// Put the finishing touches on the expected response
			expectedResponse.ID = headerId
			expectedResponse.Questions = append(expectedResponse.Questions, question)
			expectedResponse.Answers[0].Header.Name = question.Name

			// The heart of the code: call QueryResponse()
			packedResponse, err = xip.QueryResponse(packedQuery)
			Expect(err).ToNot(HaveOccurred())
			err = response.Unpack(packedResponse)
			Expect(err).ToNot(HaveOccurred())
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
			Expect(err).ToNot(HaveOccurred())
			// break the sections out to make debugging easier
			Expect(response.Header).To(Equal(expectedResponse.Header))
			Expect(response.Questions).To(Equal(expectedResponse.Questions))
			Expect(response.Answers).To(Equal(expectedResponse.Answers))
			Expect(response.Authorities).To(Equal(expectedResponse.Authorities))
			Expect(response.Additionals).To(Equal(expectedResponse.Additionals))
			// and now the whole enchilada
			Expect(response).To(Equal(expectedResponse))
		})
		When("an A record cannot be found", func() {
			BeforeEach(func() {
				name = "not-an-ip.sslip.io."
				copy(nameArray[:], name)
				expectedSOA := xip.SOAResource(name)
				expectedAuthority := dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name: dnsmessage.Name{
							Data:   nameArray,
							Length: uint8(len(name)),
						},
						Type:   dnsmessage.TypeSOA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800,
						Length: 45,
					},
					Body: &expectedSOA,
				}
				expectedResponse.Authorities = append(expectedResponse.Authorities, expectedAuthority)
			})
			It("returns the no answers, but returns an authoritative section", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(response.Answers).To(Equal([]dnsmessage.Resource{}))
				// break test down for easier debugging
				Expect(len(response.Answers)).To(Equal(0))
				Expect(len(response.Authorities)).To(Equal(1))
				Expect(response.Authorities[0].Header.Name).To(Equal(expectedResponse.Authorities[0].Header.Name))
				Expect(response.Authorities[0].Header).To(Equal(expectedResponse.Authorities[0].Header))
				Expect(response.Authorities[0].Body).To(Equal(expectedResponse.Authorities[0].Body))
				Expect(response.Authorities[0]).To(Equal(expectedResponse.Authorities[0]))
			})
		})
	})

	Describe("ResponseHeader()", func() {
		It("returns a header with the ID", func() {
			headerId = uint16(rand.Int31())
			Expect(xip.ResponseHeader(dnsmessage.Header{
				ID:                 headerId,
				Response:           false,
				OpCode:             0,
				Authoritative:      false,
				Truncated:          false,
				RecursionDesired:   false,
				RecursionAvailable: false,
				RCode:              0,
			})).To(Equal(dnsmessage.Header{
				ID:                 headerId, // taken from the query
				Response:           true,
				OpCode:             0,
				Authoritative:      true,
				Truncated:          false,
				RecursionDesired:   false, // taken from the query
				RecursionAvailable: false,
				RCode:              0,
			}))
		})
	})

	Describe("NameToA()", func() {
		DescribeTable("when it succeeds",
			func(fqdn string, expectedA dnsmessage.AResource) {
				ipv4Answer, err := xip.NameToA(fqdn)
				Expect(err).ToNot(HaveOccurred())
				Expect(*ipv4Answer).To(Equal(expectedA))
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
				Expect(err).To(MatchError("record not found"))
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
				Expect(err).ToNot(HaveOccurred())
				Expect(*ipv6Answer).To(Equal(expectedAAAA))
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
				Expect(err).To(MatchError("record not found"))
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
