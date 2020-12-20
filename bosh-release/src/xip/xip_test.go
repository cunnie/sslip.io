package xip_test

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"xip/xip"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("Xip", func() {
	var (
		err              error
		queryBuilder     dnsmessage.Builder
		queryType        dnsmessage.Type
		name             string
		nameArray        [255]byte
		packedQuery      []byte
		packedResponse   []byte
		logMessage       string
		response         dnsmessage.Message
		expectedResponse dnsmessage.Message
		headerId         uint16
		question         dnsmessage.Question
	)
	rand.Seed(GinkgoRandomSeed()) // Set to ginkgo's seed so that it's different each test & we can reproduce failures if necessary

	Describe("QueryResponse()", func() {
		BeforeEach(func() {
			headerId = uint16(rand.Int31())

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
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			}
		})
		JustBeforeEach(func() {
			// This JustBeforeEach is way too long; I know.

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
			question = dnsmessage.Question{
				Name: dnsmessage.Name{
					Data:   nameArray,
					Length: uint8(len(name)),
				},
				Type:  queryType,
				Class: dnsmessage.ClassINET,
			}
			err = queryBuilder.StartQuestions()
			Expect(err).ToNot(HaveOccurred())
			err = queryBuilder.Question(question)
			Expect(err).ToNot(HaveOccurred())
			packedQuery, err = queryBuilder.Finish()
			Expect(err).ToNot(HaveOccurred())

			// Do preliminary setup of the expected response
			expectedResponse.ID = headerId
			expectedResponse.Questions = append(expectedResponse.Questions, question)

			// The heart of the code: call QueryResponse()
			packedResponse, logMessage, err = xip.QueryResponse(packedQuery)
			Expect(err).ToNot(HaveOccurred())
			err = response.Unpack(packedResponse)
			Expect(err).ToNot(HaveOccurred())
		})
		When("it cannot Unpack() the query", func() {
			BeforeEach(func() {
				// This BeforeEach() serves no purpose other than preventing the JustBeforeEach() from complaining
				name = "this-name-does-not-matter."
				nameArray = [255]byte{} // zero-out the array otherwise tests will fail with leftovers from longer "name"s
				copy(nameArray[:], name)
				queryType = dnsmessage.TypeA
			})
			It("returns an error", func() {
				_, logMessage, err = xip.QueryResponse([]byte{})
				// I suspect the following may be brittle, and I would have been
				// better off with Expect(err).To(HaveOccurred())
				Expect(logMessage).To(Equal(""))
				Expect(err).To(MatchError("unpacking header: id: insufficient data for base length type"))
			})
		})
		When("the A record can be found", func() {
			BeforeEach(func() {
				name = "127.0.0.1.sslip.io."
				nameArray = [255]byte{} // zero-out the array otherwise tests will fail with leftovers from longer "name"s
				copy(nameArray[:], name)
				queryType = dnsmessage.TypeA

				expectedResponse.Answers = append(expectedResponse.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name: dnsmessage.Name{
							Data:   nameArray,
							Length: uint8(len(name)),
						},
						Type:   queryType,
						Class:  dnsmessage.ClassINET,
						TTL:    604800,
						Length: 4,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
				})
			})
			It("should return the correct expectedResponse", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(logMessage).To(Equal("TypeA 127.0.0.1.sslip.io. ? 127.0.0.1"))
				// break the sections out to make debugging easier
				Expect(response.Header).To(Equal(expectedResponse.Header))
				Expect(response.Questions).To(Equal(expectedResponse.Questions))
				Expect(response.Answers).To(Equal(expectedResponse.Answers))
				Expect(response.Authorities).To(Equal(expectedResponse.Authorities))
				Expect(response.Additionals).To(Equal(expectedResponse.Additionals))
				// and now the whole enchilada
				Expect(response).To(Equal(expectedResponse))
			})
		})
		When("the AAAA record can be found", func() {
			BeforeEach(func() {
				name = "--1.sslip.io."
				nameArray = [255]byte{} // zero-out the array otherwise tests will fail with leftovers from longer "name"s
				copy(nameArray[:], name)
				queryType = dnsmessage.TypeAAAA

				expectedResponse.Answers = append(expectedResponse.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name: dnsmessage.Name{
							Data:   nameArray,
							Length: uint8(len(name)),
						},
						Type:   queryType,
						Class:  dnsmessage.ClassINET,
						TTL:    604800,
						Length: 16,
					},
					Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
				})
			})
			It("should return the correct expectedResponse", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(logMessage).To(Equal("TypeAAAA --1.sslip.io. ? ::1"))
				// break the sections out to make debugging easier
				Expect(response.Header).To(Equal(expectedResponse.Header))
				Expect(response.Questions).To(Equal(expectedResponse.Questions))
				Expect(response.Answers).To(Equal(expectedResponse.Answers))
				Expect(response.Authorities).To(Equal(expectedResponse.Authorities))
				Expect(response.Additionals).To(Equal(expectedResponse.Additionals))
				// and now the whole enchilada
				Expect(response).To(Equal(expectedResponse))
			})
		})
		When("an A or an AAAA record cannot be found", func() {
			BeforeEach(func() {
				name = "not-an-ip.sslip.io."
				nameArray = [255]byte{} // zero-out the array otherwise tests will fail with leftovers from longer "name"s
				copy(nameArray[:], name)
				queryType = dnsmessage.TypeA

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
			It("returns no answers, but returns an authoritative section", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(logMessage).To(Equal("TypeA not-an-ip.sslip.io. ? nil, SOA"))
				Expect(len(response.Questions)).To(Equal(1))
				Expect(response.Questions[0]).To(Equal(question))
				// break test down for easier debugging
				Expect(len(response.Answers)).To(Equal(0))
				Expect(len(response.Authorities)).To(Equal(1))
				Expect(response.Authorities[0].Header.Name).To(Equal(expectedResponse.Authorities[0].Header.Name))
				Expect(response.Authorities[0].Header).To(Equal(expectedResponse.Authorities[0].Header))
				Expect(response.Authorities[0].Body).To(Equal(expectedResponse.Authorities[0].Body))
				Expect(response.Authorities[0]).To(Equal(expectedResponse.Authorities[0]))
				// I've made a decision to not populate the Additionals section because it's too much work
				// (And I don't think it's necessary)
				Expect(len(response.Additionals)).To(Equal(0))
			})
		})
		When("an ANY record is requested", func() {
			BeforeEach(func() {
				queryType = dnsmessage.TypeALL
			})
			It("responds that it's not implemented because it should be deprecated (RFC 8482)", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(response.RCode).To(Equal(dnsmessage.RCodeNotImplemented))
				Expect(len(response.Answers)).To(Equal(0))
				Expect(len(response.Authorities)).To(Equal(0))
				Expect(len(response.Additionals)).To(Equal(0))
			})
		})
		When("a record is requested but there's no record to return (e.g. SRV, HINFO)", func() {
			BeforeEach(func() {
				name = "no-srv-record.sslip.io."
				nameArray = [255]byte{} // zero-out the array otherwise tests will fail with leftovers from longer "name"s
				copy(nameArray[:], name)
				queryType = dnsmessage.TypeSRV

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
			It("responds with no answers but with an authority", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(logMessage).To(Equal("TypeSRV no-srv-record.sslip.io. ? nil, SOA"))
				Expect(len(response.Questions)).To(Equal(1))
				Expect(response.Questions[0]).To(Equal(question))
				// break test down for easier debugging
				Expect(len(response.Answers)).To(Equal(0))
				Expect(len(response.Authorities)).To(Equal(1))
				Expect(response.Authorities[0].Header.Name).To(Equal(expectedResponse.Authorities[0].Header.Name))
				Expect(response.Authorities[0].Header).To(Equal(expectedResponse.Authorities[0].Header))
				Expect(response.Authorities[0].Body).To(Equal(expectedResponse.Authorities[0].Body))
				Expect(response.Authorities[0]).To(Equal(expectedResponse.Authorities[0]))
				// I've made a decision to not populate the Additionals section because it's too much work
				// (And I don't think it's necessary)
				Expect(len(response.Additionals)).To(Equal(0))
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
			}, dnsmessage.RCodeSuccess)).To(Equal(dnsmessage.Header{
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
		It("returns the header with the passed-in RCode", func() {
			Expect(xip.ResponseHeader(dnsmessage.Header{}, dnsmessage.RCodeNotImplemented).
				RCode).To(Equal(dnsmessage.RCodeNotImplemented))
		})
	})
	Describe("CNAMEResources()", func() {
		It("returns no CNAME resources", func() {
			randomDomain := random8ByteString() + ".com."
			_, err := xip.CNAMEResource(randomDomain)
			Expect(err).To(HaveOccurred())
		})
		When("querying one of sslip.io's DKIM CNAME's", func() {
			It("returns the CNAME", func() {
				cname, err := xip.CNAMEResource("protonmail._domainkey.sslip.io.")
				Expect(err).To(Not(HaveOccurred()))
				Expect(cname.CNAME.String()).To(MatchRegexp("^protonmail\\.domainkey.*.domains\\.proton\\.ch\\.$"))
			})
		})
		When("a domain has been customized but has no CNAMEs", func() {
			It("returns an error", func() {
				customizedDomain := random8ByteString() + ".com."
				xip.Customizations[customizedDomain] = xip.DomainCustomization{}
				cname, err := xip.CNAMEResource(customizedDomain)
				Expect(cname).To(BeNil())
				Expect(err).To(HaveOccurred())
				delete(xip.Customizations, customizedDomain)
			})
		})
		When("a domain has been customized with CNAMES", func() {
			It("returns CNAME resources", func() {
				customizedDomain := random8ByteString() + ".com."
				xip.Customizations[customizedDomain] = xip.DomainCustomization{
					CNAME: dnsmessage.CNAMEResource{
						CNAME: dnsmessage.Name{
							// google.com.
							Length: 11,
							Data: [255]byte{
								103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 46,
							},
						},
					},
				}
				cname, err := xip.CNAMEResource(customizedDomain)
				Expect(err).ToNot(HaveOccurred())
				Expect(cname.CNAME.String()).To(Equal("google.com."))
				delete(xip.Customizations, customizedDomain) // clean-up
			})
		})
	})

	Describe("MxResources()", func() {
		It("returns the MX resource", func() {
			randomDomain := random8ByteString() + ".com."
			mx := xip.MxResources(randomDomain)
			var mxHostBytes [255]byte
			copy(mxHostBytes[:], randomDomain)
			Expect(len(mx)).To(Equal(1))
			Expect(mx[0].MX.Length).To(Equal(uint8(13))) // randomDomain has 13 letters
			Expect(mx[0].MX.Data).To(Equal(mxHostBytes))
		})
		When("sslip.io is the domain being queried", func() {
			It("returns sslip.io's custom MX records", func() {
				mx := xip.MxResources("sslip.io.")
				Expect(len(mx)).To(Equal(2))
				Expect(mx[0].MX.Data).To(Equal(xip.Customizations["sslip.io."].MX[0].MX.Data))
			})
		})
	})

	Describe("NSResources()", func() {
		It("returns a map of the name servers", func() {
			randomDomain := random8ByteString() + ".com."
			ns := xip.NSResources(randomDomain)
			for _, nameServer := range xip.NameServers {
				var nameServerBytes [255]byte
				copy(nameServerBytes[:], nameServer)
				Expect(ns[nameServer].NS.Data).To(Equal(nameServerBytes))
			}
		})
	})

	Describe("SOAResource()", func() {
		It("returns the SOA resource for the domain in question", func() {
			randomDomain := random8ByteString() + ".com."
			soa := xip.SOAResource(randomDomain)
			var domainBytes [255]byte
			copy(domainBytes[:], randomDomain)
			Expect(soa.NS.Data).To(Equal(domainBytes))
		})
	})

	Describe("TXTResources()", func() {
		It("returns no TXT resources", func() {
			randomDomain := random8ByteString() + ".com."
			_, err := xip.TXTResources(randomDomain)
			Expect(err).To(HaveOccurred())
		})
		When("queried for the sslip.io domain", func() {
			It("returns mail-related TXT resources for the sslip.io domain", func() {
				domain := "sslip.io."
				txt, err := xip.TXTResources(domain)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txt)).To(Equal(2))
				Expect(txt[0].TXT[0]).To(MatchRegexp("protonmail-verification="))
				Expect(txt[1].TXT[0]).To(MatchRegexp("v=spf1"))
			})
		})
		When("a domain has been customized", func() { // Unnecessary, but confirms Golang's behavior for me, a doubting Thomas
			customizedDomain := random8ByteString() + ".com."
			xip.Customizations[customizedDomain] = xip.DomainCustomization{}
			It("returns no TXT resources", func() {
				_, err := xip.TXTResources(customizedDomain)
				Expect(err).To(HaveOccurred())
			})
			delete(xip.Customizations, customizedDomain) // clean-up
		})
	})

	Describe("NameToA()", func() {
		DescribeTable("when it succeeds",
			func(fqdn string, expectedA dnsmessage.AResource) {
				ipv4Answers, err := xip.NameToA(fqdn)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ipv4Answers)).To(Equal(1))
				Expect(ipv4Answers[0]).To(Equal(expectedA))
			},
			// sslip.io website
			Entry("sslip.io", "sslip.io.", dnsmessage.AResource{A: [4]byte{78, 46, 204, 247}}),
			// nameservers
			Entry("ns-aws", "ns-aws.nono.io.", dnsmessage.AResource{A: [4]byte{52, 0, 56, 137}}),
			Entry("ns-azure", "ns-azure.nono.io.", dnsmessage.AResource{A: [4]byte{52, 187, 42, 158}}),
			Entry("ns-gce", "ns-gce.nono.io.", dnsmessage.AResource{A: [4]byte{104, 155, 144, 4}}),
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
			Entry("Pandaxin's paradox", "minio-01.192-168-1-100.sslip.io", dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}}),
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
			Entry("NS but no dot", "ns-aws.nono.io"),
			Entry("NS + cruft at beginning", "p-ns-aws.nono.io"),
			Entry("test-net address with dots-and-dashes mixed", "www-192.0-2.3.example-me.com"),
		)
		When("There is more than one A record", func() {
			It("returns them all", func() {
				fqdn := random8ByteString()
				xip.Customizations[fqdn] = xip.DomainCustomization{
					A: []dnsmessage.AResource{
						{A: [4]byte{1}},
						{A: [4]byte{2}},
					},
				}
				ipv4Addrs, err := xip.NameToA(fqdn)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ipv4Addrs)).To(Equal(2))
				Expect(ipv4Addrs[0].A).To(Equal([4]byte{1}))
				Expect(ipv4Addrs[1].A).To(Equal([4]byte{2}))
				delete(xip.Customizations, fqdn)
			})
		})
		When("There are multiple matches", func() {
			It("returns the leftmost one", func() {
				aResource, err := xip.NameToA("nono.io.127.0.0.1.192.168.0.1.sslip.io")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(aResource)).To(Equal(1))
				Expect(aResource[0]).
					To(Equal(dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}))
			})
		})
		When("There are matches with dashes and dots", func() {
			It("returns the one with dashes", func() {
				aResource, err := xip.NameToA("nono.io.127.0.0.1.192-168-0-1.sslip.io")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(aResource)).To(Equal(1))
				Expect(aResource[0]).
					To(Equal(dnsmessage.AResource{A: [4]byte{192, 168, 0, 1}}))
			})
		})
	})

	Describe("NameToAAAA()", func() {
		DescribeTable("when it succeeds",
			func(fqdn string, expectedAAAA dnsmessage.AAAAResource) {
				ipv6Answers, err := xip.NameToAAAA(fqdn)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ipv6Answers)).To(Equal(1))
				Expect(ipv6Answers[0]).To(Equal(expectedAAAA))
			},
			// sslip.io website
			Entry("sslip.io", "sslip.io.", xip.Customizations["sslip.io."].AAAA[0]),
			// dashes only
			Entry("loopback", "--1", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("ff with domain", "fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("ff with domain and pre", "www.fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("ff with domain dashes", "1.www-fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0-1.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("Browsing the logs", "2006-41d0-2-e01e--56dB-3598.sSLIP.io.", dnsmessage.AAAAResource{AAAA: [16]byte{32, 6, 65, 208, 0, 2, 224, 30, 0, 0, 0, 0, 86, 219, 53, 152}}),
			Entry("Browsing the logs", "1-2-3--4-5-6.sSLIP.io.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 1, 0, 2, 0, 3, 0, 0, 0, 0, 0, 4, 0, 5, 0, 6}}),
			Entry("Browsing the logs", "1--2-3-4-5-6.sSLIP.io.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 1, 0, 0, 0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6}}),
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
		When("using randomly generated IPv6 addresses (fuzz testing)", func() {
			It("should succeed every time", func() {
				for i := 0; i < 10000; i++ {
					addr := randomIPv6Address()
					ipv6Answers, err := xip.NameToAAAA(strings.ReplaceAll(addr.String(), ":", "-"))
					Expect(err).ToNot(HaveOccurred())
					Expect(ipv6Answers[0].AAAA[:]).To(Equal([]uint8(addr)))
				}
			})
		})
		When("There is more than one AAAA record", func() {
			It("returns them all", func() {
				fqdn := random8ByteString()
				xip.Customizations[fqdn] = xip.DomainCustomization{
					AAAA: []dnsmessage.AAAAResource{
						{AAAA: [16]byte{1}},
						{AAAA: [16]byte{2}},
					},
				}
				ipv6Addrs, err := xip.NameToAAAA(fqdn)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ipv6Addrs)).To(Equal(2))
				Expect(ipv6Addrs[0].AAAA).To(Equal([16]byte{1}))
				Expect(ipv6Addrs[1].AAAA).To(Equal([16]byte{2}))
				delete(xip.Customizations, fqdn)
			})
		})
	})
})

func randomIPv6Address() net.IP {
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
	return ipv6
}

// random8ByteString() returns an 8-char string consisting solely of the letters a-z.
func random8ByteString() string {
	var randomString []byte
	for i := 0; i < 8; i++ {
		// 97 == ascii 'a', and there are 26 letters in the alphabet
		randomString = append(randomString, byte(97+rand.Intn(26)))
	}
	return string(randomString)
}
