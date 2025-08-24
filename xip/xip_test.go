package xip_test

import (
	"net"
	"strings"
	"xip/testhelper"
	"xip/xip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("Xip", func() {
	var (
		err error
	)
	Describe("CNAMEResources()", func() {
		It("returns nil by default", func() {
			randomDomain := testhelper.Random8ByteString() + ".com."
			cname := xip.CNAMEResource(randomDomain)
			Expect(cname).To(BeNil())
		})
		When("querying one of sslip.io's DKIM CNAMEs", func() {
			It("returns the CNAME", func() {
				cname := xip.CNAMEResource("protonmail._domainkey.SSlip.Io.")
				Expect(cname.CNAME.String()).To(MatchRegexp("^protonmail\\.domainkey.*.domains\\.proton\\.ch\\.$"))
			})
		})
		When("querying one of nip.io's DKIM CNAMEs", func() {
			It("returns the CNAME", func() {
				cname := xip.CNAMEResource("protonmail._domainkey.nIP.iO.")
				Expect(cname).ToNot(BeNil())
				Expect(cname.CNAME.String()).To(MatchRegexp("^protonmail\\.domainkey.*.domains\\.proton\\.ch\\.$"))
			})
		})
		When("a domain has been customized but has no CNAMEs", func() {
			It("returns nil", func() {
				customizedDomain := testhelper.Random8ByteString() + ".com."
				xip.Customizations[customizedDomain] = xip.DomainCustomization{}
				cname := xip.CNAMEResource(customizedDomain)
				Expect(cname).To(BeNil())
				delete(xip.Customizations, customizedDomain)
			})
		})
		When("a domain has been customized with CNAMES", func() {
			It("returns CNAME resources", func() {
				customizedDomain := testhelper.Random8ByteString() + ".com."
				xip.Customizations[strings.ToLower(customizedDomain)] = xip.DomainCustomization{
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
				cname := xip.CNAMEResource(customizedDomain)
				Expect(cname.CNAME.String()).To(Equal("google.com."))
				delete(xip.Customizations, customizedDomain) // clean-up
			})
		})
	})

	Describe("MXResources()", func() {
		It("returns the MX resource", func() {
			randomDomain := testhelper.Random8ByteString() + ".com."
			mx := xip.MXResources(randomDomain)
			mxHostName := dnsmessage.MustNewName(randomDomain)
			Expect(len(mx)).To(Equal(1))
			Expect(mx[0].MX).To(Equal(mxHostName))
		})
		When("sslip.io is the domain being queried", func() {
			It("returns sslip.io's custom MX records", func() {
				mx := xip.MXResources("sslIP.iO.")
				Expect(len(mx)).To(Equal(2))
				Expect(mx[0].MX.Data).To(Equal(xip.Customizations["sslip.io."].MX[0].MX.Data))
			})
		})
		When("nip.io is the domain being queried", func() {
			It("returns nip.io's custom MX records", func() {
				mx := xip.MXResources("nip.iO.")
				Expect(len(mx)).To(Equal(2))
				Expect(mx[0].MX.Data).To(Equal(xip.Customizations["nip.io."].MX[0].MX.Data))
			})
		})
	})

	Describe("NSResources()", func() {
		When("we use the default nameservers", func() {
			var x, _ = xip.NewXip("file:///", []string{"ns-hetzner.sslip.io.", "ns-ovh.sslip.io.", "ns-do-sg.sslip.io."}, []string{}, []string{}, "")
			It("returns the name servers", func() {
				randomDomain := testhelper.Random8ByteString() + ".com."
				ns := x.NSResources(randomDomain)
				Expect(len(ns)).To(Equal(3))
				Expect(ns[0].NS.String()).To(Equal("ns-hetzner.sslip.io."))
				Expect(ns[1].NS.String()).To(Equal("ns-ovh.sslip.io."))
				Expect(ns[2].NS.String()).To(Equal("ns-do-sg.sslip.io."))
			})
			When(`the domain name contains "_acme-challenge."`, func() {
				When("the domain name has an embedded IP", func() {
					It(`returns an array of one NS record pointing to the domain name _sans_ "acme-challenge."`, func() {
						randomDomain := "192.168.0.1." + testhelper.Random8ByteString() + ".com."
						ns := x.NSResources("_acme-challenge." + randomDomain)
						Expect(len(ns)).To(Equal(1))
						Expect(ns[0].NS.String()).To(Equal(strings.ToLower(randomDomain)))
						aResources := xip.NameToA(randomDomain, true)
						Expect(len(aResources)).To(Equal(1))
						Expect(err).ToNot(HaveOccurred())
						Expect(aResources[0].A).To(Equal([4]byte{192, 168, 0, 1}))
					})
				})
				When("the domain name does not have an embedded IP", func() {
					It("returns the default trinity of nameservers", func() {
						randomDomain := "_acme-challenge." + testhelper.Random8ByteString() + ".com."
						ns := x.NSResources(randomDomain)
						Expect(len(ns)).To(Equal(3))
					})
				})
			})
			When("we delegate domains to other nameservers", func() {
				When(`we don't use the "=" in the arguments`, func() {
					It("returns an informative log message", func() {
						var _, logs = xip.NewXip("file://etc/blocklist-test.txt", []string{"ns-hetzner.sslip.io.", "ns-ovh.sslip.io.", "ns-do-sg.sslip.io."}, []string{}, []string{"noEquals"}, "")
						Expect(strings.Join(logs, "")).To(MatchRegexp(`"-delegates: arguments should be in the format "delegatedDomain=nameserver", not "noEquals"`))
					})
				})
				When(`there's no "." at the end of the delegated domain or nameserver`, func() {
					It(`helpfully adds the "."`, func() {
						var x, logs = xip.NewXip("file://etc/blocklist-test.txt", []string{"ns-hetzner.sslip.io.", "ns-ovh.sslip.io.", "ns-do-sg.sslip.io."}, []string{}, []string{"a=b"}, "")
						Expect(strings.Join(logs, "")).To(MatchRegexp(`Adding delegated NS record "a\.=b\."`))
						ns := x.NSResources("a.")
						Expect(len(ns)).To(Equal(1))
					})
				})
			})
		})
		When("we override the default nameservers", func() {
			var x, _ = xip.NewXip("file:///", []string{"mickey", "minn.ie.", "goo.fy"}, []string{}, []string{}, "")
			It("returns the configured servers", func() {
				randomDomain := testhelper.Random8ByteString() + ".com."
				ns := x.NSResources(randomDomain)
				Expect(len(ns)).To(Equal(3))
				Expect(ns[0].NS.String()).To(Equal("mickey."))
				Expect(ns[1].NS.String()).To(Equal("minn.ie."))
				Expect(ns[2].NS.String()).To(Equal("goo.fy."))
			})

		})
	})

	Describe("SOAResource()", func() {
		It("returns the SOA resource for the domain in question", func() {
			randomDomain := testhelper.Random8ByteString() + ".com."
			randomDomainName := dnsmessage.MustNewName(randomDomain)
			soa := xip.SOAResource(randomDomainName)
			Expect(soa.NS.Data).To(Equal(randomDomainName.Data))
		})
	})

	Describe("TXTResources()", func() {
		var x xip.Xip
		It("returns an empty array for a random domain", func() {
			randomDomain := testhelper.Random8ByteString() + ".com."
			txts, err := x.TXTResources(randomDomain, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(txts)).To(Equal(0))
		})
		When("queried for the sslip.io domain", func() {
			It("returns mail-related TXT resources for the sslip.io domain", func() {
				domain := "ssLip.iO."
				txts, err := x.TXTResources(domain, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(2))
				Expect(txts[0].TXT[0]).To(MatchRegexp("protonmail-verification="))
				Expect(txts[1].TXT[0]).To(MatchRegexp("v=spf1"))
			})
		})
		When("queried for the nip.io domain", func() {
			It("returns mail-related TXT resources for the nip.io domain", func() {
				domain := "niP.iO."
				txts, err := x.TXTResources(domain, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(2))
				Expect(txts[0].TXT[0]).To(MatchRegexp("protonmail-verification="))
				Expect(txts[1].TXT[0]).To(MatchRegexp("v=spf1"))
			})
		})
		When("a random domain has been customized w/out any TXT defaults", func() { // Unnecessary, but confirms Golang's behavior for me, a doubting Thomas
			customizedDomain := testhelper.Random8ByteString() + ".com."
			xip.Customizations[customizedDomain] = xip.DomainCustomization{}
			It("returns no TXT resources", func() {
				txts, err := x.TXTResources(customizedDomain, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(0))
			})
			delete(xip.Customizations, customizedDomain) // clean-up
		})
		When(`the domain "ip.sslip.io" is queried`, func() {
			It("returns the IP address of the querier", func() {
				txts, err := x.TXTResources("ip.sslip.io.", net.IP{1, 1, 1, 1})
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(1))
				Expect(txts[0].TXT[0]).To(MatchRegexp("^1.1.1.1$"))
			})
		})
		When(`the domain "ip.nip.io" is queried`, func() {
			It("returns the IP address of the querier", func() {
				txts, err := x.TXTResources("ip.nip.io.", net.IP{1, 1, 1, 1})
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(1))
				Expect(txts[0].TXT[0]).To(MatchRegexp("^1.1.1.1$"))
			})
		})
		When(`the domain "version.status.nip.io" is queried`, func() {
			It("returns version information", func() {
				txts, err := x.TXTResources("version.status.nip.io.", nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(3))
				Expect(txts[0].TXT[0]).To(MatchRegexp(`^0\.0\.0$`))
				Expect(txts[1].TXT[0]).To(MatchRegexp(`^0001/01/01-99:99:99-0800$`))
				Expect(txts[2].TXT[0]).To(MatchRegexp(`^cafexxx$`))
			})
		})
		When(`the domain "version.status.sslip.io" is queried`, func() {
			It("returns version information", func() {
				txts, err := x.TXTResources("version.status.sslip.io.", nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(3))
				Expect(txts[0].TXT[0]).To(MatchRegexp(`^0\.0\.0$`))
				Expect(txts[1].TXT[0]).To(MatchRegexp(`^0001/01/01-99:99:99-0800$`))
				Expect(txts[2].TXT[0]).To(MatchRegexp(`^cafexxx$`))
			})
		})
		When(`the domain "metrics.status.sslip.io" is queried`, func() {
			// the simpler "var x xip.Xip" causes the metrics test to hang
			var x, _ = xip.NewXip("file:///", []string{"ns-hetzner.sslip.io.", "ns-ovh.sslip.io.", "ns-do-sg.sslip.io."}, []string{}, []string{}, "")
			It("returns metrics information", func() {
				txts, err := x.TXTResources("metrics.status.sslip.io.", nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(12))
				Expect(txts[0].TXT[0]).To(MatchRegexp(`Uptime: 0`))
				Expect(txts[1].TXT[0]).To(MatchRegexp(`Blocklist: 0001-01-01 00:00:00\+00 0,0`))
				Expect(txts[2].TXT[0]).To(MatchRegexp(`Queries: 0 \(0.0/s\)`))
				Expect(txts[3].TXT[0]).To(MatchRegexp(`TCP/UDP: 0/0`))
				Expect(txts[4].TXT[0]).To(MatchRegexp(`Answer > 0: 0 \(0.0/s\)`))
				Expect(txts[5].TXT[0]).To(MatchRegexp(`A: 0`))
				Expect(txts[6].TXT[0]).To(MatchRegexp(`AAAA: 0`))
				Expect(txts[7].TXT[0]).To(MatchRegexp(`TXT Source: 0`))
				Expect(txts[8].TXT[0]).To(MatchRegexp(`TXT Version: 0`))
				Expect(txts[9].TXT[0]).To(MatchRegexp(`PTR IPv4/IPv6: 0/0`))
				Expect(txts[10].TXT[0]).To(MatchRegexp(`NS DNS-01: 0`))
				Expect(txts[11].TXT[0]).To(MatchRegexp(`Blocked: 0`))
			})
		})
		When(`the domain "metrics.status.nip.io" is queried`, func() {
			// the simpler "var x xip.Xip" causes the metrics test to hang
			var x, _ = xip.NewXip("file:///", []string{"ns-hetzner.sslip.io.", "ns-ovh.sslip.io.", "ns-do-sg.sslip.io."}, []string{}, []string{}, "")
			It("returns metrics information", func() {
				txts, err := x.TXTResources("metrics.status.nip.io.", nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(12))
				Expect(txts[0].TXT[0]).To(MatchRegexp(`Uptime: 0`))
				Expect(txts[1].TXT[0]).To(MatchRegexp(`Blocklist: 0001-01-01 00:00:00\+00 0,0`))
				Expect(txts[2].TXT[0]).To(MatchRegexp(`Queries: 0 \(0.0/s\)`))
				Expect(txts[3].TXT[0]).To(MatchRegexp(`TCP/UDP: 0/0`))
				Expect(txts[4].TXT[0]).To(MatchRegexp(`Answer > 0: 0 \(0.0/s\)`))
				Expect(txts[5].TXT[0]).To(MatchRegexp(`A: 0`))
				Expect(txts[6].TXT[0]).To(MatchRegexp(`AAAA: 0`))
				Expect(txts[7].TXT[0]).To(MatchRegexp(`TXT Source: 0`))
				Expect(txts[8].TXT[0]).To(MatchRegexp(`TXT Version: 0`))
				Expect(txts[9].TXT[0]).To(MatchRegexp(`PTR IPv4/IPv6: 0/0`))
				Expect(txts[10].TXT[0]).To(MatchRegexp(`NS DNS-01: 0`))
				Expect(txts[11].TXT[0]).To(MatchRegexp(`Blocked: 0`))
			})
		})
		When(`a customized domain without a TXT entry is queried`, func() {
			It("returns no records (and doesn't panic, either)", func() {
				txts, err := x.TXTResources("ns.sslip.io.", nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(len(txts)).To(Equal(0))
			})
		})
	})

	Describe("NameToA()", func() {
		xip.Customizations["custom.record."] = xip.DomainCustomization{A: []dnsmessage.AResource{
			{A: [4]byte{78, 46, 204, 247}},
		}}
		DescribeTable("when it succeeds",
			func(fqdn string, expectedA dnsmessage.AResource) {
				ipv4Answers := xip.NameToA(fqdn, true)
				Expect(ipv4Answers[0]).To(Equal(expectedA))
				Expect(len(ipv4Answers)).To(Equal(1))
			},
			Entry("custom record", "CusTom.RecOrd.", dnsmessage.AResource{A: [4]byte{78, 46, 204, 247}}),
			// dots
			Entry("loopback", "127.0.0.1", dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
			Entry("255 with domain", "255.254.253.252.com", dnsmessage.AResource{A: [4]byte{255, 254, 253, 252}}),
			Entry(`"This" network, pre-and-post`, "nono.io.0.1.2.3.ssLIp.IO", dnsmessage.AResource{A: [4]byte{0, 1, 2, 3}}),
			Entry("private network, two IPs, grabs the leftmost", "nono.io.172.16.0.30.172.31.255.255.sslip.io", dnsmessage.AResource{A: [4]byte{172, 16, 0, 30}}),
			// dashes
			Entry("shared address with dashes", "100-64-1-2", dnsmessage.AResource{A: [4]byte{100, 64, 1, 2}}),
			Entry("link-local with domain", "169-254-168-253-com", dnsmessage.AResource{A: [4]byte{169, 254, 168, 253}}),
			Entry("IETF protocol assignments with domain and www", "www-192-0-0-1-com", dnsmessage.AResource{A: [4]byte{192, 0, 0, 1}}),
			// dots-and-dashes, mix-and-matches
			Entry("Pandaxin's paradox", "minio-01.192-168-1-100.sslip.io", dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}}),
			Entry("Hexadecimal #0", "filer.7f000001.sslip.io", dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
			Entry("Hexadecimal #1, TLD", "0A09091E", dnsmessage.AResource{A: [4]byte{10, 9, 9, 30}}),
			Entry("Hexadecimal #1, TLD #2", "0A09091E.", dnsmessage.AResource{A: [4]byte{10, 9, 9, 30}}),
			Entry("Hexadecimal #1, TLD #3", ".0A09091E.", dnsmessage.AResource{A: [4]byte{10, 9, 9, 30}}),
			Entry("Hexadecimal #1, TLD #4", "www.0A09091E.", dnsmessage.AResource{A: [4]byte{10, 9, 9, 30}}),
			Entry("Hexadecimal #2, mixed case", "ffffFFFF.nip.io", dnsmessage.AResource{A: [4]byte{255, 255, 255, 255}}),
			Entry("Hexadecimal #3, different numbers", "www.fedcba98.nip.io", dnsmessage.AResource{A: [4]byte{254, 220, 186, 152}}),
			Entry("Hexadecimal #3, different numbers #2", "www.76543210.nip.io", dnsmessage.AResource{A: [4]byte{118, 84, 50, 16}}),
			Entry("Hexadecimal #4, dashes trump hex", "www.127-0-0-53.76543210.nip.io", dnsmessage.AResource{A: [4]byte{127, 0, 0, 53}}),
			Entry("Hexadecimal #4, dashes trump hex #2", "www.76543210.127-0-0-53.nip.io", dnsmessage.AResource{A: [4]byte{127, 0, 0, 53}}),
			Entry("Hexadecimal #4, dots trump hex", "www.127.0.0.53.76543210.nip.io", dnsmessage.AResource{A: [4]byte{127, 0, 0, 53}}),
			Entry("Hexadecimal #4, dots trump hex #2", "www.76543210.127.0.0.53.nip.io", dnsmessage.AResource{A: [4]byte{127, 0, 0, 53}}),
		)
		DescribeTable("when it does NOT match an IP address",
			func(fqdn string) {
				ipv4Answers := xip.NameToA(fqdn, true)
				Expect(len(ipv4Answers)).To(Equal(0))
			},
			Entry("empty string", ""),
			Entry("bare domain", "nono.io"),
			Entry("canonical domain", "sslip.io"),
			Entry("www", "www.sslip.io"),
			Entry("a lone number", "538.sslip.io"),
			Entry("too big", "256.254.253.252"),
			Entry("NS but no dot", "ns-hetzner.sslip.io"),
			Entry("NS + cruft at beginning", "p-ns-hetzner.sslip.io"),
			Entry("test-net address with dots-and-dashes mixed", "www-192.0-2.3.example-me.com"),
			Entry("Hexadecimal with too many digits (9 instead of 8)", "www.0A09091E0.com"),
			Entry("Hexadecimal with too few  digits (7 instead of 8)", "www.0A09091.com"),
			Entry("Hexadecimal with a dash instead of a .", "www-0A09091E.com"),
			Entry("Hexadecimal with a dash instead of a . #2", "www.0A09091E-com"),
		)
		When("There is more than one A record", func() {
			It("returns them all", func() {
				fqdn := testhelper.Random8ByteString()
				xip.Customizations[strings.ToLower(fqdn)] = xip.DomainCustomization{
					A: []dnsmessage.AResource{
						{A: [4]byte{1}},
						{A: [4]byte{2}},
					},
				}
				ipv4Answers := xip.NameToA(fqdn, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ipv4Answers)).To(Equal(2))
				Expect(ipv4Answers[0].A).To(Equal([4]byte{1}))
				Expect(ipv4Answers[1].A).To(Equal([4]byte{2}))
				delete(xip.Customizations, fqdn)
			})
		})
		When("There are multiple matches", func() {
			It("returns the leftmost one", func() {
				ipv4Answers := xip.NameToA("nono.io.127.0.0.1.192.168.0.1.sslip.io", true)
				Expect(len(ipv4Answers)).To(Equal(1))
				Expect(ipv4Answers[0]).
					To(Equal(dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}))
			})
		})
		When("There are matches with dashes and dots", func() {
			It("returns the one with dashes", func() {
				ipv4Answers := xip.NameToA("nono.io.127.0.0.1.192-168-0-1.sslip.io", true)
				Expect(len(ipv4Answers)).To(Equal(1))
				Expect(ipv4Answers[0]).
					To(Equal(dnsmessage.AResource{A: [4]byte{192, 168, 0, 1}}))
			})
		})
	})

	Describe("IsAcmeChallenge()", func() {
		When("the domain doesn't have '_acme-challenge.' in it", func() {
			It("returns false", func() {
				randomDomain := testhelper.Random8ByteString() + ".com."
				Expect(xip.IsAcmeChallenge(randomDomain)).To(BeFalse())
			})
			It("returns false even when there are embedded IPs", func() {
				randomDomain := "127.0.0.1." + testhelper.Random8ByteString() + ".com."
				Expect(xip.IsAcmeChallenge(randomDomain)).To(BeFalse())
			})
		})
		When("it has '_acme-challenge.' in it", func() {
			When("it does NOT have any embedded IPs", func() {
				It("returns false", func() {
					randomDomain := "_acme-challenge." + testhelper.Random8ByteString() + ".com."
					Expect(xip.IsAcmeChallenge(randomDomain)).To(BeFalse())
				})
			})
			When("it has embedded IPs", func() {
				It("returns true", func() {
					randomDomain := "_acme-challenge.127.0.0.1." + testhelper.Random8ByteString() + ".com."
					Expect(xip.IsAcmeChallenge(randomDomain)).To(BeTrue())
					randomDomain = "_acme-challenge.fe80--1." + testhelper.Random8ByteString() + ".com."
					Expect(xip.IsAcmeChallenge(randomDomain)).To(BeTrue())
				})
				When("it has random capitalization", func() {
					It("returns true", func() {
						randomDomain := "_AcMe-ChAlLeNgE.127.0.0.1." + testhelper.Random8ByteString() + ".com."
						Expect(xip.IsAcmeChallenge(randomDomain)).To(BeTrue())
						randomDomain = "_aCMe-cHAllENge.fe80--1." + testhelper.Random8ByteString() + ".com."
						Expect(xip.IsAcmeChallenge(randomDomain)).To(BeTrue())
					})
				})
			})
		})
	})
	Describe("IsDelegated()", func() {
		var nsName dnsmessage.Name
		nsName, err = dnsmessage.NewName("1.com")
		Expect(err).ToNot(HaveOccurred())
		xip.Customizations["a.com"] = xip.DomainCustomization{NS: []dnsmessage.NSResource{{NS: nsName}}}
		xip.Customizations["b.com"] = xip.DomainCustomization{}

		When("the domain is delegated", func() {
			When("the fqdn exactly matches the domain", func() {
				It("returns true", func() {
					Expect(xip.IsDelegated("A.com")).To(BeTrue())
				})
			})
			When("the fqdn is a subdomain of the domain", func() {
				It("returns true", func() {
					Expect(xip.IsDelegated("b.a.COM")).To(BeTrue())
				})
			})
			When("the fqdn doesn't match the domain", func() {
				It("returns false", func() {
					Expect(xip.IsDelegated("Aa.com")).To(BeFalse())
				})
			})
		})
		When("the domain is customized but not delegated", func() {
			It("returns false", func() {
				Expect(xip.IsDelegated("b.COM")).To(BeFalse())
			})
		})
	})

	Describe("NameToAAAA()", func() {
		DescribeTable("when it succeeds",
			func(fqdn string, expectedAAAA dnsmessage.AAAAResource) {
				ipv6Answers := xip.NameToAAAA(fqdn, true)
				Expect(ipv6Answers[0]).To(Equal(expectedAAAA))
				Expect(len(ipv6Answers)).To(Equal(1))
			},
			// dashes only
			Entry("loopback", "--1", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("ff with domain", "fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("ff with domain and pre", "www.fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("ff with domain dashes", "1.www-fffe-fdfc-fbfa-f9f8-f7f6-f5f4-f3f2-f1f0-1.com", dnsmessage.AAAAResource{AAAA: [16]byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}}),
			Entry("Browsing the logs", "2006-41d0-2-e01e--56dB-3598.sSLIP.io.", dnsmessage.AAAAResource{AAAA: [16]byte{32, 6, 65, 208, 0, 2, 224, 30, 0, 0, 0, 0, 86, 219, 53, 152}}),
			Entry("Browsing the logs", "1-2-3--4-5-6.sSLIP.io.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 1, 0, 2, 0, 3, 0, 0, 0, 0, 0, 4, 0, 5, 0, 6}}),
			Entry("Browsing the logs", "1--2-3-4-5-6.sSLIP.io.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 1, 0, 0, 0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6}}),
			Entry("Hexadecimal #0", "filer.00000000000000000000000000000001.sslip.io", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("Hexadecimal #1, TLD", "00000000000000000000000000000001", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("Hexadecimal #1, TLD #2", "00000000000000000000000000000001.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("Hexadecimal #1, TLD #3", ".00000000000000000000000000000001.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("Hexadecimal #1, TLD #4", "www.00000000000000000000000000000001.", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("Hexadecimal #2, mixed case", "89abcdef0000000089ABCDEF00000000.nip.io", dnsmessage.AAAAResource{AAAA: [16]byte{137, 171, 205, 239, 0, 0, 0, 0, 137, 171, 205, 239, 0, 0, 0, 0}}),
			Entry("Hexadecimal #3, different numbers", "www.0123456789abcdef0123456789abcdef.nip.io", dnsmessage.AAAAResource{AAAA: [16]byte{1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239}}),
			Entry("Hexadecimal #3, different numbers #2", "www.00000000000000000000000000000001.nip.io", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
			Entry("Hexadecimal #4, dashes trump hex", "www.2600--.00000000000000000000000000000001.nip.io", dnsmessage.AAAAResource{AAAA: [16]byte{38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}),
			Entry("Hexadecimal #4, dashes trump hex #2", "www.00000000000000000000000000000001.--2.nip.io", dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}),
		)
		DescribeTable("when it does not match an IP address",
			func(fqdn string) {
				ipv6Answers := xip.NameToAAAA(fqdn, true)
				Expect(len(ipv6Answers)).To(Equal(0))
			},
			Entry("empty string", ""),
			Entry("bare domain", "nono.io"),
			Entry("canonical domain", "sslip.io"),
			Entry("www", "www.sslip.io"),
			Entry("a 1 without double-dash", "-1"),
			Entry("too big", "--g"),
			Entry("Hexadecimal with too many digits (33 instead of 32)", "www.0123456789abcdef0123456789abcdef0.com"),
			Entry("Hexadecimal with too few  digits (31 instead of 32)", "www.0123456789abcdef0123456789abcde.com"),
			Entry("Hexadecimal with a dash instead of a .", "www-0123456789abcdef0123456789abcdef.com"),
			Entry("Hexadecimal with a dash instead of a . #2", "www.0123456789abcdef0123456789abcdef-com"),
		)
		When("using randomly generated IPv6 addresses (fuzz testing)", func() {
			It("should succeed every time", func() {
				for i := 0; i < 10000; i++ {
					addr := testhelper.RandomIPv6Address()
					ipv6Answers := xip.NameToAAAA(strings.ReplaceAll(addr.String(), ":", "-"), true)
					Expect(err).ToNot(HaveOccurred())
					Expect(ipv6Answers[0].AAAA[:]).To(Equal([]uint8(addr)))
				}
			})
		})
		When("There is more than one AAAA record", func() {
			It("returns them all", func() {
				fqdn := testhelper.Random8ByteString()
				xip.Customizations[strings.ToLower(fqdn)] = xip.DomainCustomization{
					AAAA: []dnsmessage.AAAAResource{
						{AAAA: [16]byte{1}},
						{AAAA: [16]byte{2}},
					},
				}
				ipv6Addrs := xip.NameToAAAA(fqdn, true)
				Expect(len(ipv6Addrs)).To(Equal(2))
				Expect(ipv6Addrs[0].AAAA).To(Equal([16]byte{1}))
				Expect(ipv6Addrs[1].AAAA).To(Equal([16]byte{2}))
				delete(xip.Customizations, fqdn)
			})
		})
	})

	Describe("ReadBlocklist()", func() {
		It("strips comments", func() {
			input := strings.NewReader("# a comment\n#another comment\nno-comments\n")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(blCIDRs)).To(BeZero())
			Expect(blIPs).To(Equal(map[string]struct{}{}))
			Expect(blStrings).To(Equal([]string{"no-comments"}))
		})
		It("strips blank lines", func() {
			input := strings.NewReader("\n\n\nno-blank-lines")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(blCIDRs)).To(BeZero())
			Expect(blIPs).To(Equal(map[string]struct{}{}))
			Expect(blStrings).To(Equal([]string{"no-blank-lines"}))
		})
		It("lowercases names for comparison", func() {
			input := strings.NewReader("NO-YELLING")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(blCIDRs)).To(BeZero())
			Expect(blIPs).To(Equal(map[string]struct{}{}))
			Expect(blStrings).To(Equal([]string{"no-yelling"}))
		})
		It("removes all non-allowable characters", func() {
			input := strings.NewReader("\nalpha #comment # comment\nåß∂ # comment # comment\ndelta∆\n ... GAMMA∑µ®† ...#asdfasdf#asdfasdf")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(blCIDRs)).To(BeZero())
			Expect(blIPs).To(Equal(map[string]struct{}{}))
			Expect(blStrings).To(Equal([]string{"alpha", "delta", "gamma"}))
		})
		It("reads in IPv4 CIDRs", func() {
			input := strings.NewReader("\n43.134.66.67/24 #asdfasdf")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(blCIDRs).To(Equal([]net.IPNet{{IP: net.IP{43, 134, 66, 0}, Mask: net.IPMask{255, 255, 255, 0}}}))
			Expect(blIPs).To(Equal(map[string]struct{}{}))
			Expect(len(blStrings)).To(BeZero())
		})
		It("reads in IPv4 CIDRs, but with a /32 converts it to an IP address", func() {
			input := strings.NewReader("\n43.134.66.67/32 #asdfasdf")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(blCIDRs)).To(BeZero())
			Expect(blIPs).To(Equal(map[string]struct{}{"43.134.66.67": {}}))
			Expect(len(blStrings)).To(BeZero())
		})
		It("reads in IPv6 CIDRs", func() {
			input := strings.NewReader("\n 2600::/64 #asdfasdf")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(blCIDRs).To(Equal([]net.IPNet{
				{IP: net.IP{38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Mask: net.IPMask{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}}}))
			Expect(blIPs).To(Equal(map[string]struct{}{}))
			Expect(len(blStrings)).To(BeZero())
		})
		It("reads in IPv4 IP addresses (but not IPv6)", func() {
			input := strings.NewReader("\n 104.155.144.4 #asdfasdf")
			blCIDRs, blIPs, blStrings, err := xip.ReadBlocklist(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(blCIDRs)).To(BeZero())
			Expect(blIPs).To(Equal(map[string]struct{}{"104.155.144.4": {}}))
			Expect(len(blStrings)).To(BeZero())
		})
	})

	Describe("IsPublic()", func() {
		DescribeTable("when determining whether an IP is public or private",
			func(ip net.IP, expectedPublic bool) {
				Expect(xip.IsPublic(ip)).To(Equal(expectedPublic))
			},
			Entry("Google Nameserver IPv4", net.ParseIP("8.8.8.8"), true),
			Entry("Google Nameserver IPv6", net.ParseIP("2001:4860:4860::8888"), true),
			Entry("Apple Studio morgoth.nono.io", net.ParseIP("2601:646:100:69f0:7d:9069:ea74:e3a"), true),
			Entry("External interface home.nono.io", net.ParseIP("2001:558:6045:109:892f:2df3:15e3:3184"), true),
			Entry("RFC 1918 Section 3 10/8", net.ParseIP("10.9.9.30"), false),
			Entry("RFC 1918 Section 3 172.16/12", net.ParseIP("172.31.255.255"), false),
			Entry("RFC 1918 Section 3 192.168/16", net.ParseIP("192.168.0.1"), false),
			Entry("RFC 4193 Section 8 fc00::/7", net.ParseIP("fdff::"), false),
			Entry("CG-NAT 100.64/10", net.ParseIP("100.127.255.255"), false),
			Entry("CG-NAT 100.64/10", net.ParseIP("100.128.0.0"), true),
			Entry("link-local IPv4", net.ParseIP("169.254.169.254"), false),
			Entry("not link-local IPv4", net.ParseIP("169.255.255.255"), true),
			Entry("link-local IPv6", net.ParseIP("fe80::"), false),
			Entry("loopback IPv4 127/8", net.ParseIP("127.127.127.127"), false),
			Entry("loopback IPv6 ::1/128", net.ParseIP("::1"), false),
			Entry("IPv4/IPv6 Translation internet", net.ParseIP("64:ff9b::"), true),
			Entry("IPv4/IPv6 Translation private internet", net.ParseIP("64:ff9b:1::"), false),
			Entry("IPv4/IPv6 Translation internet", net.ParseIP("64:ff9b::"), true),
			Entry("Teredo Tunneling", net.ParseIP("2001::"), true),
			Entry("ORCHIDv2 (?)", net.ParseIP("2001:20::"), false),
			Entry("Documentation", net.ParseIP("2001:db8::"), false),
			Entry("Private internets", net.ParseIP("fc00::"), false),
		)
	})
})
