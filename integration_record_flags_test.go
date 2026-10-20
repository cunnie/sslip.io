package main_test

import (
	"os/exec"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("record flags (-a, -aaaa, -mx, -cname, -txt, -ns, -soa)", func() {
	var serverCmd *exec.Cmd
	var serverSession *Session
	var port = getFreePort()
	var flags []string

	// digShort returns the "+short" answer section, e.g. "20 mailsec.protonmail.ch.\n"
	digShort := func(args string) string {
		digCmd := exec.Command("dig", strings.Split("+short @localhost -p "+strconv.Itoa(port)+" "+args, " ")...)
		digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
		Eventually(digSession, 1).Should(Exit(0))
		return string(digSession.Out.Contents())
	}

	When("the flags are valid", func() {
		JustBeforeEach(func() {
			flags = append(flags, "-port", strconv.Itoa(port), "-blocklistURL", "file://etc/blocklist-test.txt")
			serverCmd = exec.Command(serverPath, flags...)
			serverSession, err = Start(serverCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(serverSession.Err, 10).Should(Say("Ready to answer queries"))
		})
		AfterEach(func() {
			serverSession.Terminate()
			Eventually(serverSession).Should(Exit())
		})

		When("-a is set", func() {
			BeforeEach(func() {
				flags = []string{"-a", "a.example.com=192.168.1.1", "-a=A.Example.COM.=10.0.0.1"}
			})
			It("returns every A record, regardless of case or trailing dot", func() {
				answer := digShort("a.example.com a")
				Expect(answer).To(ContainSubstring("192.168.1.1\n"))
				Expect(answer).To(ContainSubstring("10.0.0.1\n"))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding A record "a.example.com.=192.168.1.1"`))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding A record "a.example.com.=10.0.0.1"`))
			})
		})
		When("-aaaa is set", func() {
			BeforeEach(func() {
				flags = []string{"-aaaa", "aaaa.example.com=2600::", "-aaaa", "aaaa.example.com=fc00::1"}
			})
			It("returns every AAAA record", func() {
				answer := digShort("aaaa.example.com aaaa")
				Expect(answer).To(ContainSubstring("2600::\n"))
				Expect(answer).To(ContainSubstring("fc00::1\n"))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding AAAA record "aaaa.example.com.=2600::"`))
			})
		})
		When("-mx is set", func() {
			BeforeEach(func() {
				flags = []string{"-mx", "mx.example.com=20,mailsec.protonmail.ch", "-mx", "mx.example.com=10,mail.protonmail.ch."}
			})
			It("returns every MX record, appending the trailing dot to the host if missing", func() {
				answer := digShort("mx.example.com mx")
				Expect(answer).To(ContainSubstring("20 mailsec.protonmail.ch.\n"))
				Expect(answer).To(ContainSubstring("10 mail.protonmail.ch.\n"))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding MX record "mx.example.com.=20,mailsec.protonmail.ch."`))
			})
		})
		When("-txt is set", func() {
			BeforeEach(func() {
				flags = []string{
					"-txt", `txt.example.com="protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313"`,
					"-txt", "txt.example.com=unquoted text",
				}
			})
			It("returns every TXT record, stripping the optional surrounding quotes", func() {
				answer := digShort("txt.example.com txt")
				Expect(answer).To(ContainSubstring(`"protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313"` + "\n"))
				Expect(answer).To(ContainSubstring(`"unquoted text"` + "\n"))
			})
		})
		When("-txt is longer than 255 bytes", func() {
			BeforeEach(func() {
				flags = []string{"-txt", "long.example.com=" + strings.Repeat("a", 255) + "bcd"}
			})
			It("splits the record into 255-byte strings", func() {
				Expect(digShort("long.example.com txt")).To(Equal(`"` + strings.Repeat("a", 255) + `" "bcd"` + "\n"))
			})
		})
		When("-txt is set for a domain with a built-in TXT record (ip.nip.io)", func() {
			BeforeEach(func() {
				flags = []string{"-txt", "ip.nip.io=replaced"}
			})
			It("replaces the built-in TXT record", func() {
				Expect(digShort("ip.nip.io txt")).To(Equal(`"replaced"` + "\n"))
			})
		})
		When("-cname is set", func() {
			BeforeEach(func() {
				flags = []string{"-cname", "CNAME.example.com=overwritten.example.com", "-cname", "cname.example.com.=target.example.com"}
			})
			It("returns the last CNAME, appending the trailing dot if missing", func() {
				Expect(digShort("cname.example.com cname")).To(Equal("target.example.com.\n"))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Setting CNAME record "cname.example.com.=target.example.com."`))
			})
			It("returns the CNAME for other query types, too", func() {
				for _, queryType := range []string{"txt", "a", "aaaa", "mx", "ns", "soa"} {
					Expect(digShort("cname.example.com "+queryType)).To(Equal("target.example.com.\n"), queryType)
				}
			})
		})
		When("-ns is set", func() {
			BeforeEach(func() {
				flags = []string{"-ns", "delegated.example.com=NS-00.nip.io", "-ns", "delegated.example.com=ns-01.nip.io."}
			})
			It("delegates the domain and its subdomains to the nameservers, appending the trailing dot if missing", func() {
				digCmd := exec.Command("dig", "@localhost", "-p", strconv.Itoa(port), "www.delegated.example.com", "a")
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession, 1).Should(Exit(0))
				Expect(string(digSession.Out.Contents())).To(ContainSubstring("ANSWER: 0, AUTHORITY: 2"))
				Expect(string(digSession.Out.Contents())).To(MatchRegexp(`www\.delegated\.example\.com\.\s+\d+\s+IN\s+NS\s+ns-00\.nip\.io\.\n`))
				Expect(string(digSession.Out.Contents())).To(MatchRegexp(`www\.delegated\.example\.com\.\s+\d+\s+IN\s+NS\s+ns-01\.nip\.io\.\n`))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding NS record "delegated.example.com.=ns-00.nip.io."`))
			})
		})
		When("-ns is set for the root domain (\".\")", func() {
			BeforeEach(func() {
				flags = []string{"-ns", ".=NS-00.nip.io", "-ns", ".=ns-01.nip.io."}
			})
			It("sets the default nameservers, like -nameservers, appending the trailing dot if missing", func() {
				answer := digShort("example.com ns")
				Expect(answer).To(ContainSubstring("ns-00.nip.io.\n"))
				Expect(answer).To(ContainSubstring("ns-01.nip.io.\n"))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding nameserver "ns-00.nip.io."`))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Adding nameserver "ns-01.nip.io."`))
			})
			It("doesn't delegate anything", func() {
				Expect(digShort("127.0.0.1.nip.io a")).To(Equal("127.0.0.1\n"))
			})
		})
		When("-ns is set for the root domain and -nameservers is also set", func() {
			BeforeEach(func() {
				flags = []string{"-ns", ".=ns-00.nip.io", "-nameservers", "ns-01.nip.io"}
			})
			It("returns the nameservers from both flags", func() {
				answer := digShort("example.com ns")
				Expect(answer).To(ContainSubstring("ns-00.nip.io.\n"))
				Expect(answer).To(ContainSubstring("ns-01.nip.io.\n"))
			})
		})
		When("-soa is set", func() {
			BeforeEach(func() {
				flags = []string{"-soa=NIP.io,dns-admin.nip.io.,998506478,900,900,1800,300"}
			})
			It("returns that SOA for every domain, appending the trailing dot if missing", func() {
				Expect(digShort("example.com soa")).To(Equal("nip.io. dns-admin.nip.io. 998506478 900 900 1800 300\n"))
				Expect(digShort("127.0.0.1.sslip.io soa")).To(Equal("nip.io. dns-admin.nip.io. 998506478 900 900 1800 300\n"))
				Expect(string(serverSession.Err.Contents())).To(ContainSubstring(`Setting SOA record "nip.io. dns-admin.nip.io. 998506478 900 900 1800 300"`))
			})
			It("returns that SOA in the authority section when there's no answer", func() {
				digCmd := exec.Command("dig", "@localhost", "-p", strconv.Itoa(port), "example.com", "a")
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession, 1).Should(Exit(0))
				Expect(string(digSession.Out.Contents())).To(MatchRegexp(`example\.com\.\s+\d+\s+IN\s+SOA\s+nip\.io\. dns-admin\.nip\.io\. 998506478 900 900 1800 300\n`))
			})
		})
	})

	DescribeTable("when a flag is invalid, it exits with an informative message",
		func(flag, value, message string) {
			serverCmd = exec.Command(serverPath, "-port", strconv.Itoa(port), flag, value)
			serverSession, err = Start(serverCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(serverSession, 10).Should(Exit(2))
			Expect(string(serverSession.Err.Contents())).To(ContainSubstring(message))
		},
		Entry("-a without an '='", "-a", "nip.io", `should be in the format "domain=value"`),
		Entry("-a without a domain", "-a", "=1.2.3.4", `should be in the format "domain=value"`),
		Entry("-a with an IPv6 address", "-a", "nip.io=2600::", `"2600::" is not a valid IPv4 address`),
		Entry("-aaaa with an IPv4 address", "-aaaa", "nip.io=1.2.3.4", `"1.2.3.4" is not a valid IPv6 address`),
		Entry("-mx without a preference", "-mx", "nip.io=mail.protonmail.ch", `should be in the format "domain=preference,host"`),
		Entry("-mx with a non-numeric preference", "-mx", "nip.io=ten,mail.protonmail.ch", `"ten" is not a valid MX preference`),
		Entry("-mx with a preference > 65535", "-mx", "nip.io=65536,mail.protonmail.ch", `"65536" is not a valid MX preference`),
		Entry("-cname without a target", "-cname", "cname.example.com=", `should be in the format "domain=value"`),
		Entry("-cname with a target > 255 chars", "-cname", "cname.example.com="+strings.Repeat("a.", 128), "is not a valid CNAME"),
		Entry("-txt with an unterminated quote", "-txt", `nip.io="oops`, "is not a properly-quoted string"),
		Entry("-txt with an empty quoted string", "-txt", `nip.io=""`, "is empty"),
		Entry("-ns with a nameserver > 255 chars", "-ns", "nip.io="+strings.Repeat("a.", 128), "is not a valid nameserver"),
		Entry("-soa with too few fields", "-soa", "nip.io.,dns-admin.nip.io.,998506478,900,900,1800", `should be in the format "mname,rname,serial,refresh,retry,expire,minimum"`),
		Entry("-soa with a non-numeric serial", "-soa", "nip.io.,dns-admin.nip.io.,one,900,900,1800,300", `"one" is not a valid SOA serial`),
		Entry("-soa with a minimum > 4294967295", "-soa", "nip.io.,dns-admin.nip.io.,998506478,900,900,1800,4294967296", `"4294967296" is not a valid SOA minimum`),
		Entry("-soa with an rname > 255 chars", "-soa", "nip.io.,"+strings.Repeat("a.", 128)+",998506478,900,900,1800,300", "is not a valid SOA rname"),
	)
})
