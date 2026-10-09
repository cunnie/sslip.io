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

var _ = Describe("record flags (-a, -aaaa, -mx, -txt, -ns)", func() {
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
		When("-mx is set for a domain with built-in MX records (nip.io)", func() {
			BeforeEach(func() {
				flags = []string{"-mx", "nip.io=30,mx.example.com"}
			})
			It("replaces the built-in MX records", func() {
				Expect(digShort("nip.io mx")).To(Equal("30 mx.example.com.\n"))
			})
			It("leaves the other domains' built-in MX records alone", func() {
				Expect(digShort("sslip.io mx")).To(ContainSubstring("mail.protonmail.ch."))
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
		When("-txt is set for a domain with built-in TXT records (nip.io)", func() {
			BeforeEach(func() {
				flags = []string{"-txt", "nip.io=replaced"}
			})
			It("replaces the built-in TXT records", func() {
				Expect(digShort("nip.io txt")).To(Equal(`"replaced"` + "\n"))
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
		Entry("-txt with an unterminated quote", "-txt", `nip.io="oops`, "is not a properly-quoted string"),
		Entry("-txt with an empty quoted string", "-txt", `nip.io=""`, "is empty"),
		Entry("-ns with a nameserver > 255 chars", "-ns", "nip.io="+strings.Repeat("a.", 128), "is not a valid nameserver"),
	)
})
