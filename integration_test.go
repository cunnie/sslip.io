package main_test

import (
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"xip/testhelper"
	"xip/xip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var err error
var serverCmd *exec.Cmd
var serverSession *Session
var port = getFreePort()
var serverPath, _ = Build("main.go")

var _ = BeforeSuite(func() {
	format.MaxLength = 0 // need more output, 4000 is the default
	Expect(err).ToNot(HaveOccurred())
	serverCmd = exec.Command(serverPath, "-port", strconv.Itoa(port), "-blocklistURL", "file://etc/blocklist-test.txt")
	serverSession, err = Start(serverCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred())
	// takes 0.455s to start up on macOS Big Sur 3.7 GHz Quad Core 22-nm Xeon E5-1620v2 processor (2013 Mac Pro)
	// takes 1.312s to start up on macOS Big Sur 2.0GHz quad-core 10th-generation Intel Core i5 processor (2020 13" MacBook Pro)
	// 10 seconds should be long enough for slow container-on-a-VM-with-shared-core
	Eventually(serverSession.Err, 10).Should(Say(` version \d+\.\d+\.\d+ starting`))
	Eventually(serverSession.Err, 10).Should(Say("Ready to answer queries"))
})

var _ = AfterSuite(func() {
	serverSession.Terminate()
	Eventually(serverSession).Should(Exit())
})

var _ = Describe("sslip.io-dns-server", func() {
	//var stdin io.WriteCloser
	var digCmd *exec.Cmd
	var digSession *Session
	var digArgs string

	Describe("Integration tests", func() {
		DescribeTable("when the DNS server is queried",
			func(digArgs string, digResults string, serverLogMessage string) {
				digArgs += " -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				// we want to make sure digSession has exited because we
				// want to compare the _full_ contents of the stdout in the case
				// of negative assertions (e.g. "^$")
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(digResults))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(serverLogMessage))
			},
			Entry("A (customized) for sslip.io",
				"@localhost sslip.io +short",
				`\A78.46.204.247\n\z`,
				`TypeA sslip.io. \? 78.46.204.247\n`),
			Entry("A (or lack thereof) for example.com",
				"@localhost example.com +short",
				`\A\z`,
				`TypeA example.com. \? nil, SOA example.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry("A for www-127-0-0-1.sslip.io",
				"@localhost www-127-0-0-1.sslip.io +short",
				`\A127.0.0.1\n\z`,
				`TypeA www-127-0-0-1.sslip.io. \? 127.0.0.1\n`),
			Entry("A for www.192.168.0.1.sslip.io",
				"@localhost www.192.168.0.1.sslip.io +short",
				`\A192.168.0.1\n\z`,
				`TypeA www.192.168.0.1.sslip.io. \? 192.168.0.1\n`),
			Entry("A for www.c0a80001.sslip.io",
				"@localhost www.c0a80001.sslip.io +short",
				`\A192.168.0.1\n\z`,
				`TypeA www.c0a80001.sslip.io. \? 192.168.0.1\n`),
			Entry("A for www-c0a80001.sslip.io",
				"@localhost www-c0a80001.sslip.io +short",
				`\A192.168.0.1\n\z`,
				`TypeA www-c0a80001.sslip.io. \? 192.168.0.1\n`),
			Entry("A (not found) for www.0c0a80001.sslip.io",
				"@localhost www.0c0a80001.sslip.io +short",
				`\A\z`,
				`TypeA www.0c0a80001.sslip.io. \? nil, SOA www.0c0a80001.sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry("AAAA (customized) for sslip.io",
				"@localhost sslip.io aaaa +short",
				`\A2a01:4f8:c17:b8f::2\n\z`,
				`TypeAAAA sslip.io. \? 2a01:4f8:c17:b8f::2\n`),
			Entry("AAAA not found for example.com",
				"@localhost example.com aaaa +short",
				`\A\z`,
				`TypeAAAA example.com. \? nil, SOA example.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry("AAAA for www-2601-646-100-69f0-1c09-bae7-aa42-146c.sslip.io",
				"@localhost www-2601-646-100-69f0-1c09-bae7-aa42-146c.sslip.io aaaa +short",
				`\A2601:646:100:69f0:1c09:bae7:aa42:146c\n\z`,
				`TypeAAAA www-2601-646-100-69f0-1c09-bae7-aa42-146c.sslip.io. \? 2601:646:100:69f0:1c09:bae7:aa42:146c\n`),
			Entry("ALL (ANY) is NOT implemented",
				// `+notcp` required for dig 9.11.25-RedHat-9.11.25-2.fc32 to avoid "connection refused"
				"@localhost sslip.io any +notcp",
				` status: NOTIMP,`,
				`TypeALL sslip.io. \? NotImplemented\n`),
			Entry("CNAME (customized) for protonmail._domainkey.sslip.io",
				"@localhost protonmail._domainkey.sslip.io cname +short",
				`\Aprotonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.\n\z`,
				`TypeCNAME protonmail._domainkey.sslip.io. \? protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.\n`),
			Entry("CNAME not found for example.com",
				"@localhost example.com cname +short",
				`\A\z`,
				`TypeCNAME example.com. \? nil, SOA example.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry("MX for example.com",
				"@localhost example.com mx +short",
				`\A0 example.com.\n\z`,
				`TypeMX example.com. \? 0 example.com.\n`),
			Entry("SOA for sslip.io",
				"@localhost sslip.io soa +short",
				`\Asslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n\z`,
				`TypeSOA sslip.io. \? sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry("SOA for example.com",
				"@localhost example.com soa +short",
				`\Aexample.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n\z`,
				`TypeSOA example.com. \? example.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry("SRV (or other record that we don't implement) for example.com",
				"@localhost example.com srv +short",
				`\A\z`,
				`TypeSRV example.com. \? nil, SOA example.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`TXT for version.status.sslip.io is the version number of the xip software (which gets overwritten during linking)`,
				"@127.0.0.1 version.status.sslip.io txt +short",
				`\A"0.0.0"\n"0001/01/01-99:99:99-0800"\n"cafexxx"\n\z`,
				`TypeTXT version.status.sslip.io. \? \["0.0.0"\], \["0001/01/01-99:99:99-0800"\], \["cafexxx"\]`),
			Entry(`TXT is the querier's IPv4 address and the domain "ip.sslip.io"`,
				"@127.0.0.1 ip.sslip.io txt +short",
				`127.0.0.1`,
				`TypeTXT ip.sslip.io. \? \["127.0.0.1"\]`),
			Entry(`TXT is the querier's IPv4 address and the domain is NOT "ip.sslip.io"`,
				"@127.0.0.1 example.com txt +short",
				`\A\z`,
				`TypeTXT example.com. \? nil, SOA example.com. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`get a PTR for 1.0.168.192.in-addr.arpa returns 192-168-0-1.sslip.io`,
				"@127.0.0.1 ptr -x 192.168.0.1 +short",
				`\A192-168-0-1.sslip.io.\n\z`,
				`TypePTR 1.0.168.192.in-addr.arpa. \? 192-168-0-1.sslip.io.`),
			Entry(`get a PTR for 1.0.0.127.blah.in-addr.arpa returns no records; "blah.in-addr.arpa is not a valid domain."`,
				"@127.0.0.1 1.0.0.127.blah.in-addr.arpa ptr +short",
				`\A\z`,
				`TypePTR 1.0.0.127.blah.in-addr.arpa. \? nil, SOA sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`get a PTR for blah.1.0.0.127.in-addr.arpa returns no records; "blah" isn't a valid subdomain' `,
				"@127.0.0.1 blah.1.0.0.127.in-addr.arpa ptr +short",
				`\A\z`,
				`TypePTR blah.1.0.0.127.in-addr.arpa. \? nil, SOA sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`get a PTR for 0.0.127.in-addr.arpa returns no records; should have 4 octets, not 3`,
				"@127.0.0.1 0.0.127.in-addr.arpa ptr +short",
				`\A\z`,
				`TypePTR 0.0.127.in-addr.arpa. \? nil, SOA sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`get a PTR for 2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa returns 2601-646-100-69f0-14ce-6eea-9204-bba2.sslip.io`,
				"@127.0.0.1 ptr -x 2601:646:100:69f0:14ce:6eea:9204:bba2 +short",
				`\A2601-646-100-69f0-14ce-6eea-9204-bba2.sslip.io.\n\z`,
				`TypePTR 2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. \? 2601-646-100-69f0-14ce-6eea-9204-bba2.sslip.io.`),
			Entry(`get a PTR for 2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.blah.ip6.arpa returns no records; "blah isn't a valid subdomain'"`,
				"@127.0.0.1 2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.blah.ip6.arpa ptr +short",
				`\A\z`,
				`TypePTR 2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.blah.ip6.arpa. \? nil, SOA sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`get a PTR for b2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa returns no records; "b2" isn't a valid subdomain'`,
				"@127.0.0.1 b2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa ptr +short",
				`\A\z`,
				`TypePTR b2.a.b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. \? nil, SOA sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`get a PTR for b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa returns no records; has too few numbers`,
				"@127.0.0.1 b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa ptr +short",
				`\A\z`,
				`TypePTR b.b.4.0.2.9.a.e.e.6.e.c.4.1.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. \? nil, SOA sslip.io. briancunnie.gmail.com. 20250615 900 900 1800 180\n`),
			Entry(`TODO: should, but doesn't, return an IDNA2008-compliant record for ::1`,
				"@127.0.0.1 -x ::1 +short",
				`\A--1.sslip.io.\n\z`,
				`TypePTR 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. \? --1.sslip.io.\n`),
			Entry(`TODO: should, but doesn't, return an IDNA2008-compliant record for 2600::`,
				"@127.0.0.1 -x 2600:: +short",
				`\A2600--.sslip.io.\n\z`,
				`TypePTR 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.2.ip6.arpa. \? 2600--.sslip.io.\n`),
			Entry(`over TCP, A (customized) for sslip.io`,
				"@localhost sslip.io +short +vc",
				`\A78.46.204.247\n\z`,
				`TypeA sslip.io. \? 78.46.204.247\n`),
			Entry(`TXT for _psl sslip.io is a link to the pull request for putting sslip.io on the Public Suffix List`,
				"@localhost _psl.sslip.io txt +short",
				`\A"https://github.com/publicsuffix/list/pull/2206"\n\z`,
				`TypeTXT _psl.sslip.io. \? \["https://github.com/publicsuffix/list/pull/2206"\]`),
		)
	})
	Describe("for more complex assertions", func() {
		When("we want to make sure our TTL is an hour if we need to block ", func() {
			It("returns a TTL of 3600, at least for the non-RFC 1918 non-localhost IPv4 adresses", func() {
				digArgs = "@localhost 52.0.56.138.sslip.io -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`52\.0\.56\.138\.sslip\.io\.\s+3600\s+IN\s+A\s+52\.0\.56\.138\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeA 52\.0\.56\.138\.sslip\.io\. \? 52\.0\.56\.138\n`))
			})
			It("returns a TTL of 3600, at least for the non-RFC 4193 non-localhost IPv6 addresses", func() {
				digArgs = "@localhost aaaa 2600-1f18-aaf-6900--b.sslip.io -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`2600-1f18-aaf-6900--b.sslip.io.\s+3600\s+IN\s+AAAA\s+2600:1f18:aaf:6900::b`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeAAAA 2600-1f18-aaf-6900--b\.sslip\.io\. \? 2600:1f18:aaf:6900::b\n`))
			})
		})
		When("our test is run on a machine which has IPv6", func() {
			cmd := exec.Command("ping6", "-c", "1", "::1")
			err := cmd.Run() // if the command succeeds, we have IPv6
			if err == nil {
				It("returns a TXT of the querier's IPv6 address when querying ip.sslip.io", func() {
					digCmd = exec.Command("dig", "@::1", "ip.sslip.io", "txt", "+short", "-p", strconv.Itoa(port))
					digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(digSession, 1).Should(Exit(0))
					Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`::1`))
					Eventually(serverSession.Err).Should(Say(`TypeTXT ip\.sslip\.io\. \? \["::1"\]`))
					Expect(digSession).To(Exit())
				})
			}
		})
		When("we do reverse lookups (PTR) on a random series of IPv6 addresses (fuzz testing)", func() {
			It("should succeed every time", func() {
				for i := 0; i < 50; i++ {
					addr := testhelper.RandomIPv6Address()
					digArgs = "@localhost -x " + addr.String() + " -p " + strconv.Itoa(port) + " +short"
					digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
					digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					expectedPtr := strings.ReplaceAll(addr.String(), ":", "-") + ".sslip.io."
					Eventually(digSession).Should(Say(expectedPtr))
					Eventually(digSession, 1).Should(Exit(0))
				}
			})
		})
		When("ns.sslip.io is queried", func() {
			It("returns all the A records", func() {
				digArgs = "@localhost ns.sslip.io +short -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`146.190.110.69`))
				Eventually(digSession).Should(Say(`104.155.144.4`))
				Eventually(digSession).Should(Say(`5.78.115.44`))
				Eventually(digSession).Should(Say(`51.75.53.19`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeA ns.sslip.io. \? 146.190.110.69, 104.155.144.4, 5.78.115.44, 51.75.53.19\n`))
			})
			It("returns all the AAAA records", func() {
				digArgs = "@localhost aaaa ns.sslip.io +short -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`2400:6180:0:d2:0:1:da21:d000`))
				Eventually(digSession).Should(Say(`2600:1900:4000:4d12::`))
				Eventually(digSession).Should(Say(`2a01:4ff:1f0:c920::`))
				Eventually(digSession).Should(Say(`2001:41d0:602:2313::1`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeAAAA ns.sslip.io. \? 2400:6180:0:d2:0:1:da21:d000, 2600:1900:4000:4d12::, 2a01:4ff:1f0:c920::, 2001:41d0:602:2313::1\n`))
			})
		})
		When("there are multiple MX records returned (e.g. sslip.io)", func() {
			It("returns all the records", func() {
				digArgs = "@localhost sslip.io mx +short -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`10 mail.protonmail.ch.`))
				Eventually(digSession).Should(Say(`20 mailsec.protonmail.ch.\n$`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeMX sslip.io. \? 10 mail.protonmail.ch., 20 mailsec.protonmail.ch.\n`))
			})
		})
		When("there are multiple NS records returned (e.g. almost any NS query)", func() {
			It("returns all the records", func() {
				digArgs = "@localhost example.com ns -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 8`))
				Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
				Eventually(digSession).Should(Say(`;; ADDITIONAL SECTION:`))
				Eventually(digSession).Should(Say(`ns-do-sg.sslip.io..*146.190.110.69\n`))
				Eventually(digSession).Should(Say(`ns-do-sg.sslip.io..*2400:6180:0:d2:0:1:da21:d000\n`))
				Eventually(digSession).Should(Say(`ns-gce.sslip.io..*104.155.144.4\n`))
				Eventually(digSession).Should(Say(`ns-gce.sslip.io..*2600:1900:4000:4d12::\n`))
				Eventually(digSession).Should(Say(`ns-hetzner.sslip.io..*5.78.115.44\n`))
				Eventually(digSession).Should(Say(`ns-hetzner.sslip.io..*2a01:4ff:1f0:c920::\n`))
				Eventually(digSession).Should(Say(`ns-ovh.sslip.io..*51.75.53.19\n`))
				Eventually(digSession).Should(Say(`ns-ovh.sslip.io..*2001:41d0:602:2313::1\n`))
				Eventually(digSession, 1).Should(Exit(0))
				// the server names may appear out-of-order
				Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`NS\tns-do-sg.sslip.io.\n`))
				Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`NS\tns-gce.sslip.io.\n`))
				Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`NS\tns-hetzner.sslip.io.\n`))
				Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`NS\tns-ovh.sslip.io.\n`))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeNS example.com. \? ns-do-sg.sslip.io., ns-gce.sslip.io., ns-hetzner.sslip.io., ns-ovh.sslip.io.\n`))
			})
		})
		When(`there are multiple TXT records returned (e.g. SPF for sslip.io)`, func() {
			It("returns the custom TXT records", func() {
				digArgs = "@localhost sslip.io txt +short -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26"`))
				Eventually(digSession).Should(Say(`"v=spf1 include:_spf.protonmail.ch mx ~all"`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeTXT sslip.io. \? \["protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26"\], \["v=spf1 include:_spf.protonmail.ch mx ~all"\]\n`))
			})
		})
		When(`a record for an "_acme-challenge" domain is queried`, func() {
			When(`it's an NS record`, func() {
				It(`returns the NS record of the query with the "_acme-challenge." stripped`, func() {
					digArgs = "@localhost _acme-challenge.fe80--.sslip.io ns -p " + strconv.Itoa(port)
					digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
					digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(digSession).Should(Say(`flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1`))
					Eventually(digSession).Should(Say(`;; AUTHORITY SECTION:`))
					Eventually(digSession).Should(Say(`fe80--.sslip.io.`))
					Eventually(digSession).Should(Say(`;; ADDITIONAL SECTION:`))
					Eventually(digSession).Should(Say(`fe80--.sslip.io..*fe80::\n`))
					Eventually(digSession, 1).Should(Exit(0))
					Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeNS _acme-challenge.fe80--.sslip.io. \? nil, NS fe80--.sslip.io.\n`))
				})
			})
			When(`it's a TXT record`, func() {
				It(`returns the NS record of the query with the "_acme-challenge." stripped`, func() {
					digArgs = "@localhost _acme-challenge.127-0-0-1.sslip.io txt -p " + strconv.Itoa(port)
					digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
					digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(digSession).Should(Say(`flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1,`))
					Eventually(digSession).Should(Say(`;; AUTHORITY SECTION:\n`))
					Eventually(digSession).Should(Say(`^_acme-challenge.127-0-0-1.sslip.io. 604800 IN NS 127-0-0-1.sslip.io.\n`))
					Eventually(digSession, 1).Should(Exit(0))
					Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeTXT _acme-challenge.127-0-0-1.sslip.io. \? nil, NS 127-0-0-1.sslip.io.\n`))
				})
			})
			When(`it's a A record`, func() {
				It(`returns the NS record of the query with the "_acme-challenge." stripped`, func() {
					digArgs = "@localhost _acme-challenge.127-0-0-1.sslip.io a -p " + strconv.Itoa(port)
					digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
					digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(digSession).Should(Say(`flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1,`))
					Eventually(digSession).Should(Say(`;; AUTHORITY SECTION:\n`))
					Eventually(digSession).Should(Say(`^_acme-challenge.127-0-0-1.sslip.io. 604800 IN NS 127-0-0-1.sslip.io.\n`))
					Eventually(digSession, 1).Should(Exit(0))
					Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeA _acme-challenge.127-0-0-1.sslip.io. \? nil, NS 127-0-0-1.sslip.io.\n`))
				})
			})
		})
		When(`a TXT record for an "metrics.status.sslip.io" domain is repeatedly queried`, func() {
			It("rate-limits the queries after some amount requests", func() {
				// typically ~9 milliseconds / query, ~125 queries / sec on 4-core Xeon
				var start, stop time.Time
				throttled := false
				// double the the number of queries to make sure we exhaust the channel's buffers
				for i := 0; i < xip.MetricsBufferSize*2; i++ {
					start = time.Now()
					digArgs = "@localhost metrics.status.sslip.io txt -p " + strconv.Itoa(port)
					digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
					_, err := digCmd.Output()
					Expect(err).ToNot(HaveOccurred())
					stop = time.Now()
					// we currently buffer at 250 milliseconds, so for our test we use a smidgen less because jitter
					if stop.Sub(start) > 240*time.Millisecond {
						throttled = true
						break
					}
				}
				Expect(throttled).To(BeTrue())
			})
		})
	})
	Describe(`The domain blocklist`, func() {
		DescribeTable("when queried",
			func(digArgs string, digResults string, serverLogMessage string) {
				digArgs += " -p " + strconv.Itoa(port)
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				// we want to make sure digSession has exited because we
				// want to compare the _full_ contents of the stdout in the case
				// of negative assertions (e.g. "^$")
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(digResults))
				Eventually(serverSession.Err).Should(Say(serverLogMessage))
			},
			Entry("an A record with a forbidden string on the left-hand side is redirected",
				"@localhost raiffeisen.94.228.116.140.sslip.io +short",
				`\A52.0.56.137\n\z`,
				`TypeA raiffeisen.94.228.116.140.sslip.io. \? 52.0.56.137\n$`),
			Entry("an A record with a forbidden string on the right-hand side is redirected",
				"@localhost www.94-228-116-140.raiffeisen.com +short",
				`\A52.0.56.137\n\z`,
				`TypeA www.94-228-116-140.raiffeisen.com. \? 52.0.56.137\n$`),
			Entry("an A record with a forbidden string embedded is redirected",
				"@localhost international-raiffeisen-bank.94.228.116.140.sslip.io +short",
				`\A52.0.56.137\n\z`,
				`TypeA international-raiffeisen-bank.94.228.116.140.sslip.io. \? 52.0.56.137\n$`),
			Entry("an A record with a forbidden string with a private IP is not redirected",
				"@localhost raiffeisen.192.168.0.20.sslip.io +short",
				`\A192.168.0.20\n\z`,
				`TypeA raiffeisen.192.168.0.20.sslip.io. \? 192.168.0.20\n$`),
			Entry("an AAAA record with a forbidden string is redirected",
				"@localhost international-raiffeisen-bank.2600--.sslip.io aaaa +short",
				`\A2600:1f18:aaf:6900::a\n\z`,
				`TypeAAAA international-raiffeisen-bank.2600--.sslip.io. \? 2600:1f18:aaf:6900::a\n$`),
			Entry("an AAAA record with a forbidden string with a private IP is NOT redirected",
				"@localhost international-raiffeisen-bank.fc00--.sslip.io aaaa +short",
				`\Afc00::\n\z`,
				`TypeAAAA international-raiffeisen-bank.fc00--.sslip.io. \? fc00::\n$`),
			// use regex to account for rotated nameserver order
			Entry("an NS record with acme_challenge with a forbidden string is not delegated",
				"@localhost _acme-challenge.raiffeisen.fe80--.sslip.io ns +short",
				`\Ans-[a-z-]+.sslip.io.\nns-[a-z-]+.sslip.io.\nns-[a-z-]+.sslip.io.\nns-[a-z-]+.sslip.io.\n\z`,
				`TypeNS _acme-challenge.raiffeisen.fe80--.sslip.io. \? ns-do-sg.sslip.io., ns-gce.sslip.io., ns-hetzner.sslip.io., ns-ovh.sslip.io.\n$`),
			Entry("an A record with a forbidden CIDR is redirected",
				"@localhost nf.43.134.66.67.sslip.io +short",
				`\A52.0.56.137\n\z`,
				`TypeA nf.43.134.66.67.sslip.io. \? 52.0.56.137\n$`),
			Entry("an AAAA record with a forbidden CIDR is redirected",
				"@localhost 2601-646-100-69f7-cafe-bebe-cafe-baba.sslip.io aaaa +short",
				`\A2600:1f18:aaf:6900::a\n\z`,
				`TypeAAAA 2601-646-100-69f7-cafe-bebe-cafe-baba.sslip.io. \? 2600:1f18:aaf:6900::a\n$`),
		)
	})
	When("it can't bind to any UDP port", func() {
		It("prints an error message and exits", func() {
			Expect(err).ToNot(HaveOccurred())
			secondServerCmd := exec.Command(serverPath, "-port", strconv.Itoa(port), "-blocklistURL", "file://etc/blocklist-test.txt")
			secondServerSession, err := Start(secondServerCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(secondServerSession.Err, 10).Should(Say("I couldn't bind via UDP to any IPs"))
			Eventually(secondServerSession).Should(Exit(1))
		})
	})
	When("it can't bind to any TCP port", func() {
		var squatters []net.Listener
		var newPort = getFreePort() // I need a new free port to bind on because a server is running on the old port
		BeforeEach(func() {
			squatters, err = squatOnTcp(newPort)
			Expect(err).ToNot(HaveOccurred())
		})
		AfterEach(func() {
			for _, squatter := range squatters {
				err = squatter.Close()
				Expect(err).ToNot(HaveOccurred())
			}
		})
		It("prints an error message and continues running", func() {
			Expect(err).ToNot(HaveOccurred())
			secondServerCmd := exec.Command(serverPath, "-port", strconv.Itoa(newPort), "-blocklistURL", "file://etc/blocklist-test.txt")
			secondServerSession, err := Start(secondServerCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(secondServerSession.Err, 10).Should(Say(` version \d+\.\d+\.\d+ starting`))
			Eventually(secondServerSession.Err, 10).Should(Say(`I couldn't bind via TCP to "\[::\]:\d+" \(INADDR_ANY, all interfaces\), so I'll try to bind to each address individually.`))
			Eventually(secondServerSession.Err, 10).Should(Say("I couldn't bind via TCP to any IPs"))
			Eventually(secondServerSession.Err, 10).Should(Say("Ready to answer queries"))
			secondServerSession.Terminate()
			Eventually(secondServerSession).Should(Exit())
		})
	})
	When("it can't bind via UDP to the loopback address", func() {
		var newPort = getFreePort() // I need a new free port to bind on because the server has already bound to the old port
		var squatter *net.UDPConn
		BeforeEach(func() {
			squatter, err = squatOnUdpLoopbackPort(newPort)
			Expect(err).ToNot(HaveOccurred())
		})
		It("prints an informative message and binds to the addresses it can", func() {
			Expect(err).ToNot(HaveOccurred())
			secondServerCmd := exec.Command(serverPath, "-port", strconv.Itoa(newPort), "-blocklistURL", "file://etc/blocklist-test.txt")
			secondServerSession, err := Start(secondServerCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(secondServerSession.Err, 10).Should(Say(` version \d+\.\d+\.\d+ starting`))
			Eventually(secondServerSession.Err, 10).Should(Say(`I couldn't bind via UDP to "\[::\]:\d+" \(INADDR_ANY, all interfaces\), so I'll try to bind to each address individually.`))
			Eventually(secondServerSession.Err, 10).Should(Say(`I couldn't bind via UDP to the following IPs:.* "(::1|127\.0\.0\.1)"`))
			err = squatter.Close()
			Expect(err).ToNot(HaveOccurred())
			Eventually(secondServerSession.Err, 10).Should(Say("Ready to answer queries"))
			secondServerSession.Terminate()
			Eventually(secondServerSession).Should(Exit())
		})
	})
	When("it can't bind via TCP to the loopback address", func() {
		var newPort = getFreePort() // I need a new free port to bind on because the server has already bound to the old port
		var squatters []net.Listener
		BeforeEach(func() {
			squatters = squatOnTcpLoopback(newPort)
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
		})
		It("prints an informative message and binds to the addresses it can", func() {
			Expect(err).ToNot(HaveOccurred())
			secondServerCmd := exec.Command(serverPath, "-port", strconv.Itoa(newPort), "-blocklistURL", "file://etc/blocklist-test.txt")
			secondServerSession, err := Start(secondServerCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(secondServerSession.Err, 10).Should(Say(` version \d+\.\d+\.\d+ starting`))
			Eventually(secondServerSession.Err, 10).Should(Say(`I couldn't bind via TCP to "\[::\]:\d+" \(INADDR_ANY, all interfaces\), so I'll try to bind to each address individually.`))
			Eventually(secondServerSession.Err, 10).Should(Say(`I couldn't bind via TCP to the following IPs:.* "(::1|127\.0\.0\.1)"`))
			for _, squatter := range squatters {
				err = squatter.Close()
				Expect(err).ToNot(HaveOccurred())
			}
			Eventually(secondServerSession.Err, 10).Should(Say("Ready to answer queries"))
			secondServerSession.Terminate()
			Eventually(secondServerSession).Should(Exit())
		})
	})
})

func squatOnUdpLoopbackPort(port int) (squatter *net.UDPConn, err error) {
	// try IPv6's loopback
	udpAddr := net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: port,
	}
	squatter, err = net.ListenUDP("udp", &udpAddr)
	if err != nil {
		// try IPv4's loopback
		udpAddr = net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: port,
		}
		squatter, err = net.ListenUDP("udp", &udpAddr)
	}
	return squatter, err
}

func squatOnTcpLoopback(port int) (squatters []net.Listener) {
	var addrsToBind = []string{"[::1]", "127.0.0.1"}
	// Get the GOOS environment variable to determine the operating system.
	goos := strings.ToLower(runtime.GOOS)
	if goos == "darwin" {
		// macOS needs to bind to _all_ interfaces as well; don't know why
		addrsToBind = append([]string{"[::]"}, addrsToBind...)
	}
	// try to bind to both IPv4 and IPv6's loopback
	for _, addr := range addrsToBind {
		addrPort := addr + ":" + strconv.Itoa(port)
		squatter, err := net.Listen("tcp", addrPort)
		if err != nil {
			continue // probably
		}
		squatters = append(squatters, squatter)
	}
	return squatters
}

// squatOnTcp(port) makes any subsequent attempt to bind to that port to fail, for testing purposes
func squatOnTcp(port int) (squatters []net.Listener, err error) {
	/*
		on macOS, not only do I need to listen on ALL addresses, but I also
		need to listen to addresses individually. This isn't the case with Linux.
		On a typical macOS dual-stack machine, I'll be able to create ~7 Listeners
		(INADDR_ANY, 2 loopback, 1 IPv4, 3 IPv6)
	*/
	var squatter net.Listener
	squatter, err = net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		//log.Println(err.Error())
	} else {
		squatters = append(squatters, squatter)
	}
	addrCIDRs, err := net.InterfaceAddrs() // typical addrCIDR "10.9.9.161/24"
	ipv6regex := regexp.MustCompile(`:`)
	for _, addrCIDR := range addrCIDRs {
		ip, _, err := net.ParseCIDR(addrCIDR.String())
		if err != nil {
			return squatters, err
		}
		ipv6 := ipv6regex.MatchString(addrCIDR.String())
		// accommodate IPv6's requirements for brackets: "[::1]:1024" vs "127.0.0.1:1024"
		if ipv6 {
			squatter, err = net.Listen("tcp", "["+ip.String()+"]"+":"+strconv.Itoa(port))
			//log.Println("[" + ip.String() + "]" + ":" + strconv.Itoa(port))
			if err != nil {
				//log.Println(err.Error())
				// ignore errors on IPv6 bind attempts; it's probably a link-local, which needs a scope
				// https://stackoverflow.com/questions/2455762/why-cant-i-bind-ipv6-socket-to-a-linklocal-address
				continue
			}
		} else {
			squatter, err = net.Listen("tcp", ip.String()+":"+strconv.Itoa(port))
			//log.Println(ip.String() + ":" + strconv.Itoa(port))
			if err != nil {
				//log.Println(err.Error())
				continue
			}
		}
		squatters = append(squatters, squatter)
	}
	//log.Println(len(squatters))
	return squatters, err
}

// getFreePort should always succeed unless something awful has happened, e.g. port exhaustion
func getFreePort() int {
	// we use a time-based seed to generate a random port to avoid collisions in our test
	// we also bind for a millisecond (in `isPortFree()` to make sure we don't collide
	// with another test running in parallel
	listenPort := (time.Now().Nanosecond() % (65536 - 1024)) + 1023
	for {
		listenPort += 1
		switch {
		case listenPort > 65535:
			listenPort = 1023 // we've reached the highest port, start over
			// 1024 (lowest unprivileged port) - 1 (immediately incremented)
		case isPortFree(listenPort):
			return listenPort
		}
	}
}

func isPortFree(port int) bool {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return false
	}
	// we must Sleep() in order to avoid a race condition when tests
	// are run in parallel (`ginkgo -p`) and the `ListenUDP()` and `Close()`
	// we sleep for a millisecond because the port is randomized based on the millisecond.
	time.Sleep(1 * time.Millisecond)
	err = conn.Close()
	if err != nil {
		log.Printf("I couldn't close port %d", port)
		return false
	}
	return true
}
