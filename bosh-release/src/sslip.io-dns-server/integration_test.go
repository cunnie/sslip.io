package main_test

import (
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("sslip.io-dns-server", func() {
	//var stdin io.WriteCloser
	var err error
	var serverCmd *exec.Cmd
	var serverSession *Session
	var digCmd *exec.Cmd
	var digSession *Session
	var digArgs string

	BeforeSuite(func() {
		serverPath, err := Build("main.go")
		Expect(err).ToNot(HaveOccurred())
		serverCmd = exec.Command(serverPath)
		serverSession, err = Start(serverCmd, GinkgoWriter, GinkgoWriter)
		// If you get a "listen udp :53: bind: address already in use" and you're on Linux, enter
		// "sudo systemctl sudo systemctl stop systemd-resolved" and then try again
		// TODO: bind to unprivileged port (NOT 53) for non-macOS users (e.g. port 35353)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(455 * time.Millisecond) // takes 0.455s to start up on macOS Big Sur 4-core Xeon
	})

	AfterSuite(func() {
		serverSession.Terminate()
		Eventually(serverSession).Should(Exit())
	})

	JustBeforeEach(func() {
		args := strings.Split(digArgs, " ")
		digCmd = exec.Command("dig", args...)
		digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Integration tests", func() {
		DescribeTable("when the DNS server is queried",
			func(digArgs string, digResults string, serverLogMessage string) {
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
			Entry("A (customized) for sslip.io",
				"@localhost sslip.io +short",
				`\A78.46.204.247\n\z`,
				`TypeA sslip.io. \? 78.46.204.247\n$`),
			Entry("A (or lack thereof) for example.com",
				"@localhost example.com +short",
				`\A\z`,
				`TypeA example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
			Entry("A for www-127-0-0-1.sslip.io",
				"@localhost www-127-0-0-1.sslip.io +short",
				`\A127.0.0.1\n\z`,
				`TypeA www-127-0-0-1.sslip.io. \? 127.0.0.1\n$`),
			Entry("A for www.192.168.0.1.sslip.io",
				"@localhost www.192.168.0.1.sslip.io +short",
				`\A192.168.0.1\n\z`,
				`TypeA www.192.168.0.1.sslip.io. \? 192.168.0.1\n$`),
			Entry("AAAA (customized) for sslip.io",
				"@localhost sslip.io aaaa +short",
				`\A2a01:4f8:c17:b8f::2\n\z`,
				`TypeAAAA sslip.io. \? 2a01:4f8:c17:b8f::2\n$`),
			Entry("AAAA not found for example.com",
				"@localhost example.com aaaa +short",
				`\A\z`,
				`TypeAAAA example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
			Entry("AAAA for www-2601-646-100-69f0-1c09-bae7-aa42-146c.sslip.io",
				"@localhost www-2601-646-100-69f0-1c09-bae7-aa42-146c.sslip.io aaaa +short",
				`\A2601:646:100:69f0:1c09:bae7:aa42:146c\n\z`,
				`TypeAAAA www-2601-646-100-69f0-1c09-bae7-aa42-146c.sslip.io. \? 2601:646:100:69f0:1c09:bae7:aa42:146c\n$`),
			Entry("ALL (ANY) is NOT implemented",
				// `+notcp` required for dig 9.11.25-RedHat-9.11.25-2.fc32 to avoid "connection refused"
				"@localhost sslip.io any +notcp",
				` status: NOTIMP,`,
				`TypeALL sslip.io. \? NotImplemented\n$`),
			Entry("CNAME (customized) for protonmail._domainkey.sslip.io",
				"@localhost protonmail._domainkey.sslip.io cname +short",
				`\Aprotonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.\n\z`,
				`TypeCNAME protonmail._domainkey.sslip.io. \? protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.\n$`),
			Entry("CNAME not found for example.com",
				"@localhost example.com cname +short",
				`\A\z`,
				`TypeCNAME example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
			Entry("MX for example.com",
				"@localhost example.com mx +short",
				`\A0 example.com.\n\z`,
				`TypeMX example.com. \? 0 example.com.\n$`),
			Entry("SOA for sslip.io",
				"@localhost sslip.io soa +short",
				`\Asslip.io. briancunnie.gmail.com. 2021011400 900 900 1800 300\n\z`,
				`TypeSOA sslip.io. \? sslip.io. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
			Entry("SOA for example.com",
				"@localhost example.com soa +short",
				`\Aexample.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n\z`,
				`TypeSOA example.com. \? example.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
			Entry("SRV (or other record that we don't implement) for example.com",
				"@localhost example.com srv +short",
				`\A\z`,
				`TypeSRV example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
			Entry("TXT not found for example.com",
				"@localhost example.com txt +short",
				`\A\z`,
				`TypeTXT example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021011400 900 900 1800 300\n$`),
		)
	})
	Describe("for more complex assertions", func() {
		When("there are multiple MX records returned (e.g. sslip.io)", func() {
			It("returns all the records", func() {
				digArgs = "@localhost sslip.io mx +short"
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
				digArgs = "@localhost example.com ns"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 3`))
				Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
				Eventually(digSession).Should(Say(`ns-aws.nono.io.\n`))
				Eventually(digSession).Should(Say(`ns-azure.nono.io.\n`))
				Eventually(digSession).Should(Say(`ns-gce.nono.io.\n`))
				Eventually(digSession).Should(Say(`;; ADDITIONAL SECTION:`))
				Eventually(digSession).Should(Say(`ns-aws.nono.io..*52.0.56.137\n`))
				Eventually(digSession).Should(Say(`ns-azure.nono.io..*52.187.42.158\n`))
				Eventually(digSession).Should(Say(`ns-gce.nono.io..*104.155.144.4\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeNS example.com. \? ns-aws.nono.io., ns-azure.nono.io., ns-gce.nono.io.\n`))
			})
		})
		When(`there are multiple TXT records returned (e.g. SPF for sslip.io)`, func() {
			It("returns the custom TXT records", func() {
				digArgs = "@localhost sslip.io txt +short"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26"`))
				Eventually(digSession).Should(Say(`"v=spf1 include:_spf.protonmail.ch mx ~all"`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeTXT sslip.io. \? \["protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26"\], \["v=spf1 include:_spf.protonmail.ch mx ~all"\]\n`))
			})
		})
		When(`there are multiple TXT records returned (e.g. SPF for sslip.io)`, func() {
			It("returns the custom TXT records", func() {
				digArgs = "@localhost sslip.io txt +short"
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
					digArgs = "@localhost _acme-challenge.fe80--.sslip.io ns"
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
					digArgs = "@localhost _acme-challenge.127-0-0-1.sslip.io txt"
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
					digArgs = "@localhost _acme-challenge.127-0-0-1.sslip.io a"
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
	})
})
