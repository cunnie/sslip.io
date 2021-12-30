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
		// TODO: bind to unprivileged port (NOT 53) for non-macOS users (e.g. port 35353)
		Expect(err).ToNot(HaveOccurred())
		// takes 0.455s to start up on macOS Big Sur 3.7 GHz Quad Core 22-nm Xeon E5-1620v2 processor (2013 Mac Pro)
		// takes 1.312s to start up on macOS Big Sur 2.0GHz quad-core 10th-generation Intel Core i5 processor (2020 13" MacBook Pro)
		// round up to 3 seconds to account for slow machines
		time.Sleep(3 * time.Second) // takes 0.455s to start up on macOS Big Sur 4-core Xeon
	})

	AfterSuite(func() {
		serverSession.Terminate()
		Eventually(serverSession).Should(Exit())
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
				`TypeA example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
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
				`TypeAAAA example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
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
				`TypeCNAME example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
			Entry("MX for example.com",
				"@localhost example.com mx +short",
				`\A0 example.com.\n\z`,
				`TypeMX example.com. \? 0 example.com.\n$`),
			Entry("SOA for sslip.io",
				"@localhost sslip.io soa +short",
				`\Asslip.io. briancunnie.gmail.com. 2021080200 900 900 1800 300\n\z`,
				`TypeSOA sslip.io. \? sslip.io. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
			Entry("SOA for example.com",
				"@localhost example.com soa +short",
				`\Aexample.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n\z`,
				`TypeSOA example.com. \? example.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
			Entry("SRV (or other record that we don't implement) for example.com",
				"@localhost example.com srv +short",
				`\A\z`,
				`TypeSRV example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
			Entry(`TXT for version.sslip.io is the version number of the xip software (which gets overwritten during linking)`,
				"@127.0.0.1 version.sslip.io txt +short",
				`\A"dev"\n"today"\n"xxx"\n\z`,
				`TypeTXT version.sslip.io. \? \["dev"\], \["today"\], \["xxx"\]`),
			Entry(`TXT is the querier's IPv4 address and the domain "ip.sslip.io"`,
				"@127.0.0.1 ip.sslip.io txt +short",
				`127.0.0.1`,
				`TypeTXT ip.sslip.io. \? \["127.0.0.1"\]`),
			Entry(`TXT is the querier's IPv4 address and the domain is NOT "ip.sslip.io"`,
				"@127.0.0.1 example.com txt +short",
				`\A\z`,
				`TypeTXT example.com. \? nil, SOA example.com. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
			Entry(`getting a non-existent value: TXT for my-key.k-v.io"`,
				"@127.0.0.1 my-key.k-v.io txt +short",
				`\A\z`,
				`TypeTXT my-key.k-v.io. \? nil, SOA my-key.k-v.io. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
			Entry(`putting a value: TXT for put.MyValue.MY-KEY.k-v.io"`,
				"@127.0.0.1 put.MyValue.MY-KEY.k-v.io txt +short",
				`"MyValue"`,
				`TypeTXT put.MyValue.MY-KEY.k-v.io. \? \["MyValue"\]`),
			Entry(`getting a value: TXT for my-key.k-v.io"`,
				"@127.0.0.1 my-key.k-v.io txt +short",
				`"MyValue"`,
				`TypeTXT my-key.k-v.io. \? \["MyValue"\]`),
			Entry(`deleting a value: TXT for delete.my-key.k-v.io"`,
				"@127.0.0.1 delete.my-key.k-v.io txt +short",
				`"MyValue"`,
				`TypeTXT delete.my-key.k-v.io. \? \["MyValue"\]`),
			Entry(`getting a non-existent value: TXT for my-key.k-v.io"`,
				"@127.0.0.1 my-key.k-v.io txt +short",
				`\A\z`,
				`TypeTXT my-key.k-v.io. \? nil, SOA my-key.k-v.io. briancunnie.gmail.com. 2021080200 900 900 1800 300\n$`),
		)
	})
	Describe("for more complex assertions", func() {
		When("our test is run on a machine which has IPv6", func() {
			cmd := exec.Command("ping6", "-c", "1", "::1")
			err := cmd.Run() // if the command succeeds, we have IPv6
			if err == nil {
				It("returns a TXT of the querier's IPv6 address when querying ip.sslip.io", func() {
					digCmd = exec.Command("dig", "@::1", "ip.sslip.io", "txt", "+short")
					digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(digSession, 1).Should(Exit(0))
					Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`::1`))
					Eventually(serverSession.Err).Should(Say(`TypeTXT ip\.sslip\.io\. \? \["::1"\]`))
					Expect(digSession).To(Exit())
				})
			}
		})
		When("ns.sslip.io is queried", func() {
			It("returns all the A records", func() {
				digArgs = "@localhost ns.sslip.io +short"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`52.0.56.137`))
				Eventually(digSession).Should(Say(`52.187.42.158`))
				Eventually(digSession).Should(Say(`104.155.144.4`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeA ns.sslip.io. \? 52.0.56.137, 52.187.42.158, 104.155.144.4\n`))
			})
			It("returns all the AAAA records", func() {
				digArgs = "@localhost aaaa ns.sslip.io +short"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`2600:1f18:aaf:6900::a`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeAAAA ns.sslip.io. \? 2600:1f18:aaf:6900::a\n`))
			})
		})
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
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 4`))
				Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
				Eventually(digSession).Should(Say(`ns-aws.sslip.io.\n`))
				Eventually(digSession).Should(Say(`ns-azure.sslip.io.\n`))
				Eventually(digSession).Should(Say(`ns-gce.sslip.io.\n`))
				Eventually(digSession).Should(Say(`;; ADDITIONAL SECTION:`))
				Eventually(digSession).Should(Say(`ns-aws.sslip.io..*52.0.56.137\n`))
				Eventually(digSession).Should(Say(`ns-aws.sslip.io..*2600:1f18:aaf:6900::a\n`))
				Eventually(digSession).Should(Say(`ns-azure.sslip.io..*52.187.42.158\n`))
				Eventually(digSession).Should(Say(`ns-gce.sslip.io..*104.155.144.4\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeNS example.com. \? ns-aws.sslip.io., ns-azure.sslip.io., ns-gce.sslip.io.\n`))
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
		When(`a TXT record for a host under the "k-v.io" domain is queried`, func() {
			It(`the PUT has a three-minute TTL`, func() {
				digArgs = "@localhost put.a.b.k-v.io txt"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`put.a.b.k-v.io.		180	IN	TXT	"a"`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeTXT put.a.b.k-v.io. \? \["a"\]`))
			})
			It(`the GET has a three-minute TTL`, func() {
				digArgs = "@localhost b.k-v.io txt"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`b.k-v.io.		180	IN	TXT	"a"`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeTXT b.k-v.io. \? \["a"\]`))
			})
			It(`the DELETE has a three-minute TTL`, func() {
				digArgs = "@localhost delete.b.k-v.io txt"
				digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`delete.b.k-v.io.	180	IN	TXT	"a"`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeTXT delete.b.k-v.io. \? \["a"\]`))
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
