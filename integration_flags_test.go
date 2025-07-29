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

var _ = Describe("flags", func() {
	var serverCmd *exec.Cmd
	var serverSession *Session
	var port = getFreePort()
	var flags []string

	JustBeforeEach(func() {
		flags = append(flags, "-port", strconv.Itoa(port), "-blocklistURL", "file://etc/blocklist-test.txt")
		serverCmd = exec.Command(serverPath, flags...)
		serverSession, err = Start(serverCmd, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
		// takes 0.455s to start up on macOS Big Sur 3.7 GHz Quad Core 22-nm Xeon E5-1620v2 processor (2013 Mac Pro)
		// takes 1.312s to start up on macOS Big Sur 2.0GHz quad-core 10th-generation Intel Core i5 processor (2020 13" MacBook Pro)
		// 10 seconds should be long enough for slow container-on-a-VM-with-shared-core
		Eventually(serverSession.Err, 10).Should(Say("Ready to answer queries"))
	})
	AfterEach(func() {
		serverSession.Terminate()
		Eventually(serverSession).Should(Exit())
	})
	When("-nameservers is set", func() {
		BeforeEach(func() {
			flags = []string{"-nameservers=mickey.minnie.,daffy.duck"}
		})
		It("returns all the NS records, appending dots as needed", func() {
			digArgs := "@localhost example.com ns -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0`))
			Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`mickey.minnie.\n`))
			Eventually(string(digSession.Out.Contents())).Should(MatchRegexp(`daffy.duck.\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding nameserver "mickey\.minnie\."\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding nameserver "daffy\.duck\."\n`))
			// we don't know the order in which the nameservers will be returned, so we try both
			Eventually(string(serverSession.Err.Contents())).Should(Or(MatchRegexp(`TypeNS example.com. \? mickey\.minnie\., daffy\.duck\.\n`), MatchRegexp(`TypeNS example.com. \? daffy\.duck\., mickey\.minnie\.\n`)))
		})
		When("a nameserver is an empty string", func() {
			BeforeEach(func() {
				flags = []string{"-nameservers="}
			})
			It("should message that it's skipping that nameserver and continue", func() {
				Expect(string(serverSession.Err.Contents())).Should(MatchRegexp(`-nameservers: ignoring zero-length nameserver ""`))
			})
		})
		When("a nameserver is too long (>255 chars)", func() {
			var tooLongDomainName = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789" +
				"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789" +
				"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789" +
				"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789"

			BeforeEach(func() {
				flags = []string{"-nameservers=" + tooLongDomainName}
			})
			It("should message that it's skipping that nameserver and continue", func() {
				Expect(string(serverSession.Err.Contents())).Should(MatchRegexp(`-nameservers: ignoring invalid nameserver "` + tooLongDomainName))
			})
		})
	})
	When("-addresses is set", func() {
		BeforeEach(func() {
			flags = []string{"-addresses=a.b.c=1.2.3.4,a.b.c=5.6.7.8,a.b.c=2600::"}
		})
		It("returns the addresses when the A records of the hostnames are queried", func() {
			digArgs := "@localhost a.b.c A -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0`))
			Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
			Eventually(digSession).Should(Say(`1.2.3.4\n`))
			Eventually(digSession).Should(Say(`5.6.7.8\n`))
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding record "a.b.c.=1.2.3.4"\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding record "a.b.c.=5.6.7.8"\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding record "a.b.c.=2600::"\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeA a\.b\.c\. \? 1\.2\.3\.4, 5\.6\.7\.8\n`))
		})
		It("returns the addresses when the AAAA records of the hostnames are queried", func() {
			digArgs := "@localhost a.b.c AAAA -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
			Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
			Eventually(digSession).Should(Say(`2600::\n`))
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeAAAA a\.b\.c\. \? 2600::\n`))
		})
		When(`addresses don't include an "="`, func() {
			BeforeEach(func() {
				flags = []string{"-addresses=a.b.c"}
			})
			It("should message that it's skipping that address and continue", func() {
				Expect(string(serverSession.Err.Contents())).Should(MatchRegexp(`-addresses: arguments should be in the format "host=ip", not "a.b.c"`))
			})
		})
	})
	When("-quiet is set", func() {
		BeforeEach(func() {
			flags = []string{"-quiet"}
		})
		It("doesn't print out log messages so that GCP doesn't charge $17/mo for storing them", func() {
			digArgs := "@localhost 169.254.169.254 -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(Not(MatchRegexp(`169\.254\.169\.254`)))
		})
	})
	When("-public is set to false", func() {
		BeforeEach(func() {
			flags = []string{"-public=false"}
		})
		It("doesn't resolve public IPv4 addresses", func() {
			digArgs := "@localhost 8-8-8-8.sslip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`\? nil, SOA 8-8-8-8\.sslip\.io\. briancunnie\.gmail\.com\.`))
		})
		It("doesn't resolve public IPv6 addresses", func() {
			digArgs := "@localhost aaaa 2600--.sslip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`\? nil, SOA 2600--\.sslip\.io\. briancunnie\.gmail\.com\.`))
		})
		It("doesn't resolve public IPv4 addresses (hexadecimal)", func() {
			digArgs := "@localhost 08080808.nip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`\? nil, SOA 08080808\.nip\.io\. briancunnie\.gmail\.com\.`))
		})
		It("doesn't resolve public IPv6 addresses (hexadecimal)", func() {
			digArgs := "@localhost aaaa 26010646010069f0042c6ab3cdd9e562.nip.io -p " + strconv.Itoa(port) // my laptop's IPv6 address
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`\? nil, SOA 26010646010069f0042c6ab3cdd9e562\.nip\.io\. briancunnie\.gmail\.com\.`))
		})
		It("resolves private IPv4 addresses", func() {
			digArgs := "@localhost 192-168-0-1.sslip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`192-168-0-1\.sslip\.io\. \? 192\.168\.0\.1`))
		})
		It("resolves private IPv6 addresses", func() {
			digArgs := "@localhost aaaa fc00--.sslip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`fc00--\.sslip\.io\. \? fc00::`))
		})
		It("resolves private IPv4 addresses (hexadecimal)", func() {
			digArgs := "@localhost 7f000001.nip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeA 7f000001.nip.io. \? 127.0.0.1`))
		})
		It("resolves private IPv6 addresses (hexadecimal)", func() {
			digArgs := "@localhost aaaa 00000000000000000000000000000001.nip.io -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeAAAA 00000000000000000000000000000001.nip.io. \? ::1`))
		})
	})
	When("-delegates is set", func() {
		BeforeEach(func() {
			flags = []string{"-delegates=" +
				"_acme-challenge.127-0-0-1.IP.io=ns.nono.io," +
				"2600--.IP.IO=ns-1.nono.com," +
				"_acme-challenge.73-189-219-4.ip.IO=ns-2.nono.com," +
				"a.b.C=d.E.f"}
		})
		When("the arguments are missing", func() {
			BeforeEach(func() {
				flags = []string{"-delegates="}
			})
			It("should give an informative message", func() {
				Expect(string(serverSession.Err.Contents())).Should(Not(MatchRegexp(`-delegates`)))
			})
		})
		When("the arguments are mangled", func() {
			BeforeEach(func() {
				flags = []string{"-delegates=blahblah"}
			})
			It("should give an informative message", func() {
				Expect(string(serverSession.Err.Contents())).Should(MatchRegexp(`-delegates: arguments should be in the format "delegatedDomain=nameserver", not "blahblah"`))
			})
		})
		When("only some of the arguments are mangled", func() {
			BeforeEach(func() {
				flags = []string{"-delegates=a.b=c.d,blahblah"}
			})
			It("adds the correct ones, gives an informative message for the mangled ones", func() {
				Expect(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding delegated NS record "a.b.=c.d."`))
				Expect(string(serverSession.Err.Contents())).Should(MatchRegexp(`-delegates: arguments should be in the format "delegatedDomain=nameserver", not "blahblah"`))
			})
		})
		When("looking up a delegated domain", func() {
			It("should return a non-authoritative NS record pointing to the nameserver", func() {
				digArgs := "@localhost _acme-challenge.127-0-0-1.IP.io -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`;; AUTHORITY SECTION:`))
				Eventually(digSession).Should(Say(`_acme-challenge.127-0-0-1.IP.io. 604800	IN NS	ns.nono.io.\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`_acme-challenge\.127-0-0-1\.IP\.io\. \? nil, NS ns\.nono\.io\.`))
			})
		})
		When("looking up the subdomain of a delegated domain", func() {
			It("should return a non-authoritative NS record pointing to the nameserver", func() {
				digArgs := "@localhost subdomain.2600--.IP.IO -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`;; AUTHORITY SECTION:`))
				Eventually(digSession).Should(Say(`subdomain.2600--.IP.IO.	604800	IN	NS	ns-1.nono.com.\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`subdomain\.2600--\.IP\.IO\. \? nil, NS ns-1\.nono\.com\.`))
			})
		})
		When("looking up a delegated domain that wouldn't have resolved to an IP address", func() {
			It("it delegates", func() {
				digArgs := "@localhost a.b.c -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`;; AUTHORITY SECTION:`))
				Eventually(digSession).Should(Say(`a.b.c.			604800	IN	NS	d.e.f.`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`a\.b\.c\. \? nil, NS d\.e\.f\.`))
			})
		})
	})
	When("-ptr-domain is set", func() {
		When("doing a reverse-lookup of an IPv4 address", func() {
			BeforeEach(func() {
				flags = []string{"-ptr-domain=" + "hp.com."}
			})
			It("should return the PTR record with the 'hp.com.' domain", func() {
				digArgs := "@localhost -x 127.0.0.2 -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`2.0.0.127.in-addr.arpa.	604800	IN	PTR	127-0-0-2.hp.com.`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypePTR 2\.0\.0\.127\.in-addr\.arpa\. \? 127-0-0-2\.hp\.com\.`))
			})
		})
		When("the PTR domain is set without a trailing dot", func() {
			BeforeEach(func() {
				flags = []string{"-ptr-domain=" + "ibm.com"}
			})
			It("should return the PTR record with the 'ibm.com.' domain", func() {
				digArgs := "@localhost -x 127.0.0.3 -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`3.0.0.127.in-addr.arpa.	604800	IN	PTR	127-0-0-3.ibm.com.`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypePTR 3\.0\.0\.127\.in-addr\.arpa\. \? 127-0-0-3\.ibm\.com\.`))
			})
		})
		When("the PTR domain is a mere '.'", func() {
			BeforeEach(func() {
				flags = []string{"-ptr-domain=" + "."}
			})
			It("should return the PTR record with the '.' domain (no double-dot, '..')", func() {
				digArgs := "@localhost -x 127.0.0.4 -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`4.0.0.127.in-addr.arpa.	604800	IN	PTR	127-0-0-4.\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypePTR 4\.0\.0\.127\.in-addr\.arpa\. \? 127-0-0-4\.\n`))
			})
		})
		When("the PTR domain is an empty string", func() {
			BeforeEach(func() {
				flags = []string{"-ptr-domain="}
			})
			It("should return the PTR record with the '.' domain", func() {
				digArgs := "@localhost -x 127.0.0.5 -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`5.0.0.127.in-addr.arpa.	604800	IN	PTR	127-0-0-5.\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypePTR 5\.0\.0\.127\.in-addr\.arpa\. \? 127-0-0-5\.\n`))
			})
		})
		When("the PTR record queried is IPv6", func() {
			BeforeEach(func() {
				flags = []string{}
			})
			It("should return the PTR record with the 'nip.io.' domain", func() {
				digArgs := "@localhost -x 2601:646:100:69f0:8ab:8f21:27de:5375 -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`5.7.3.5.e.d.7.2.1.2.f.8.b.a.8.0.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. 604800 IN PTR	2601-646-100-69f0-8ab-8f21-27de-5375.nip.io.\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypePTR 5.7.3.5.e.d.7.2.1.2.f.8.b.a.8.0.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. \? 2601-646-100-69f0-8ab-8f21-27de-5375.nip.io.\n`))
			})
		})
		When("the PTR domain is set and the PTR record queried is IPv6", func() {
			BeforeEach(func() {
				flags = []string{"-ptr-domain=att.com"}
			})
			It("should return the PTR record with the 'nip.io.' domain", func() {
				digArgs := "@localhost -x 2601:646:100:69f0:8ab:8f21:27de:5375 -p " + strconv.Itoa(port)
				digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
				digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`))
				Eventually(digSession).Should(Say(`5.7.3.5.e.d.7.2.1.2.f.8.b.a.8.0.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. 604800 IN PTR	2601-646-100-69f0-8ab-8f21-27de-5375.att.com.\n`))
				Eventually(digSession, 1).Should(Exit(0))
				Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypePTR 5.7.3.5.e.d.7.2.1.2.f.8.b.a.8.0.0.f.9.6.0.0.1.0.6.4.6.0.1.0.6.2.ip6.arpa. \? 2601-646-100-69f0-8ab-8f21-27de-5375.att.com.\n`))
			})
		})
	})
})
