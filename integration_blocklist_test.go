package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

// These hostnames encode both an IPv4 address and an IPv6 address, e.g.
// "127.0.0.1--1.nip.io" is both 127.0.0.1 and 1::1. Only the address family
// matching the query type should be checked against the blocklist.
//
// "_acme-challenge" names are normally delegated to the name with the
// "_acme-challenge." stripped, but not when either address is blocked: we
// don't want to help a phishing site get a TLS certificate.
var _ = Describe("a blocklist containing 127.0.0.1 and 2600::1", Ordered, func() {
	var blocklistServerSession *Session
	var blocklistPort = getFreePort()

	BeforeAll(func() {
		blocklistPath := filepath.Join(GinkgoT().TempDir(), "blocklist.txt")
		Expect(os.WriteFile(blocklistPath, []byte("127.0.0.1\n2600::1\n"), 0644)).To(Succeed())

		blocklistServerCmd := exec.Command(serverPath,
			"-port", strconv.Itoa(blocklistPort),
			"-blocklistURL", "file://"+blocklistPath,
			"-nameservers", defaultNameservers,
			// the AAAA redirect address makes a wrongly-blocked AAAA query visible
			"-addresses", "blocked.nip.io=10.9.9.30,blocked.nip.io=2001:db8::30")
		blocklistServerSession, err = Start(blocklistServerCmd, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
		Eventually(blocklistServerSession.Err, 10).Should(Say("Ready to answer queries"))
	})

	AfterAll(func() {
		blocklistServerSession.Terminate()
		Eventually(blocklistServerSession).Should(Exit())
	})

	DescribeTable("when queried",
		func(hostname string, qType string, digResults string, serverLogMessage string) {
			digCmd := exec.Command("dig", "@localhost", "-p", strconv.Itoa(blocklistPort), hostname, qType, "+short")
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			Expect(string(digSession.Out.Contents())).To(MatchRegexp(digResults))
			Eventually(blocklistServerSession.Err).Should(Say(serverLogMessage))
		},
		Entry("an A record of 127.0.0.1--1.nip.io is redirected",
			"127.0.0.1--1.nip.io", "A",
			`\A10\.9\.9\.30\n\z`,
			`TypeA 127\.0\.0\.1--1\.nip\.io\. \? 10\.9\.9\.30\n`),
		Entry("an A record of www.--1.127-0-0-1.nip.io is redirected",
			"www.--1.127-0-0-1.nip.io", "A",
			`\A10\.9\.9\.30\n\z`,
			`TypeA www\.--1\.127-0-0-1\.nip\.io\. \? 10\.9\.9\.30\n`),
		Entry("an AAAA record of 127.0.0.1.--1.nip.io (::1) is NOT redirected",
			"127.0.0.1.--1.nip.io", "AAAA",
			`\A::1\n\z`,
			`TypeAAAA 127\.0\.0\.1\.--1\.nip\.io\. \? ::1\n`),
		Entry("an AAAA record of www.--1.127-0-0-1.nip.io (::1) is NOT redirected",
			"www.--1.127-0-0-1.nip.io", "AAAA",
			`\A::1\n\z`,
			`TypeAAAA www\.--1\.127-0-0-1\.nip\.io\. \? ::1\n`),
	)

	// our own nameservers, in any (rotated) order, as either the answer or the authority
	ourNameservers := `(_acme-challenge\.\S+\.\s+604800\s+IN\s+NS\s+(ns-00\.nip\.io|ns-01\.nip\.io|ns-ovh\.sslip\.io)\.\n){3}`

	DescribeTable(`when an "_acme-challenge" name is queried`,
		func(hostname string, qType string, digResults string, serverLogMessage string) {
			digCmd := exec.Command("dig", "@localhost", "-p", strconv.Itoa(blocklistPort), hostname, qType, "+noall", "+answer", "+authority")
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))
			// strip dig's ";" comments & blank lines, leaving only the answer & authority records
			var records strings.Builder
			for _, line := range strings.SplitAfter(string(digSession.Out.Contents()), "\n") {
				if !strings.HasPrefix(line, ";") && strings.TrimSpace(line) != "" {
					records.WriteString(line)
				}
			}
			Expect(records.String()).To(MatchRegexp(digResults))
			Eventually(blocklistServerSession.Err).Should(Say(serverLogMessage))
		},
		// IPv4
		Entry("a TXT record of an unblocked IPv4 is delegated",
			"_acme-challenge.1-2-3-4.nip.io", "TXT",
			`\A_acme-challenge\.1-2-3-4\.nip\.io\.\s+604800\s+IN\s+NS\s+1-2-3-4\.nip\.io\.\n\z`,
			`TypeTXT _acme-challenge\.1-2-3-4\.nip\.io\. \? nil, NS 1-2-3-4\.nip\.io\.\n`),
		Entry("an NS record of a blocked IPv4 is NOT delegated",
			"_acme-challenge.127-0-0-1.nip.io", "NS",
			`\A`+ourNameservers+`\z`,
			`TypeNS _acme-challenge\.127-0-0-1\.nip\.io\. \? ns-00\.nip\.io\., ns-01\.nip\.io\., ns-ovh\.sslip\.io\.\n`),
		// FIXME: TXT should return an empty list, not the set of nameservers
		Entry("a TXT record of a blocked IPv4 is NOT delegated",
			"_acme-challenge.127-0-0-1.nip.io", "TXT",
			`\A`+ourNameservers+`\z`,
			`TypeTXT _acme-challenge\.127-0-0-1\.nip\.io\. \? nil, NS ns-00\.nip\.io\., ns-01\.nip\.io\., ns-ovh\.sslip\.io\.\n`),
		Entry("an A record of a blocked IPv4 is redirected",
			"_acme-challenge.127-0-0-1.nip.io", "A",
			`\A_acme-challenge\.127-0-0-1\.nip\.io\.\s+604800\s+IN\s+A\s+10\.9\.9\.30\n\z`,
			`TypeA _acme-challenge\.127-0-0-1\.nip\.io\. \? 10\.9\.9\.30\n`),
		// IPv6
		Entry("a TXT record of an unblocked IPv6 is delegated",
			"_acme-challenge.2600--2.nip.io", "TXT",
			`\A_acme-challenge\.2600--2\.nip\.io\.\s+604800\s+IN\s+NS\s+2600--2\.nip\.io\.\n\z`,
			`TypeTXT _acme-challenge\.2600--2\.nip\.io\. \? nil, NS 2600--2\.nip\.io\.\n`),
		Entry("an NS record of a blocked IPv6 is NOT delegated",
			"_acme-challenge.2600--1.nip.io", "NS",
			`\A`+ourNameservers+`\z`,
			`TypeNS _acme-challenge\.2600--1\.nip\.io\. \? ns-00\.nip\.io\., ns-01\.nip\.io\., ns-ovh\.sslip\.io\.\n`),
		// FIXME: TXT should return an empty list, not the set of nameservers
		Entry("a TXT record of a blocked IPv6 is NOT delegated",
			"_acme-challenge.2600--1.nip.io", "TXT",
			`\A`+ourNameservers+`\z`,
			`TypeTXT _acme-challenge\.2600--1\.nip\.io\. \? nil, NS ns-00\.nip\.io\., ns-01\.nip\.io\., ns-ovh\.sslip\.io\.\n`),
		Entry("an AAAA record of a blocked IPv6 is redirected",
			"_acme-challenge.2600--1.nip.io", "AAAA",
			`\A_acme-challenge\.2600--1\.nip\.io\.\s+604800\s+IN\s+AAAA\s+2001:db8::30\n\z`,
			`TypeAAAA _acme-challenge\.2600--1\.nip\.io\. \? 2001:db8::30\n`),
		// both: blocked IPv4 (127.0.0.1), unblocked IPv6 (::1)
		// FIXME: TXT should return an empty list, not the set of nameservers
		Entry("a TXT record of a name with a blocked IPv4 and an unblocked IPv6 is NOT delegated",
			"_acme-challenge.www.--1.127-0-0-1.nip.io", "TXT",
			`\A`+ourNameservers+`\z`,
			`TypeTXT _acme-challenge\.www\.--1\.127-0-0-1\.nip\.io\. \? nil, NS ns-00\.nip\.io\., ns-01\.nip\.io\., ns-ovh\.sslip\.io\.\n`),
		Entry("an AAAA record of a name with a blocked IPv4 and an unblocked IPv6 is neither delegated nor redirected",
			"_acme-challenge.www.--1.127-0-0-1.nip.io", "AAAA",
			`\A_acme-challenge\.www\.--1\.127-0-0-1\.nip\.io\.\s+3600\s+IN\s+AAAA\s+::1\n\z`,
			`TypeAAAA _acme-challenge\.www\.--1\.127-0-0-1\.nip\.io\. \? ::1\n`),
	)
})
