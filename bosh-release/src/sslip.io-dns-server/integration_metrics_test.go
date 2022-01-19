package main_test

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
	"xip/xip"

	. "github.com/onsi/ginkgo/v2"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("IntegrationMetrics", func() {
	When("the server is queried", func() {
		// One big `It()` block because these tests cannot be run in parallel (singleton)
		It("should update metrics", func() {
			expectedMetrics := getMetrics()

			// non-existent record updates .Queries
			expectedMetrics.Queries += 2           // two queries: nonexistent.sslip.io, metrics.status.sslip.io
			expectedMetrics.SuccessfulQueries += 1 // metrics.status.sslip.io
			actualMetrics := digAndGetMetrics("@localhost non-existent.sslip.io +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// MX record updates .Queries, .SuccessfulQueries
			expectedMetrics.Queries += 2
			expectedMetrics.SuccessfulQueries += 2
			actualMetrics = digAndGetMetrics("@localhost sslip.io mx +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// A record updates .Queries, .SuccessfulQueries, .SuccessfulAQueries
			expectedMetrics.Queries += 2
			expectedMetrics.SuccessfulQueries += 2
			expectedMetrics.SuccessfulAQueries += 1
			actualMetrics = digAndGetMetrics("@localhost 127.0.0.1.sslip.io +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// AAAA record updates .Queries, .SuccessfulQueries, .SuccessfulAAAAQueries
			expectedMetrics.Queries += 2
			expectedMetrics.SuccessfulQueries += 2
			expectedMetrics.SuccessfulAAAAQueries += 1
			actualMetrics = digAndGetMetrics("@localhost 2600--.sslip.io aaaa +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// source IP TXT record updates .Queries, .SuccessfulQueries, .SuccessfulTXTSrcIPQueries
			expectedMetrics.Queries += 2
			expectedMetrics.SuccessfulQueries += 2
			expectedMetrics.SuccessfulTXTSrcIPQueries += 1
			actualMetrics = digAndGetMetrics("@localhost ip.sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// version TXT record updates .Queries, .SuccessfulQueries, .SuccessfulTXTVersionQueries
			expectedMetrics.Queries += 2
			expectedMetrics.SuccessfulQueries += 2
			expectedMetrics.SuccessfulTXTVersionQueries += 1
			actualMetrics = digAndGetMetrics("@localhost version.status.sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// DNS-01 challenge N record updates .Queries, .SuccessfulQueries, .SuccessfulNSDNS01ChallengeQueries
			expectedMetrics.Queries += 2
			// DNS-01 challenges don't count as successful because we're not authoritative; we're delegating
			expectedMetrics.SuccessfulQueries += 1
			expectedMetrics.SuccessfulNSDNS01ChallengeQueries += 1
			actualMetrics = digAndGetMetrics("@localhost _acme-challenge.fe80--.sslip.io NS +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// 3 failed lookups + metrics
			expectedMetrics.Queries += 4
			expectedMetrics.SuccessfulQueries += 1
			dig("@localhost non-existent.sslip.io +short")
			dig("@localhost non-existent.sslip.io aaaa +short")
			dig("@localhost non-existent.sslip.io txt +short")
			actualMetrics = getMetrics()
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// Always successful: SOA MX NS
			expectedMetrics.Queries += 4
			expectedMetrics.SuccessfulQueries += 4
			dig("@localhost non-existent.sslip.io soa +short")
			dig("@localhost non-existent.sslip.io mx +short")
			dig("@localhost non-existent.sslip.io ns +short")
			actualMetrics = getMetrics()
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())
		})
	})
})

func digAndGetMetrics(digArgs string) xip.Metrics {
	dig(digArgs)
	return getMetrics()
}

func dig(digArgs string) {
	digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
	digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred())
	Eventually(digSession, 1).Should(Exit(0))
}

func getMetrics() (m xip.Metrics) {
	digArgs := "@localhost metrics.status.sslip.io txt +short"
	digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
	stdout, err := digCmd.Output()
	Expect(err).ToNot(HaveOccurred())
	var uptime int
	var junk string
	_, err = fmt.Sscanf(string(stdout),
		"\"uptime (seconds): %d\"\n"+
			"\"key-value store: %s\n"+ // %s "swallows" the double-quote at the end
			"\"queries: %d\"\n"+
			"\"queries/second: %s\n"+
			"\"successful:\"\n"+
			"\"- queries: %d\"\n"+
			"\"- queries/second: %s\n"+
			"\"- A: %d\"\n"+
			"\"- AAAA: %d\"\n"+
			"\"- source IP TXT: %d\"\n"+
			"\"- version TXT: %d\"\n"+
			"\"- DNS-01 challenge: %d\"\n",
		&uptime,
		&junk,
		&m.Queries,
		&junk,
		&m.SuccessfulQueries,
		&junk,
		&m.SuccessfulAQueries,
		&m.SuccessfulAAAAQueries,
		&m.SuccessfulTXTSrcIPQueries,
		&m.SuccessfulTXTVersionQueries,
		&m.SuccessfulNSDNS01ChallengeQueries,
	)
	Expect(err).ToNot(HaveOccurred())
	m.Start = time.Now().Add(-time.Duration(uptime) * time.Second)
	//_, err = fmt.Fscanf(digSession.Out, "queries: %d", &m.Queries)
	return m
}
