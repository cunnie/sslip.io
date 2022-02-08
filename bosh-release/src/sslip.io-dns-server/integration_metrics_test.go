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
			var actualMetrics xip.Metrics
			expectedMetrics := getMetrics()

			// A updates .Queries, .AnsweredQueries, .AnsweredAQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics.AnsweredAQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost 127.0.0.1.sslip.io +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// A (non-existent) record updates .Queries
			expectedMetrics.Queries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost non-existent.sslip.io +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// A blocked updates .Queries, .AnsweredQueries, .AnsweredBlockedQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics.AnsweredBlockedQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			dig("@localhost bank-of-raiffeisen.127.0.0.1.sslip.io +short")
			actualMetrics = getMetrics()
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// AAAA updates .Queries, .AnsweredQueries, .AnsweredAAAAQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics.AnsweredAAAAQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost 2600--.sslip.io aaaa +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// AAAA (non-existent) updates .Queries
			expectedMetrics.Queries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost non-existent.sslip.io aaaa +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// MX (customized) updates .Queries, .AnsweredQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost sslip.io mx +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// MX updates .Queries, AnsweredQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost non-existent.sslip.io mx +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// NS updates .Queries, AnsweredQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost non-existent.sslip.io ns +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// NS DNS-01 challenge record updates .Queries, .AnsweredNSDNS01ChallengeQueries
			expectedMetrics.Queries += 1
			// DNS-01 challenges don't count as successful because we're not authoritative; we're delegating
			expectedMetrics.AnsweredNSDNS01ChallengeQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost _acme-challenge.fe80--.sslip.io NS +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// Always successful: SOA
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			dig("@localhost non-existent.sslip.io soa +short")
			actualMetrics = getMetrics()
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// TXT sslip.io (customized) updates .Queries, .AnsweredQueries,
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// TXT sslip.io (non-existent) updates .Queries, .AnsweredQueries,
			expectedMetrics.Queries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost non-existent.sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// TXT ip.sslip.io updates .Queries, .AnsweredQueries, .AnsweredTXTSrcIPQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics.AnsweredTXTSrcIPQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost ip.sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// TXT version.sslip.io updates .Queries, .AnsweredQueries, .AnsweredXTVersionQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredQueries += 1
			expectedMetrics.AnsweredXTVersionQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost version.status.sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())

			// TXT DNS-01 challenge record updates .Queries, .AnsweredNSDNS01ChallengeQueries
			expectedMetrics.Queries += 1
			expectedMetrics.AnsweredNSDNS01ChallengeQueries += 1
			expectedMetrics = bumpExpectedToAccountForMetricsQuery(expectedMetrics)
			actualMetrics = digAndGetMetrics("@localhost _acme-challenge.fe80--.sslip.io txt +short")
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())
		})
	})
})

// bumpExpectedToAccountForMetricsQuery takes into account that
// digging for the metrics endpoint affects the metrics. It's like
// the Heisenberg uncertainty principle (observing changes the values)
func bumpExpectedToAccountForMetricsQuery(metrics xip.Metrics) xip.Metrics {
	metrics.Queries += 1
	metrics.AnsweredQueries += 1
	return metrics
}

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
		"\"Uptime (seconds): %d\"\n"+
			"\"Key-value store: %s\n"+ // %s "swallows" the double-quote at the end
			"\"Queries: %d\"\n"+
			"\"Queries/second: %s\n"+
			"\"AnsQueries: %d\"\n"+
			"\"AnsQueries/second: %s\n"+
			"\"AnsA: %d\"\n"+
			"\"AnsAAAA: %d\"\n"+
			"\"Source IP TXT: %d\"\n"+
			"\"Version TXT: %d\"\n"+
			"\"DNS-01 challenge: %d\"\n"+
			"\"Blocked: %d\"\n",
		&uptime,
		&junk,
		&m.Queries,
		&junk,
		&m.AnsweredQueries,
		&junk,
		&m.AnsweredAQueries,
		&m.AnsweredAAAAQueries,
		&m.AnsweredTXTSrcIPQueries,
		&m.AnsweredXTVersionQueries,
		&m.AnsweredNSDNS01ChallengeQueries,
		&m.AnsweredBlockedQueries,
	)
	Expect(err).ToNot(HaveOccurred())
	m.Start = time.Now().Add(-time.Duration(uptime) * time.Second)
	//_, err = fmt.Fscanf(digSession.Out, "queries: %d", &m.Queries)
	return m
}
