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
	var digCmd *exec.Cmd
	var digSession *Session
	var digArgs string

	When("the server is queried", func() {
		It("should update metrics", func() {
			startMetrics := getMetrics()
			digArgs = "@localhost non-existent.sslip.io +short"
			digCmd = exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err = Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			// we want to make sure digSession has exited because we
			// want to parse the _full_ contents of stdout
			Eventually(digSession, 1).Should(Exit(0))
			expectedMetrics := startMetrics
			expectedMetrics.Queries += 2 // two queries: nonexistent.sslip.io, metrics.status.sslip.io
			actualMetrics := getMetrics()
			Expect(expectedMetrics.MostlyEquals(actualMetrics)).To(BeTrue())
		})
	})
})

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
			"\"queries: %d\"\n",
		&uptime,
		&junk,
		&m.Queries,
	)
	Expect(err).ToNot(HaveOccurred())
	m.Start = time.Now().Add(-time.Duration(uptime) * time.Second)
	//_, err = fmt.Fscanf(digSession.Out, "queries: %d", &m.Queries)
	return m
}
