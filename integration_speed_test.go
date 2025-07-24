package main_test

import (
	"net"
	"os/exec"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("speed", func() {
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
	When("we want test the throughput", func() {
		var loopbackAddr *net.UDPAddr
		var conn *net.UDPConn
		var msg dnsmessage.Message
		const numQueries = 5000 // set to 123456 when testing
		const minThroughput = 1000

		BeforeEach(func() {
			loopbackAddr, err = net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(port))
			Expect(err).ToNot(HaveOccurred())
			conn, err = net.DialUDP("udp", nil, loopbackAddr)
			Expect(err).ToNot(HaveOccurred())
		})
		It("runs "+strconv.Itoa(numQueries)+" queries and the throughput is > "+strconv.Itoa(minThroughput)+" queries/sec", func() {
			msg = dnsmessage.Message{
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName("127-0-0-1.sslip.io."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			}
			responseBuf := make([]byte, 512)
			queryBuf, err := msg.Pack()
			Expect(err).ToNot(HaveOccurred())
			startTime := time.Now()
			// The queries/second is conservative, realistically should be higher
			// - queries are done sequentially, not in parallel
			// - each query includes an overhead of 4 Expect()
			// current max queries is 2047/second (ns-ovh.sslip.io.)
			// ~27k Apple M4
			// ~19k Apple M2
			// ~8k vSphere Xeon D-1736 2.7GHz
			// ~6k AWS Graviton T2
			// ~5k Azure Xeon E5-2673 v4 @ 2.30GHz

			// blocklist exacts a 3% - 11% penalty
			// with `-quiet` and 4-entry blocklist on M4
			// ~32k-34k
			// with 725 entry blocklist
			// ~30k-31k
			for i := 0; i < numQueries; i += 1 {
				bytesWritten, err := conn.Write(queryBuf)
				Expect(err).ToNot(HaveOccurred())
				Expect(bytesWritten).To(Equal(len(queryBuf)))
				bytesRead, err := conn.Read(responseBuf)
				Expect(err).ToNot(HaveOccurred())
				Expect(bytesRead).To(Equal(52)) // The A record response "127.0.0.1" is 52 bytes
			}
			elapsedSeconds := time.Since(startTime).Seconds()
			Eventually(serverSession.Err).Should(Say(`TypeA 127-0-0-1\.sslip\.io\. \? 127\.0\.0\.1`))
			//fmt.Fprintf(os.Stderr, "Queries/second: %.2f\n", float64(numQueries)/elapsedSeconds)
			Expect(float64(numQueries) / elapsedSeconds).Should(BeNumerically(">", minThroughput))
		})
	})
})
