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
		flags = append(flags, "-port", strconv.Itoa(port), "-blocklistURL", "file://../../etc/blocklist.txt")
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
			Eventually(digSession).Should(Say(`mickey.minnie.\n`))
			Eventually(digSession).Should(Say(`daffy.duck.\n`))
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding nameserver "mickey\.minnie\."\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`Adding nameserver "daffy\.duck\."\n`))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeNS example.com. \? mickey\.minnie\., daffy\.duck\.\n`))
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
})
