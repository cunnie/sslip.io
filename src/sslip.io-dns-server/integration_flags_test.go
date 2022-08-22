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
		It("returns all the records, appending dots as needed", func() {
			digArgs := "@localhost example.com ns -p " + strconv.Itoa(port)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, err := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(digSession).Should(Say(`flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0`))
			Eventually(digSession).Should(Say(`;; ANSWER SECTION:`))
			Eventually(digSession).Should(Say(`mickey.minnie.\n`))
			Eventually(digSession).Should(Say(`daffy.duck.\n`))
			Eventually(digSession, 1).Should(Exit(0))
			Eventually(string(serverSession.Err.Contents())).Should(MatchRegexp(`TypeNS example.com. \? mickey\.minnie\., daffy\.duck\.\n`))
		})
	})
})
