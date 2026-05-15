package main_test

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("-dnstap flag", func() {
	var dnstapServerCmd *exec.Cmd
	var dnstapServerSession *Session
	var dnstapPort = getFreePort()
	var socketPath string
	var listener net.Listener
	var receivedFrames chan []byte

	BeforeEach(func() {
		receivedFrames = make(chan []byte, 100)
		socketPath = filepath.Join(os.TempDir(), "test-dnstap-"+strconv.Itoa(dnstapPort)+".sock")
		os.Remove(socketPath)
		var lerr error
		listener, lerr = net.Listen("unix", socketPath)
		Expect(lerr).ToNot(HaveOccurred())
		go dtListen(listener, receivedFrames)
	})

	JustBeforeEach(func() {
		dnstapServerCmd = exec.Command(serverPath,
			"-port", strconv.Itoa(dnstapPort),
			"-blocklistURL", "file://etc/blocklist-test.txt",
			"-dnstap="+socketPath)
		dnstapServerSession, err = Start(dnstapServerCmd, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
		Eventually(dnstapServerSession.Err, 10).Should(Say("Ready to answer queries"))
	})

	AfterEach(func() {
		dnstapServerSession.Terminate()
		Eventually(dnstapServerSession).Should(Exit())
		listener.Close()
		os.Remove(socketPath)
	})

	When("a query returns an A record", func() {
		It("sends a dnstap frame whose response_message contains an A record", func() {
			digArgs := "@localhost 127-0-0-1.sslip.io A -p " + strconv.Itoa(dnstapPort)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, derr := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(derr).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))

			var frame []byte
			Eventually(receivedFrames, 2).Should(Receive(&frame))
			Expect(dtFrameHasAorAAAA(frame)).To(BeTrue())
		})
	})

	When("a query returns an AAAA record", func() {
		It("sends a dnstap frame whose response_message contains an AAAA record", func() {
			digArgs := "@localhost aaaa fc00--.sslip.io -p " + strconv.Itoa(dnstapPort)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, derr := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(derr).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))

			var frame []byte
			Eventually(receivedFrames, 2).Should(Receive(&frame))
			Expect(dtFrameHasAorAAAA(frame)).To(BeTrue())
		})
	})

	When("a query returns only NS records (no A/AAAA answer)", func() {
		It("does not send a dnstap frame", func() {
			digArgs := "@localhost example.com NS -p " + strconv.Itoa(dnstapPort)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, derr := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(derr).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))

			Consistently(receivedFrames, 500*time.Millisecond).ShouldNot(Receive())
		})
	})

	When("a query returns no answer", func() {
		It("does not send a dnstap frame", func() {
			digArgs := "@localhost nonexistent.example.com A -p " + strconv.Itoa(dnstapPort)
			digCmd := exec.Command("dig", strings.Split(digArgs, " ")...)
			digSession, derr := Start(digCmd, GinkgoWriter, GinkgoWriter)
			Expect(derr).ToNot(HaveOccurred())
			Eventually(digSession, 1).Should(Exit(0))

			Consistently(receivedFrames, 500*time.Millisecond).ShouldNot(Receive())
		})
	})
})

var _ = Describe("-dnstap flag with bad socket", func() {
	When("the dnstap socket path does not exist", func() {
		It("prints a warning mentioning 'dnstap' and continues running", func() {
			badPort := getFreePort()
			badCmd := exec.Command(serverPath,
				"-port", strconv.Itoa(badPort),
				"-blocklistURL", "file://etc/blocklist-test.txt",
				"-dnstap=/nonexistent/path/dnstap.sock")
			badSession, serr := Start(badCmd, GinkgoWriter, GinkgoWriter)
			Expect(serr).ToNot(HaveOccurred())
			Eventually(badSession.Err, 10).Should(Say("dnstap.*warning|warning.*dnstap"))
			Eventually(badSession.Err, 10).Should(Say("Ready to answer queries"))
			badSession.Terminate()
			Eventually(badSession).Should(Exit())
		})
	})
})

// --- Minimal framestream dnstap receiver ---

const (
	dtFsAccept      = uint32(1)
	dtFsStart       = uint32(2)
	dtFsContentType = "protobuf:dnstap.Dnstap"
)

// dtListen accepts one connection, performs the framestream handshake, and
// forwards all data frames into frames.
func dtListen(l net.Listener, frames chan<- []byte) {
	conn, err := l.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	if _, err := dtReadControl(conn); err != nil { // READY
		return
	}
	if err := dtWriteControl(conn, dtFsAccept); err != nil { // ACCEPT
		return
	}
	if _, err := dtReadControl(conn); err != nil { // START
		return
	}
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(hdr[:])
		if length == 0 { // control frame (STOP) — drain it and exit
			var ctrlLenBuf [4]byte
			if _, err := io.ReadFull(conn, ctrlLenBuf[:]); err != nil {
				return
			}
			ctrlLen := binary.BigEndian.Uint32(ctrlLenBuf[:])
			_, _ = io.ReadFull(conn, make([]byte, ctrlLen))
			return
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}
		frames <- data
	}
}

func dtReadControl(r io.Reader) (uint32, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(hdr[4:])
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, err
	}
	if len(body) < 4 {
		return 0, nil
	}
	return binary.BigEndian.Uint32(body[:4]), nil
}

func dtWriteControl(w io.Writer, frameType uint32) error {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, frameType)
	body = binary.BigEndian.AppendUint32(body, 1) // CONTENT_TYPE field
	body = binary.BigEndian.AppendUint32(body, uint32(len(dtFsContentType)))
	body = append(body, dtFsContentType...)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], 0)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// dtFrameHasAorAAAA decodes a dnstap protobuf frame and checks whether the
// embedded response_message DNS payload contains an A or AAAA answer record.
func dtFrameHasAorAAAA(frame []byte) bool {
	msgBytes := dtExtractBytes(frame, 14) // Dnstap.message (field 14)
	if msgBytes == nil {
		return false
	}
	responseBytes := dtExtractBytes(msgBytes, 14) // Message.response_message (field 14)
	if responseBytes == nil {
		return false
	}
	var p dnsmessage.Parser
	if _, err := p.Start(responseBytes); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	for {
		hdr, err := p.AnswerHeader()
		if err != nil {
			return false
		}
		if hdr.Type == dnsmessage.TypeA || hdr.Type == dnsmessage.TypeAAAA {
			return true
		}
		if err := p.SkipAnswer(); err != nil {
			return false
		}
	}
}

// dtExtractBytes returns the raw bytes of the first length-delimited protobuf
// field with the given field number, or nil if not found.
func dtExtractBytes(data []byte, fieldNum uint64) []byte {
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return nil
		}
		data = data[n:]
		fn, wt := tag>>3, tag&7
		switch wt {
		case 0:
			_, n := binary.Uvarint(data)
			if n <= 0 {
				return nil
			}
			data = data[n:]
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 {
				return nil
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return nil
			}
			if fn == fieldNum {
				result := make([]byte, length)
				copy(result, data[:length])
				return result
			}
			data = data[length:]
		case 5:
			if len(data) < 4 {
				return nil
			}
			data = data[4:]
		default:
			return nil
		}
	}
	return nil
}
