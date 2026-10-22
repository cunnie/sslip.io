package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("ResponseHasAorAAAA", func() {
	When("the response contains an A record answer", func() {
		It("returns true", func() {
			Expect(ResponseHasAorAAAA(dnsAResponse())).To(BeTrue())
		})
	})
	When("the response contains an AAAA record answer", func() {
		It("returns true", func() {
			Expect(ResponseHasAorAAAA(dnsAAAAResponse())).To(BeTrue())
		})
	})
	When("the response contains only NS records in the authority section", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA(dnsNSAuthorityResponse())).To(BeFalse())
		})
	})
	When("the response has an empty answer section", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA(dnsEmptyAnswerResponse())).To(BeFalse())
		})
	})
	When("given invalid DNS bytes", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA([]byte{0xff, 0x00, 0x01})).To(BeFalse())
		})
	})
	When("given empty bytes", func() {
		It("returns false", func() {
			Expect(ResponseHasAorAAAA([]byte{})).To(BeFalse())
		})
	})
})

var _ = Describe("encodeDnstapFrame", func() {
	It("sets identity, type, and message", func() {
		msg := []byte{0x08, 0x02}
		encoded := encodeDnstapFrame([]byte("ns-ovh"), msg)
		Expect(pbTestExtract(encoded, 1)).To(Equal([]byte("ns-ovh"))) // Dnstap.identity
		Expect(pbTestExtractUint(encoded, 15)).To(Equal(uint64(1)))   // Dnstap.type = MESSAGE
		Expect(pbTestExtract(encoded, 14)).To(Equal(msg))             // Dnstap.message
	})

	It("omits identity when it is empty", func() {
		encoded := encodeDnstapFrame(nil, []byte{0x08, 0x02})
		Expect(pbTestExtract(encoded, 1)).To(BeNil())
	})
})

var _ = Describe("encodeDnstapMsg", func() {
	It("includes the response bytes verbatim and omits the query bytes", func() {
		responseBytes := dnsAResponse()
		src := net.ParseIP("192.168.1.50")
		qt := time.Unix(1700000000, 123456789)
		rt := time.Unix(1700000001, 987654321)

		encoded := encodeDnstapMsg(responseBytes, src, 5353, true, qt, rt)

		Expect(pbTestExtract(encoded, 10)).To(BeNil())              // Message.query_message
		Expect(pbTestExtract(encoded, 14)).To(Equal(responseBytes)) // Message.response_message
	})

	It("sets socket_family to INET for IPv4 sources", func() {
		encoded := encodeDnstapMsg(dnsAResponse(), net.ParseIP("1.2.3.4"), 53, true, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 2)).To(Equal(uint64(dtSocketFamilyINET)))
	})

	It("sets socket_family to INET6 for IPv6 sources", func() {
		encoded := encodeDnstapMsg(dnsAAAAResponse(), net.ParseIP("2001:db8::1"), 53, true, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 2)).To(Equal(uint64(dtSocketFamilyINET6)))
	})

	It("sets socket_protocol to UDP when isUDP is true", func() {
		encoded := encodeDnstapMsg(dnsAResponse(), net.ParseIP("1.2.3.4"), 53, true, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 3)).To(Equal(uint64(dtSocketProtocolUDP)))
	})

	It("sets socket_protocol to TCP when isUDP is false", func() {
		encoded := encodeDnstapMsg(dnsAResponse(), net.ParseIP("1.2.3.4"), 53, false, time.Now(), time.Now())
		Expect(pbTestExtractUint(encoded, 3)).To(Equal(uint64(dtSocketProtocolTCP)))
	})
})

// --- DNS message builders ---

func dnsAResponse() []byte {
	name, _ := dnsmessage.NewName("127-0-0-1.sslip.io.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
	)
	_ = b.StartAuthorities()
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

func dnsAAAAResponse() []byte {
	name, _ := dnsmessage.NewName("fc00--.sslip.io.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.AAAAResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.AAAAResource{AAAA: [16]byte{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	)
	_ = b.StartAuthorities()
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

func dnsNSAuthorityResponse() []byte {
	name, _ := dnsmessage.NewName("sslip.io.")
	nsName, _ := dnsmessage.NewName("ns.sslip.io.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.StartAuthorities()
	_ = b.NSResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 3600},
		dnsmessage.NSResource{NS: nsName},
	)
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

func dnsEmptyAnswerResponse() []byte {
	name, _ := dnsmessage.NewName("nonexistent.example.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	_ = b.StartAuthorities()
	_ = b.StartAdditionals()
	result, _ := b.Finish()
	return result
}

// --- Minimal protobuf field extractor for tests ---

// pbTestExtract returns the raw bytes of the first length-delimited (wire type 2) field
// with the given field number.
func pbTestExtract(data []byte, fieldNum uint64) []byte {
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return nil
		}
		data = data[n:]
		fn, wt := tag>>3, tag&7
		switch wt {
		case 0: // varint
			_, n := binary.Uvarint(data)
			if n <= 0 {
				return nil
			}
			data = data[n:]
		case 2: // length-delimited
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
		case 5: // 32-bit
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

// pbTestExtractUint returns the varint value of the first wire-type-0 field with the given number.
func pbTestExtractUint(data []byte, fieldNum uint64) uint64 {
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return 0
		}
		data = data[n:]
		fn, wt := tag>>3, tag&7
		switch wt {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return 0
			}
			if fn == fieldNum {
				return v
			}
			data = data[n:]
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 {
				return 0
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return 0
			}
			data = data[length:]
		case 5:
			if len(data) < 4 {
				return 0
			}
			data = data[4:]
		default:
			return 0
		}
	}
	return 0
}

var _ = Describe("DnstapWriter", func() {
	BeforeEach(func() {
		// DnstapWriter logs via the standard logger; send it to GinkgoWriter so it only appears on failure or with -v
		log.SetOutput(GinkgoWriter)
		DeferCleanup(log.SetOutput, os.Stderr)
	})

	sendOne := func(dw *DnstapWriter) {
		dw.SendDnstap(dnsAResponse(), net.ParseIP("1.2.3.4"), 53, true, time.Now(), time.Now())
	}

	When("the collector stops reading", func() {
		It("never blocks the sender, and counts the dropped messages", func() {
			client, server := net.Pipe() // unbuffered: writes block until server reads, which it never does
			defer server.Close()
			dw := newDnstapWriter("", 4)
			go func() { _ = dw.stream(client) }()
			sent := make(chan struct{})
			go func() {
				for i := 0; i < 10000; i++ {
					sendOne(dw)
				}
				close(sent)
			}()
			Eventually(sent, 2).Should(BeClosed())
			Expect(dw.dropped.Load()).To(BeNumerically(">", 0))
			close(dw.stop)
		})
	})

	It("batches many small frames into large writes", func() {
		client, server := net.Pipe()
		dw := newDnstapWriter("", dnstapQueueLength)
		for i := 0; i < 1000; i++ {
			sendOne(dw)
		}
		streamDone := make(chan error)
		go func() { streamDone <- dw.stream(client) }()
		buf := make([]byte, 2*dnstapBatchBytes)
		n, err := server.Read(buf) // net.Pipe delivers each Write as-is, so n is the size of one write
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(dnstapBatchBytes))
		go func() { _, _ = io.Copy(io.Discard, server) }()
		close(dw.stop)
		Eventually(streamDone).Should(Receive(BeNil()))
	})

	When("the collector restarts", func() {
		It("reconnects and resumes sending", func() {
			socketPath := filepath.Join(GinkgoT().TempDir(), "dnstap.sock")
			frames := make(chan []byte, 100)

			shutdown := fakeCollector(socketPath, frames)
			dw := newDnstapWriter(socketPath, dnstapQueueLength)
			dw.retryInterval = 500 * time.Millisecond
			go dw.run()
			defer dw.Close()
			Eventually(func() int { sendOne(dw); return len(frames) }, 5, 100*time.Millisecond).Should(BeNumerically(">", 0))

			// the collector goes away, then comes back
			shutdown()
			for len(frames) > 0 {
				<-frames
			}
			shutdown = fakeCollector(socketPath, frames)
			defer shutdown()
			Eventually(func() int { sendOne(dw); return len(frames) }, 10, 100*time.Millisecond).Should(BeNumerically(">", 0))
		})
	})
})

// fakeCollector listens on socketPath and, for each connection, performs the framestream
// handshake and forwards data frames to frames. The returned func shuts it down,
// closing the listener and every connection, as a restarting collector would.
func fakeCollector(socketPath string, frames chan<- []byte) (shutdown func()) {
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	Expect(err).ToNot(HaveOccurred())
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				if fsReadControl(conn, fsControlReady) != nil ||
					fsWriteControl(conn, fsControlAccept, dnstapContentType) != nil ||
					fsReadControl(conn, fsControlStart) != nil {
					return
				}
				var hdr [4]byte
				for {
					if _, err := io.ReadFull(conn, hdr[:]); err != nil {
						return
					}
					length := binary.BigEndian.Uint32(hdr[:])
					if length == 0 { // control frame (e.g. STOP)
						return
					}
					frame := make([]byte, length)
					if _, err := io.ReadFull(conn, frame); err != nil {
						return
					}
					frames <- frame
				}
			}()
		}
	}()
	return func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	}
}
