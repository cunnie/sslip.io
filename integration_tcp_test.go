package main_test

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/dns/dnsmessage"
)

var _ = Describe("TCP", func() {
	When("a client opens a TCP connection but never sends a query", func() {
		It("still answers other TCP clients", func() {
			serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			// the silent client: connects and then says nothing
			silentConn, err := net.Dial("tcp", serverAddr)
			Expect(err).ToNot(HaveOccurred())
			// closing the silent connection un-sticks a server that's blocked on it
			DeferCleanup(silentConn.Close)
			// give the server time to accept the silent connection before we connect
			time.Sleep(100 * time.Millisecond)

			conn, err := net.Dial("tcp", serverAddr)
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(conn.Close)
			Expect(conn.SetDeadline(time.Now().Add(3 * time.Second))).To(Succeed())

			name := dnsmessage.MustNewName("127.0.0.1.sslip.io.")
			query, err := (&dnsmessage.Message{
				Header: dnsmessage.Header{ID: 0x5150, RecursionDesired: true},
				Questions: []dnsmessage.Question{
					{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				},
			}).Pack()
			Expect(err).ToNot(HaveOccurred())
			// DNS over TCP prefixes each message with a 2-byte length (RFC 1035 §4.2.2)
			framedQuery := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
			_, err = conn.Write(append(framedQuery, query...))
			Expect(err).ToNot(HaveOccurred())

			lengthPrefix := make([]byte, 2)
			_, err = io.ReadFull(conn, lengthPrefix)
			Expect(err).ToNot(HaveOccurred(), "the TCP lookup got stuck behind the silent client")
			response := make([]byte, binary.BigEndian.Uint16(lengthPrefix))
			_, err = io.ReadFull(conn, response)
			Expect(err).ToNot(HaveOccurred())

			var msg dnsmessage.Message
			Expect(msg.Unpack(response)).To(Succeed())
			Expect(msg.Header.ID).To(Equal(uint16(0x5150)))
			Expect(msg.Answers).To(HaveLen(1))
			Expect(msg.Answers[0].Body).To(Equal(&dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}))
		})
	})
})
