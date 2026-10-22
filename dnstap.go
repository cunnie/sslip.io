package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	fsControlAccept    = uint32(1)
	fsControlStart     = uint32(2)
	fsControlStop      = uint32(3)
	fsControlReady     = uint32(4)
	fsFieldContentType = uint32(1)
	dnstapContentType  = "protobuf:dnstap.Dnstap"

	dtMsgTypeAuthResponse = uint32(2)
	dtSocketFamilyINET    = uint32(1)
	dtSocketFamilyINET6   = uint32(2)
	dtSocketProtocolUDP   = uint32(1)
	dtSocketProtocolTCP   = uint32(2)

	// at ~10k qps, 64k frames is several seconds of backlog; beyond that we drop rather than block DNS
	dnstapQueueLength = 65536
	// frames are batched into writes of this size: fewer syscalls and full-sized TCP segments
	dnstapBatchBytes = 16 * 1024
	// a partially-filled batch is sent at least this often, so low-traffic servers aren't stuck
	dnstapFlushInterval   = time.Second
	dnstapDropLogInterval = time.Minute
	// after a lost connection or a failed connection attempt, wait this long before trying again
	dnstapRetryInterval = time.Minute
	// a collector that accepts but never responds or reads must not wedge the writer
	dnstapConnectTimeout = 5 * time.Second
	dnstapWriteTimeout   = 10 * time.Second
)

// DnstapWriter sends dnstap AUTH_RESPONSE messages over a framestream connection.
// Sending never blocks: frames are queued, batched by a background goroutine,
// and dropped (and counted) if the queue is full or the collector is unreachable.
// If the connection fails, the background goroutine reconnects.
type DnstapWriter struct {
	addr     string // Unix socket path starting with "/" or TCP "host:port"
	identity []byte // Dnstap.identity: the hostname, e.g. "ns-ovh"
	// how long to wait before reconnecting; a field, not just a const, so tests needn't wait a minute
	retryInterval time.Duration
	frames        chan []byte
	dropped       atomic.Uint64
	stop          chan struct{}
	done          chan struct{}
}

// NewDnstapWriter returns a writer that connects to addr (Unix socket path starting with "/"
// or TCP "host:port") in the background, reconnecting whenever the connection is lost.
func NewDnstapWriter(addr string) *DnstapWriter {
	dw := newDnstapWriter(addr, dnstapQueueLength)
	go dw.logDrops()
	go dw.run()
	return dw
}

func newDnstapWriter(addr string, queueLength int) *DnstapWriter {
	dw := &DnstapWriter{
		addr:          addr,
		retryInterval: dnstapRetryInterval,
		frames:        make(chan []byte, queueLength),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	if hostname, err := os.Hostname(); err == nil {
		shortHostname, _, _ := strings.Cut(hostname, ".") // "ns-ovh.sslip.io" → "ns-ovh"
		dw.identity = []byte(shortHostname)
	}
	return dw
}

// connect dials the collector and performs the framestream handshake.
func (dw *DnstapWriter) connect() (net.Conn, error) {
	network := "tcp"
	if strings.HasPrefix(dw.addr, "/") {
		network = "unix"
	}
	conn, err := net.DialTimeout(network, dw.addr, dnstapConnectTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(dnstapConnectTimeout))
	if err = fsHandshake(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("framestream handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func fsHandshake(conn net.Conn) error {
	if err := fsWriteControl(conn, fsControlReady, dnstapContentType); err != nil {
		return err
	}
	if err := fsReadControl(conn, fsControlAccept); err != nil {
		return err
	}
	return fsWriteControl(conn, fsControlStart, dnstapContentType)
}

// SendDnstap queues a dnstap AUTH_RESPONSE message for a DNS response. It never blocks:
// if the queue is full (slow link or collector), the message is dropped.
func (dw *DnstapWriter) SendDnstap(responseBytes []byte, srcAddr net.IP, srcPort int, isUDP bool, queryTime, responseTime time.Time) {
	msg := encodeDnstapMsg(responseBytes, srcAddr, srcPort, isUDP, queryTime, responseTime)
	select {
	case dw.frames <- encodeDnstapFrame(dw.identity, msg):
	default:
		dw.dropped.Add(1)
	}
}

// Close sends any queued frames and a STOP control frame, then closes the connection.
func (dw *DnstapWriter) Close() {
	close(dw.stop)
	<-dw.done
}

// run connects to the collector and streams frames to it. If connecting fails or the
// connection is lost, it waits dw.retryInterval before trying again.
func (dw *DnstapWriter) run() {
	defer close(dw.done)
	for {
		conn, err := dw.connect()
		if err != nil {
			log.Printf("dnstap: warning: could not connect to %q, retrying in %v: %v", dw.addr, dw.retryInterval, err)
		} else {
			log.Printf("dnstap: connected to %q", dw.addr)
			if err = dw.stream(conn); err == nil {
				return // stopped
			}
			log.Printf("dnstap: lost connection to %q, reconnecting in %v: %v", dw.addr, dw.retryInterval, err)
		}
		if !dw.discardFor(dw.retryInterval) {
			return
		}
	}
}

// discardFor drops queued frames (so the queue doesn't fill with stale data while the
// collector is unreachable) for duration d. It returns false if the writer was stopped.
func (dw *DnstapWriter) discardFor(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-dw.frames:
			dw.dropped.Add(1)
		case <-timer.C:
			return true
		case <-dw.stop:
			return false
		}
	}
}

// stream is the sole writer to conn. It packs frames into large writes, flushing
// when the batch buffer fills or every dnstapFlushInterval. It returns nil when the
// writer is stopped, or the error that broke the connection. Either way, conn is closed.
func (dw *DnstapWriter) stream(conn net.Conn) error {
	defer func() { _ = conn.Close() }()
	bw := bufio.NewWriterSize(deadlineWriter{conn}, dnstapBatchBytes) // writes through to conn each time it fills
	flushTicker := time.NewTicker(dnstapFlushInterval)
	defer flushTicker.Stop()
	for {
		select {
		case frame := <-dw.frames:
			if err := fsWriteData(bw, frame); err != nil {
				return err // the frames in bw are lost, too
			}
		case <-flushTicker.C:
			if err := bw.Flush(); err != nil {
				return err
			}
		case <-dw.stop:
			for {
				select {
				case frame := <-dw.frames:
					if err := fsWriteData(bw, frame); err != nil {
						return nil
					}
				default:
					_ = fsWriteControl(bw, fsControlStop, "")
					_ = bw.Flush()
					return nil
				}
			}
		}
	}
}

// logDrops periodically reports how many frames were dropped.
func (dw *DnstapWriter) logDrops() {
	ticker := time.NewTicker(dnstapDropLogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if dropped := dw.dropped.Swap(0); dropped > 0 {
				log.Printf("dnstap: dropped %d messages in the last %v (queue full or collector unreachable)", dropped, dnstapDropLogInterval)
			}
		case <-dw.stop:
			return
		}
	}
}

// deadlineWriter gives each write a deadline, so a collector that stops reading
// breaks the connection (and triggers a reconnect) instead of blocking forever.
type deadlineWriter struct{ net.Conn }

func (w deadlineWriter) Write(p []byte) (int, error) {
	_ = w.SetWriteDeadline(time.Now().Add(dnstapWriteTimeout))
	return w.Conn.Write(p)
}

// ResponseHasAorAAAA reports whether the packed DNS response contains at least one A or AAAA answer.
func ResponseHasAorAAAA(responseBytes []byte) bool {
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

// --- Framestream ---

func fsWriteControl(w io.Writer, frameType uint32, contentType string) error {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, frameType)
	if contentType != "" {
		body = binary.BigEndian.AppendUint32(body, fsFieldContentType)
		body = binary.BigEndian.AppendUint32(body, uint32(len(contentType)))
		body = append(body, contentType...)
	}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:], 0)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func fsReadControl(r io.Reader, expectedType uint32) error {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(hdr[0:]) != 0 {
		return fmt.Errorf("framestream: missing escape sequence")
	}
	length := binary.BigEndian.Uint32(hdr[4:])
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	if len(body) < 4 {
		return fmt.Errorf("framestream: control frame too short")
	}
	if binary.BigEndian.Uint32(body[0:4]) != expectedType {
		return fmt.Errorf("framestream: expected control type %d, got %d", expectedType, binary.BigEndian.Uint32(body[0:4]))
	}
	return nil
}

func fsWriteData(w io.Writer, data []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// --- Minimal protobuf encoding ---

func pbAppendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// wire type 2: length-delimited (bytes, string, embedded message)
func pbAppendBytes(b []byte, fieldNum uint64, data []byte) []byte {
	b = pbAppendVarint(b, fieldNum<<3|2)
	b = pbAppendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// wire type 0: varint (int32, int64, uint32, uint64, sint32, sint64, bool, enum)
func pbAppendUint32(b []byte, fieldNum uint64, v uint32) []byte {
	b = pbAppendVarint(b, fieldNum<<3)
	return pbAppendVarint(b, uint64(v))
}

func pbAppendUint64(b []byte, fieldNum uint64, v uint64) []byte {
	b = pbAppendVarint(b, fieldNum<<3)
	return pbAppendVarint(b, v)
}

// wire type 5: 32-bit little-endian (fixed32, sfixed32, float)
func pbAppendFixed32(b []byte, fieldNum uint64, v uint32) []byte {
	b = pbAppendVarint(b, fieldNum<<3|5)
	return binary.LittleEndian.AppendUint32(b, v)
}

// --- Dnstap encoding (dnstap.proto Dnstap type) ---

func encodeDnstapFrame(identity, msg []byte) []byte {
	var frame []byte
	if len(identity) > 0 {
		frame = pbAppendBytes(frame, 1, identity) // Dnstap.identity
	}
	frame = pbAppendUint32(frame, 15, 1)  // Dnstap.type = MESSAGE(1)
	frame = pbAppendBytes(frame, 14, msg) // Dnstap.message
	return frame
}

// --- Dnstap Message encoding (dnstap.proto Message type) ---

// The query message is omitted: the response's question section carries the query name,
// and leaving it out roughly halves the size of each frame on the wire.
func encodeDnstapMsg(responseBytes []byte, srcAddr net.IP, srcPort int, isUDP bool, queryTime, responseTime time.Time) []byte {
	socketFamily := dtSocketFamilyINET
	addrBytes := srcAddr.To4()
	if addrBytes == nil {
		socketFamily = dtSocketFamilyINET6
		addrBytes = srcAddr.To16()
	}
	socketProtocol := dtSocketProtocolUDP
	if !isUDP {
		socketProtocol = dtSocketProtocolTCP
	}

	var msg []byte
	msg = pbAppendUint32(msg, 1, dtMsgTypeAuthResponse)               // Message.type = AUTH_RESPONSE
	msg = pbAppendUint32(msg, 2, socketFamily)                        // Message.socket_family
	msg = pbAppendUint32(msg, 3, socketProtocol)                      // Message.socket_protocol
	msg = pbAppendBytes(msg, 4, addrBytes)                            // Message.query_address
	msg = pbAppendUint32(msg, 6, uint32(srcPort))                     // Message.query_port
	msg = pbAppendUint64(msg, 8, uint64(queryTime.Unix()))            // Message.query_time_sec
	msg = pbAppendFixed32(msg, 9, uint32(queryTime.Nanosecond()))     // Message.query_time_nsec
	msg = pbAppendUint64(msg, 12, uint64(responseTime.Unix()))        // Message.response_time_sec
	msg = pbAppendFixed32(msg, 13, uint32(responseTime.Nanosecond())) // Message.response_time_nsec
	msg = pbAppendBytes(msg, 14, responseBytes)                       // Message.response_message
	return msg
}
