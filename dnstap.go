package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
)

// DnstapWriter sends dnstap AUTH_RESPONSE messages over a framestream connection.
type DnstapWriter struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewDnstapWriter connects to addr (Unix socket path starting with "/" or TCP "host:port")
// and performs the framestream handshake.
func NewDnstapWriter(addr string) (*DnstapWriter, error) {
	var conn net.Conn
	var err error
	if strings.HasPrefix(addr, "/") {
		conn, err = net.Dial("unix", addr)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	dw := &DnstapWriter{conn: conn}
	if err = dw.handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dnstap framestream handshake: %w", err)
	}
	return dw, nil
}

func (dw *DnstapWriter) handshake() error {
	if err := fsWriteControl(dw.conn, fsControlReady, dnstapContentType); err != nil {
		return err
	}
	if err := fsReadControl(dw.conn, fsControlAccept); err != nil {
		return err
	}
	return fsWriteControl(dw.conn, fsControlStart, dnstapContentType)
}

// SendDnstap encodes and sends a dnstap AUTH_RESPONSE message for a DNS query/response pair.
func (dw *DnstapWriter) SendDnstap(queryBytes, responseBytes []byte, srcAddr net.IP, srcPort int, isUDP bool, queryTime, responseTime time.Time) error {
	msg := encodeDnstapMsg(queryBytes, responseBytes, srcAddr, srcPort, isUDP, queryTime, responseTime)
	var frame []byte
	frame = pbAppendUint32(frame, 15, 1)  // Dnstap.type = MESSAGE(1)
	frame = pbAppendBytes(frame, 14, msg) // Dnstap.message
	dw.mu.Lock()
	defer dw.mu.Unlock()
	return fsWriteData(dw.conn, frame)
}

// Close sends a STOP control frame and closes the connection.
func (dw *DnstapWriter) Close() {
	dw.mu.Lock()
	defer dw.mu.Unlock()
	_ = fsWriteControl(dw.conn, fsControlStop, "")
	_ = dw.conn.Close()
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
	b = pbAppendVarint(b, fieldNum<<3|0)
	return pbAppendVarint(b, uint64(v))
}

func pbAppendUint64(b []byte, fieldNum uint64, v uint64) []byte {
	b = pbAppendVarint(b, fieldNum<<3|0)
	return pbAppendVarint(b, v)
}

// wire type 5: 32-bit little-endian (fixed32, sfixed32, float)
func pbAppendFixed32(b []byte, fieldNum uint64, v uint32) []byte {
	b = pbAppendVarint(b, fieldNum<<3|5)
	return binary.LittleEndian.AppendUint32(b, v)
}

// --- Dnstap Message encoding (dnstap.proto Message type) ---

func encodeDnstapMsg(queryBytes, responseBytes []byte, srcAddr net.IP, srcPort int, isUDP bool, queryTime, responseTime time.Time) []byte {
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
	msg = pbAppendBytes(msg, 10, queryBytes)                          // Message.query_message
	msg = pbAppendUint64(msg, 12, uint64(responseTime.Unix()))        // Message.response_time_sec
	msg = pbAppendFixed32(msg, 13, uint32(responseTime.Nanosecond())) // Message.response_time_nsec
	msg = pbAppendBytes(msg, 14, responseBytes)                       // Message.response_message
	return msg
}
