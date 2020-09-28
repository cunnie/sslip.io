// Package xip provides functions to create a DNS server which, when queried
// with a hostname with an embedded IP address, returns that IP Address.  It
// was inspired by xip.io, which was created by Sam Stephenson
package xip

import (
	"errors"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
var ipv4RE = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.-]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)
var ipv6RE = regexp.MustCompile(`(^|[.-])(([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)
var ErrNotFound = errors.New("record not found")

const (
	Hostmaster = "yoyo.nono.io."
	MxHost     = "mail.protonmail.ch."
)

// QueryResponse takes in a raw (packed) DNS query and returns a raw (packed)
// DNS response It takes in the raw data to offload as much as possible from
// main(). main() is hard to unit test, but functions like QueryResponse are
// easy.
func QueryResponse(queryBytes []byte) ([]byte, error) {
	var queryHeader dnsmessage.Header
	var err error
	var response []byte
	var p dnsmessage.Parser

	if queryHeader, err = p.Start(queryBytes); err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(response, ResponseHeader(queryHeader))
	b.EnableCompression()
	if err = b.StartQuestions(); err != nil {
		return nil, err
	}
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if err = b.Question(q); err != nil {
			return nil, err
		}
		err = processQuestion(q, &b)
		if err != nil {
			return nil, err
		}
	}

	responseBytes, err := b.Finish()
	// I couldn't figure an easy way to test the error condition in Ginkgo
	if err != nil {
		return nil, err
	}
	return responseBytes, nil
}

func processQuestion(q dnsmessage.Question, b *dnsmessage.Builder) error {
	switch q.Type {
	case dnsmessage.TypeA:
		{
			nameToA, err := NameToA(q.Name.String())
			if err != nil {
				// There's only one possible error this can be: ErrNotFound. note that
				// this could be written more efficiently; however, I wrote it to
				// accommodate 'if err != nil' convention. My first version was 'if
				// err == nil', and it flummoxed me.
				err = b.StartAuthorities()
				if err != nil {
					return err
				}
				err = b.SOAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
					Length: 0,
				}, SOAResource(q.Name.String()))
				if err != nil {
					return err
				}
			} else {
				err = b.StartAnswers()
				if err != nil {
					return err
				}
				err = b.AResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeSOA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, *nameToA)
				if err != nil {
					return err
				}
			}
		}
	case dnsmessage.TypeAAAA:
		{
			nameToAAAA, err := NameToAAAA(q.Name.String())
			if err != nil {
				// There's only one possible error this can be: ErrNotFound. note that
				// this could be written more efficiently; however, I wrote it to
				// accommodate 'if err != nil' convention. My first version was 'if
				// err == nil', and it flummoxed me.
				err = b.StartAuthorities()
				if err != nil {
					return err
				}
				err = b.SOAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeSOA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
					Length: 0,
				}, SOAResource(q.Name.String()))
				if err != nil {
					return err
				}
			} else {
				err = b.StartAnswers()
				if err != nil {
					return err
				}
				err = b.AAAAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, *nameToAAAA)
				if err != nil {
					return err
				}
			}
		}
	case dnsmessage.TypeMX:
		{
			err := b.StartAnswers()
			if err != nil {
				return err
			}
			err = b.MXResource(dnsmessage.ResourceHeader{
				Name:   q.Name,
				Type:   dnsmessage.TypeMX,
				Class:  dnsmessage.ClassINET,
				TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
				Length: 0,
			}, MXResource())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ResponseHeader returns a pre-fab DNS response header. Note that we're always
// authoritative and therefore recursion is never available.  We're able to
// "white label" domains by indiscriminately matching every query that comes
// our way. Not being recursive has the added benefit of not being usable as an
// amplifier in a DDOS attack
func ResponseHeader(query dnsmessage.Header) dnsmessage.Header {
	return dnsmessage.Header{
		ID:                 query.ID,
		Response:           true,
		OpCode:             0,
		Authoritative:      true,
		Truncated:          false,
		RecursionDesired:   query.RecursionDesired,
		RecursionAvailable: false,
	}
}

// NameToA returns either an AResource that matched the hostname or ErrNotFound
func NameToA(fqdnString string) (*dnsmessage.AResource, error) {
	fqdn := []byte(fqdnString)
	if !ipv4RE.Match(fqdn) {
		return &dnsmessage.AResource{}, ErrNotFound
	}

	match := string(ipv4RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ".", -1)
	ipv4address := net.ParseIP(match).To4()

	return &dnsmessage.AResource{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}}, nil
}

// NameToAAAA NameToA returns either an AAAAResource that matched the hostname
// or ErrNotFound
func NameToAAAA(fqdnString string) (*dnsmessage.AAAAResource, error) {
	fqdn := []byte(fqdnString)
	if !ipv6RE.Match(fqdn) {
		return &dnsmessage.AAAAResource{}, ErrNotFound
	}

	match := string(ipv6RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ":", -1)
	ipv16address := net.ParseIP(match).To16()

	AAAAR := dnsmessage.AAAAResource{}
	for i := range ipv16address {
		AAAAR.AAAA[i] = ipv16address[i]
	}
	return &AAAAR, nil
}

func MXResource() dnsmessage.MXResource {
	var mxHostBytes [255]byte
	copy(mxHostBytes[:], MxHost)
	return dnsmessage.MXResource{
		Pref: 0,
		MX: dnsmessage.Name{
			Data:   mxHostBytes,
			Length: uint8(len(MxHost)),
		},
	}
}

// SOAResource returns the hard-coded SOA
func SOAResource(domain string) dnsmessage.SOAResource {
	var domainBytes [255]byte
	copy(domainBytes[:], domain)
	var mboxArray [255]byte
	copy(mboxArray[:], Hostmaster)
	return dnsmessage.SOAResource{
		NS: dnsmessage.Name{
			Data:   domainBytes,
			Length: uint8(len(domain)),
		},
		MBox: dnsmessage.Name{
			Data:   mboxArray,
			Length: uint8(len(Hostmaster)),
		},
		Serial: 2020090400,
		// I cribbed the Refresh/Retry/Expire from google.com
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  300,
	}
}
