// Package xip provides functions to create a DNS server which, when queried
// with a hostname with an embedded IP address, returns that IP Address.  It
// was inspired by xip.io, which was created by Sam Stephenson
package xip

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	Hostmaster = "briancunnie.gmail.com."
	MxHost     = "mail.protonmail.ch."
)

// DomainCustomizations are values that are returned for specific queries.
// The map key is the the domain in question, e.g. "sslip.io." (always include trailing dot).
// For example, when querying for MX records for "sslip.io", return the protonmail servers,
// but when querying for MX records for generic queries, e.g. "127.0.0.1.sslip.io", return the
// default (which happens to be no MX records).
//
// Noticeably absent are the NS records and SOA records. They don't need to be customized
// because they are always the same, regardless of the domain being queried.
type DomainCustomizations map[string]struct {
	A     []dnsmessage.AResource
	AAAA  []dnsmessage.AAAAResource
	CNAME dnsmessage.CNAMEResource
	MX    []dnsmessage.MXResource
	TXT   dnsmessage.TXTResource
}

var (
	// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
	ipv4REDots   = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)
	ipv4REDashes = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])-){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)
	ipv6RE       = regexp.MustCompile(`(^|[.-])(([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)
	ErrNotFound  = errors.New("record not found")
	NameServers  = []string{
		"ns-aws.nono.io.",
		"ns-azure.nono.io.",
		"ns-gce.nono.io.",
	}

	Customizations = DomainCustomizations{
		"sslip.io.": {
			A: []dnsmessage.AResource{
				{A: [4]byte{78, 46, 204, 247}},
			},
			AAAA: []dnsmessage.AAAAResource{
				{AAAA: [16]byte{42, 1, 4, 248, 12, 23, 11, 143, 0, 0, 0, 0, 0, 0, 0, 2}},
			},
			MX: []dnsmessage.MXResource{
				// mail.protonmail.ch
				{
					Pref: 10,
					// Use The Go Playground https://play.golang.org/p/tM4y1eLJ1dg
					// to convert strings to dnsmessage.Name for easy cut-and-paste
					MX: dnsmessage.Name{
						Length: 19,
						Data: [255]byte{
							109, 97, 105, 108, 46, 112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 46, 99, 104, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						},
					},
				},
				// mailsec.protonmail.ch
				{
					Pref: 20,
					MX: dnsmessage.Name{
						Length: 22,
						Data: [255]byte{
							109, 97, 105, 108, 115, 101, 99, 46, 112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 46, 99, 104, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						},
					},
				},
			},
			// although multiple TXT records with multiple strings are allowed, we're sticking
			// with a single TXT record with multiple strings to simplify things, just like AWS
			// does: https://serverfault.com/questions/815841/multiple-txt-fields-for-same-subdomain
			TXT: dnsmessage.TXTResource{
				TXT: []string{"v=spf1 include:_spf.protonmail.ch mx ~all"},
			},
		},
		// nameserver addresses; we get queries for those every once in a while
		"ns-aws.nono.io.":   {A: []dnsmessage.AResource{{A: [4]byte{52, 0, 56, 137}}}},
		"ns-azure.nono.io.": {A: []dnsmessage.AResource{{A: [4]byte{52, 187, 42, 158}}}},
		"ns-gce.nono.io.":   {A: []dnsmessage.AResource{{A: [4]byte{104, 155, 144, 4}}}},
	}
)

// DNSError sets the RCode for failed queries, currently only the ANY query
type DNSError struct {
	RCode dnsmessage.RCode
}

func (e *DNSError) Error() string {
	// https://github.com/golang/go/wiki/CodeReviewComments#error-strings
	// error strings shouldn't have capitals, but in this case it's okay because DNS is an acronym
	return fmt.Sprintf("DNS lookup failure, RCode: %v", e.RCode)
}

// QueryResponse takes in a raw (packed) DNS query and returns a raw (packed)
// DNS response, a string (for logging) that describes the query and the
// response, and an error. It takes in the raw data to offload as much as
// possible from main(). main() is hard to unit test, but functions like
// QueryResponse are not as hard.
//
// Examples of log strings returned:
//   78.46.204.247.33654: TypeA 127-0-0-1.sslip.io ? 127.0.0.1
//   78.46.204.247.33654: TypeA www.sslip.io ? nil, SOA
//   78.46.204.247.33654: TypeNS www.example.com ? NS
//   78.46.204.247.33654: TypeSOA www.example.com ? SOA
//   2600::.33654: TypeAAAA --1.sslip.io ? ::1
func QueryResponse(queryBytes []byte) (responseBytes []byte, logMessage string, err error) {
	var queryHeader dnsmessage.Header
	var response []byte
	var p dnsmessage.Parser

	if queryHeader, err = p.Start(queryBytes); err != nil {
		return
	}

	b := dnsmessage.NewBuilder(response, ResponseHeader(queryHeader, dnsmessage.RCodeSuccess))
	b.EnableCompression()
	if err = b.StartQuestions(); err != nil {
		return
	}
	for {
		var q dnsmessage.Question
		q, err = p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		if err = b.Question(q); err != nil {
			return
		}
		logMessage, err = processQuestion(q, &b)
		if err != nil {
			if e, ok := err.(*DNSError); ok {
				// set RCODE to
				queryHeader.RCode = e.RCode
				b = dnsmessage.NewBuilder(response, ResponseHeader(queryHeader, dnsmessage.RCodeNotImplemented))
				b.EnableCompression()
				break
			} else {
				// processQuestion shouldn't return any error but DNSError,
				// but who knows? Someone might break contract. This is the guard.
				err = fmt.Errorf("processQuestion() returned unexpected error type: %s", err.Error())
				return
			}
		}
	}

	responseBytes, err = b.Finish()
	// I couldn't figure an easy way to test this error condition in Ginkgo
	if err != nil {
		return
	}
	return
}

func processQuestion(q dnsmessage.Question, b *dnsmessage.Builder) (logMessage string, err error) {
	logMessage = q.Type.String() + " " + q.Name.String() + " ? "
	switch q.Type {
	case dnsmessage.TypeA:
		{
			var nameToA *dnsmessage.AResource
			nameToA, err = NameToA(q.Name.String())
			if err != nil {
				// There's only one possible error this can be: ErrNotFound. note that
				// this could be written more efficiently; however, I wrote it to
				// accommodate 'if err != nil' convention. My first version was 'if
				// err == nil', and it flummoxed me.
				err = b.StartAuthorities()
				if err != nil {
					return
				}
				err = b.SOAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
					Length: 0,
				}, SOAResource(q.Name.String()))
				if err != nil {
					return
				}
				logMessage += "nil, SOA"
			} else {
				err = b.StartAnswers()
				if err != nil {
					return
				}
				err = b.AResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeSOA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, *nameToA)
				if err != nil {
					return
				}
				ip := net.IP(nameToA.A[:])
				logMessage += ip.String()
			}
		}
	case dnsmessage.TypeAAAA:
		{
			var nameToAAAA *dnsmessage.AAAAResource
			nameToAAAA, err = NameToAAAA(q.Name.String())
			if err != nil {
				// There's only one possible error this can be: ErrNotFound. note that
				// this could be written more efficiently; however, I wrote it to
				// accommodate 'if err != nil' convention. My first version was 'if
				// err == nil', and it flummoxed me.
				err = b.StartAuthorities()
				if err != nil {
					return
				}
				err = b.SOAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeSOA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
					Length: 0,
				}, SOAResource(q.Name.String()))
				if err != nil {
					return
				}
				logMessage += "nil, SOA"
			} else {
				err = b.StartAnswers()
				if err != nil {
					return
				}
				err = b.AAAAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, *nameToAAAA)
				if err != nil {
					return
				}
				ip := net.IP(nameToAAAA.AAAA[:])
				logMessage += ip.String()
			}
		}
	case dnsmessage.TypeALL:
		{
			// We don't implement type ANY, so return "NotImplemented" like CloudFlare (1.1.1.1)
			// https://blog.cloudflare.com/rfc8482-saying-goodbye-to-any/
			// Google (8.8.8.8) returns every record they can find (A, AAAA, SOA, NS, MX, ...).
			err = &DNSError{RCode: dnsmessage.RCodeNotImplemented}
			return
		}
	case dnsmessage.TypeMX:
		{
			err = b.StartAnswers()
			if err != nil {
				return
			}
			mailExchangers := MXResource(q.Name.String())
			var logMessages []string
			for _, mailExchanger := range mailExchangers {
				err = b.MXResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeMX,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, mailExchanger)
				logMessages = append(logMessages, strconv.Itoa(int(mailExchanger.Pref))+" "+string(mailExchanger.MX.Data[:]))
				if err != nil {
					return
				}
			}
			logMessage += strings.Join(logMessages, ", ")
		}
	case dnsmessage.TypeNS:
		{
			err = b.StartAnswers()
			if err != nil {
				return
			}
			nameServers := NSResources()
			for _, nameServer := range nameServers {
				err = b.NSResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeNS,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, nameServer)
			}
			logMessage += "NS"
		}
	case dnsmessage.TypeSOA:
		{
			err = b.StartAnswers()
			if err != nil {
				return
			}
			err = b.SOAResource(dnsmessage.ResourceHeader{
				Name:   q.Name,
				Type:   dnsmessage.TypeSOA,
				Class:  dnsmessage.ClassINET,
				TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
				Length: 0,
			}, SOAResource(q.Name.String()))
			if err != nil {
				return
			}
			logMessage += "SOA"
		}
	default:
		{
			// default is the same case as an A/AAAA record which is not found,
			// i.e. we return no answers, but we return an authority section
			err = b.StartAuthorities()
			if err != nil {
				return
			}
			err = b.SOAResource(dnsmessage.ResourceHeader{
				Name:   q.Name,
				Type:   dnsmessage.TypeSOA,
				Class:  dnsmessage.ClassINET,
				TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
				Length: 0,
			}, SOAResource(q.Name.String()))
			if err != nil {
				return
			}
			logMessage += "nil, SOA"
		}
	}
	return
}

// ResponseHeader returns a pre-fab DNS response header. Note that we're always
// authoritative and therefore recursion is never available.  We're able to
// "white label" domains by indiscriminately matching every query that comes
// our way. Not being recursive has the added benefit of not being usable as an
// amplifier in a DDOS attack. We pass in the RCODE, which is normally RCodeSuccess
// but can also be a failure (e.g. ANY type we return RCodeNotImplemented)
func ResponseHeader(query dnsmessage.Header, rcode dnsmessage.RCode) dnsmessage.Header {
	return dnsmessage.Header{
		ID:                 query.ID,
		Response:           true,
		OpCode:             0,
		Authoritative:      true,
		Truncated:          false,
		RecursionDesired:   query.RecursionDesired,
		RecursionAvailable: false,
		RCode:              rcode,
	}
}

// NameToA returns either an AResource that matched the hostname or ErrNotFound
func NameToA(fqdnString string) (*dnsmessage.AResource, error) {
	fqdn := []byte(fqdnString)
	// is it a customized A record? If so, return early
	if domain, ok := Customizations[fqdnString]; ok && len(domain.A) > 0 {
		return &domain.A[0], nil // TODO: handle multiple A records
	}
	for _, ipv4RE := range []*regexp.Regexp{ipv4REDots, ipv4REDashes} {
		if ipv4RE.Match(fqdn) {
			match := string(ipv4RE.FindSubmatch(fqdn)[2])
			match = strings.Replace(match, "-", ".", -1)
			ipv4address := net.ParseIP(match).To4()
			return &dnsmessage.AResource{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}}, nil
		}
	}
	return &dnsmessage.AResource{}, ErrNotFound
}

// NameToAAAA NameToA returns either an AAAAResource that matched the hostname
// or ErrNotFound
func NameToAAAA(fqdnString string) (*dnsmessage.AAAAResource, error) {
	fqdn := []byte(fqdnString)
	// is it a customized AAAA record? If so, return early
	if domain, ok := Customizations[fqdnString]; ok && len(domain.AAAA) > 0 {
		return &domain.AAAA[0], nil // TODO: handle multiple AAAA records
	}
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

func NSResources() map[string]dnsmessage.NSResource {
	nsResources := make(map[string]dnsmessage.NSResource)
	for _, nameServer := range NameServers {
		var nameServerBytes [255]byte
		copy(nameServerBytes[:], nameServer)
		nsResources[nameServer] = dnsmessage.NSResource{
			NS: dnsmessage.Name{
				Data:   nameServerBytes,
				Length: uint8(len(nameServer)),
			},
		}
	}
	return nsResources
}

func MXResource(fqdnString string) []dnsmessage.MXResource {
	if domain, ok := Customizations[fqdnString]; ok && len(domain.MX) > 0 {
		return domain.MX
	}
	var mxHostBytes [255]byte
	copy(mxHostBytes[:], fqdnString)
	return []dnsmessage.MXResource{
		{
			Pref: 0,
			MX: dnsmessage.Name{
				Data:   mxHostBytes,
				Length: uint8(len(fqdnString)),
			},
		},
	}
}

// SOAResource returns the hard-coded SOA
func SOAResource(fqdnString string) dnsmessage.SOAResource {
	var domainBytes [255]byte
	copy(domainBytes[:], fqdnString)
	var mboxArray [255]byte
	copy(mboxArray[:], Hostmaster)
	return dnsmessage.SOAResource{
		NS: dnsmessage.Name{
			Data:   domainBytes,
			Length: uint8(len(fqdnString)),
		},
		MBox: dnsmessage.Name{
			Data:   mboxArray,
			Length: uint8(len(Hostmaster)),
		},
		Serial: 2020121000,
		// I cribbed the Refresh/Retry/Expire from google.com
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  300,
	}
}
