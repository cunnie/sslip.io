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

// DomainCustomizations are values that are returned for specific queries.
// The map key is the the domain in question, e.g. "sslip.io." (always include trailing dot).
// For example, when querying for MX records for "sslip.io", return the protonmail servers,
// but when querying for MX records for generic queries, e.g. "127.0.0.1.sslip.io", return the
// default (which happens to be no MX records).
//
// Noticeably absent are the NS records and SOA records. They don't need to be customized
// because they are always the same, regardless of the domain being queried.
type DomainCustomization struct {
	A     []dnsmessage.AResource
	AAAA  []dnsmessage.AAAAResource
	CNAME dnsmessage.CNAMEResource
	MX    []dnsmessage.MXResource
	TXT   []dnsmessage.TXTResource
}

type DomainCustomizations map[string]DomainCustomization

var (
	ipv4REDots   = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	ipv4REDashes = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?[0-9])?[0-9])-){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
	ipv6RE           = regexp.MustCompile(`(^|[.-])(([0-9a-fA-F]{1,4}-){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|--(ffff(-0{1,4})?-)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	ErrNotFound      = errors.New("record not found")
	// Use The Go Playground https://play.golang.org/p/G2BYkakyj-R
	// to convert strings to dnsmessage.Name for easy cut-and-paste
	NameServers = []dnsmessage.NSResource{
		// ns-aws.nono.io.
		{
			NS: dnsmessage.Name{
				Length: 15,
				Data: [255]byte{
					110, 115, 45, 97, 119, 115, 46, 110, 111, 110, 111, 46, 105, 111, 46,
				},
			},
		},
		// ns-azure.nono.io.
		{
			NS: dnsmessage.Name{
				Length: 17,
				Data: [255]byte{
					110, 115, 45, 97, 122, 117, 114, 101, 46, 110, 111, 110, 111, 46, 105, 111, 46,
				},
			},
		},
		// ns-gce.nono.io.
		{
			NS: dnsmessage.Name{
				Length: 15,
				Data: [255]byte{
					110, 115, 45, 103, 99, 101, 46, 110, 111, 110, 111, 46, 105, 111, 46,
				},
			},
		},
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
					MX: dnsmessage.Name{
						Length: 19,
						Data: [255]byte{
							109, 97, 105, 108, 46, 112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 46, 99, 104, 46,
						},
					},
				},
				// mailsec.protonmail.ch
				{
					Pref: 20,
					MX: dnsmessage.Name{
						Length: 22,
						Data: [255]byte{
							109, 97, 105, 108, 115, 101, 99, 46, 112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 46, 99, 104, 46,
						},
					},
				},
			},
			// Although multiple TXT records with multiple strings are allowed, we're sticking
			// with a multiple TXT records with a single string apiece because that's what ProtonMail requires
			// and that's what google.com does.
			TXT: []dnsmessage.TXTResource{
				{TXT: []string{"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26"}}, // ProtonMail verification; don't delete
				{TXT: []string{"v=spf1 include:_spf.protonmail.ch mx ~all"}},                        // Sender Policy Framework
			},
		},
		// nameserver addresses; we get queries for those every once in a while
		"ns-aws.nono.io.":   {A: []dnsmessage.AResource{{A: [4]byte{52, 0, 56, 137}}}},
		"ns-azure.nono.io.": {A: []dnsmessage.AResource{{A: [4]byte{52, 187, 42, 158}}}},
		"ns-gce.nono.io.":   {A: []dnsmessage.AResource{{A: [4]byte{104, 155, 144, 4}}}},
		// CNAMEs for sslip.io for DKIM signing
		"protonmail._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dnsmessage.Name{
					// protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.
					Length: 93,
					Data: [255]byte{
						112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 46, 100, 111, 109, 97, 105, 110, 107, 101, 121, 46, 100, 119, 52, 103, 121, 107, 118, 53, 105, 50, 98, 114, 116, 107, 106, 103, 108, 114, 102, 51, 52, 119, 102, 54, 107, 98, 120, 112, 97, 53, 104, 103, 116, 109, 103, 50, 120, 113, 111, 112, 105, 110, 104, 103, 120, 110, 53, 97, 120, 111, 55, 51, 97, 46, 100, 111, 109, 97, 105, 110, 115, 46, 112, 114, 111, 116, 111, 110, 46, 99, 104, 46,
					},
				},
			},
		},
		"protonmail2._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dnsmessage.Name{
					// protonmail2.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.
					Length: 94,
					Data: [255]byte{
						112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 50, 46, 100, 111, 109, 97, 105, 110, 107, 101, 121, 46, 100, 119, 52, 103, 121, 107, 118, 53, 105, 50, 98, 114, 116, 107, 106, 103, 108, 114, 102, 51, 52, 119, 102, 54, 107, 98, 120, 112, 97, 53, 104, 103, 116, 109, 103, 50, 120, 113, 111, 112, 105, 110, 104, 103, 120, 110, 53, 97, 120, 111, 55, 51, 97, 46, 100, 111, 109, 97, 105, 110, 115, 46, 112, 114, 111, 116, 111, 110, 46, 99, 104, 46,
					},
				},
			},
		},
		"protonmail3._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dnsmessage.Name{
					// protonmail3.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.
					Length: 94,
					Data: [255]byte{
						112, 114, 111, 116, 111, 110, 109, 97, 105, 108, 51, 46, 100, 111, 109, 97, 105, 110, 107, 101, 121, 46, 100, 119, 52, 103, 121, 107, 118, 53, 105, 50, 98, 114, 116, 107, 106, 103, 108, 114, 102, 51, 52, 119, 102, 54, 107, 98, 120, 112, 97, 53, 104, 103, 116, 109, 103, 50, 120, 113, 111, 112, 105, 110, 104, 103, 120, 110, 53, 97, 120, 111, 55, 51, 97, 46, 100, 111, 109, 97, 105, 110, 115, 46, 112, 114, 111, 116, 111, 110, 46, 99, 104, 46,
					},
				},
			},
		},
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
			var nameToAs []dnsmessage.AResource
			nameToAs, err = NameToA(q.Name.String())
			if err != nil {
				// There's only one possible error this can be: ErrNotFound. note that
				// this could be written more efficiently; however, I wrote it to
				// accommodate 'if err != nil' convention. My first version was 'if
				// err == nil', and it flummoxed me.
				err = noAnswersOnlyAuthorities(q, b, &logMessage)
				return
			} else {
				err = b.StartAnswers()
				if err != nil {
					return
				}
				var logMessages []string
				for _, nameToA := range nameToAs {
					err = b.AResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypeAAAA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, nameToA)
					if err != nil {
						return
					}
					ip := net.IP(nameToA.A[:])
					logMessages = append(logMessages, ip.String())
				}
				logMessage += strings.Join(logMessages, ", ")
			}
		}
	case dnsmessage.TypeAAAA:
		{
			var nameToAAAAs []dnsmessage.AAAAResource
			nameToAAAAs, err = NameToAAAA(q.Name.String())
			if err != nil {
				// There's only one possible error this can be: ErrNotFound
				err = noAnswersOnlyAuthorities(q, b, &logMessage)
				return
			} else {
				err = b.StartAnswers()
				if err != nil {
					return
				}
				var logMessages []string
				for _, nameToAAAA := range nameToAAAAs {
					err = b.AAAAResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypeAAAA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, nameToAAAA)
					if err != nil {
						return
					}
					ip := net.IP(nameToAAAA.AAAA[:])
					logMessages = append(logMessages, ip.String())
				}
				logMessage += strings.Join(logMessages, ", ")
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
	case dnsmessage.TypeCNAME:
		{
			err = b.StartAnswers()
			if err != nil {
				return
			}
			var cname *dnsmessage.CNAMEResource
			cname, err = CNAMEResource(q.Name.String())
			if err != nil {
				err = noAnswersOnlyAuthorities(q, b, &logMessage)
				return
			}
			err = b.CNAMEResource(dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeCNAME,
				Class: dnsmessage.ClassINET,
				// aggressively expire (5 mins) CNAME records until we are sure sslip.io's CNAMEs are correct
				TTL:    300,
				Length: 0,
			}, *cname)
			if err != nil {
				return
			}
			logMessage += "CNAME " + cname.CNAME.String()
		}
	case dnsmessage.TypeMX:
		{
			err = b.StartAnswers()
			if err != nil {
				return
			}
			mailExchangers := MxResources(q.Name.String())
			var logMessages []string
			for _, mailExchanger := range mailExchangers {
				err = b.MXResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeMX,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, mailExchanger)
				logMessages = append(logMessages, strconv.Itoa(int(mailExchanger.Pref))+" "+string(mailExchanger.MX.Data[:mailExchanger.MX.Length]))
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
			nameServers := NSResources(q.Name.String())
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
	case dnsmessage.TypeTXT:
		{
			err = b.StartAnswers()
			if err != nil {
				return
			}
			var txts []dnsmessage.TXTResource
			txts, err = TXTResources(q.Name.String())
			if err != nil {
				err = noAnswersOnlyAuthorities(q, b, &logMessage)
				return
			}
			var logMessageTXTss []string
			for _, txt := range txts {
				err = b.TXTResource(dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
					// aggressively expire (5 mins) TXT records, long enough to obtain a Let's Encrypt cert,
					// but short enough to free up frequently-used domains (e.g. 192.168.0.1.sslip.io) for the next user
					TTL:    300,
					Length: 0,
				}, txt)
				if err != nil {
					return
				}
				var logMessageTXTs []string
				for _, TXTstring := range txt.TXT {
					logMessageTXTs = append(logMessageTXTs, TXTstring)
				}
				logMessageTXTss = append(logMessageTXTss, `TXT "`+strings.Join(logMessageTXTs, `", "`)+`"`)
			}
			logMessage += strings.Join(logMessageTXTss, " ")
		}
	default:
		{
			// default is the same case as an A/AAAA record which is not found,
			// i.e. we return no answers, but we return an authority section
			err = noAnswersOnlyAuthorities(q, b, &logMessage)
			return
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

// NameToA returns either an []AResource that matched the hostname or ErrNotFound
func NameToA(fqdnString string) ([]dnsmessage.AResource, error) {
	fqdn := []byte(fqdnString)
	// is it a customized A record? If so, return early
	if domain, ok := Customizations[fqdnString]; ok && len(domain.A) > 0 {
		return domain.A, nil
	}
	for _, ipv4RE := range []*regexp.Regexp{ipv4REDashes, ipv4REDots} {
		if ipv4RE.Match(fqdn) {
			match := string(ipv4RE.FindSubmatch(fqdn)[2])
			match = strings.Replace(match, "-", ".", -1)
			ipv4address := net.ParseIP(match).To4()
			return []dnsmessage.AResource{
				{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}},
			}, nil
		}
	}
	return nil, ErrNotFound
}

// NameToAAAA returns either []AAAAResource that matched the hostname
// or ErrNotFound
func NameToAAAA(fqdnString string) ([]dnsmessage.AAAAResource, error) {
	fqdn := []byte(fqdnString)
	// is it a customized AAAA record? If so, return early
	if domain, ok := Customizations[fqdnString]; ok && len(domain.AAAA) > 0 {
		return domain.AAAA, nil
	}
	if !ipv6RE.Match(fqdn) {
		return nil, ErrNotFound
	}

	ipv6RE.Longest()
	match := string(ipv6RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ":", -1)
	ipv16address := net.ParseIP(match).To16()

	AAAAR := dnsmessage.AAAAResource{}
	for i := range ipv16address {
		AAAAR.AAAA[i] = ipv16address[i]
	}
	return []dnsmessage.AAAAResource{AAAAR}, nil
}

func CNAMEResource(fqdnString string) (*dnsmessage.CNAMEResource, error) {
	if domain, ok := Customizations[fqdnString]; ok && domain.CNAME != (dnsmessage.CNAMEResource{}) {
		return &domain.CNAME, nil
	}
	return nil, ErrNotFound
}

func MxResources(fqdnString string) []dnsmessage.MXResource {
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

func NSResources(fqdnString string) []dnsmessage.NSResource {
	return NameServers
}

// SOAResource returns the hard-coded (except MNAME) SOA
func SOAResource(fqdnString string) dnsmessage.SOAResource {
	var domainBytes [255]byte
	copy(domainBytes[:], fqdnString)
	return dnsmessage.SOAResource{
		NS: dnsmessage.Name{
			Data:   domainBytes,
			Length: uint8(len(fqdnString)),
		},
		// "briancunnie.gmail.com."
		MBox: dnsmessage.Name{
			Length: 22,
			Data: [255]byte{
				98, 114, 105, 97, 110, 99, 117, 110, 110, 105, 101, 46, 103, 109, 97, 105, 108, 46, 99, 111, 109, 46,
			},
		},
		Serial: 2020122000,
		// cribbed the Refresh/Retry/Expire from google.com
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  300,
	}
}

func TXTResources(fqdnString string) ([]dnsmessage.TXTResource, error) {
	if domain, ok := Customizations[fqdnString]; ok {
		return domain.TXT, nil
	}
	return nil, ErrNotFound
}

func noAnswersOnlyAuthorities(q dnsmessage.Question, b *dnsmessage.Builder, logMessage *string) error {
	err := b.StartAuthorities()
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
	*logMessage += "nil, SOA"
	return nil
}
