// Package xip provides functions to create a DNS server which, when queried
// with a hostname with an embedded IP address, returns that IP Address.  It
// was inspired by xip.io, which was created by Sam Stephenson
package xip

import (
	"errors"
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

// There's nothing like global variables to make my heart pound with joy.
// Some of these are global because they are, in essence, constants which
// I don't want to waste time recreating with every function call.
// But `Customizations` is a true global variable.
var (
	ipv4REDots   = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	ipv4REDashes = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?[0-9])?[0-9])-){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
	ipv6RE           = regexp.MustCompile(`(^|[.-])(([0-9a-fA-F]{1,4}-){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|--(ffff(-0{1,4})?-)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	dns01ChallengeRE = regexp.MustCompile(`(?i)_acme-challenge\.`)
	nsAws, _         = dnsmessage.NewName("ns-aws.nono.io.")
	nsAzure, _       = dnsmessage.NewName("ns-azure.nono.io.")
	nsGce, _         = dnsmessage.NewName("ns-gce.nono.io.")
	NameServers      = []dnsmessage.NSResource{
		{NS: nsAws},
		{NS: nsAzure},
		{NS: nsGce},
	}

	mbox, _        = dnsmessage.NewName("briancunnie.gmail.com.")
	mx1, _         = dnsmessage.NewName("mail.protonmail.ch.")
	mx2, _         = dnsmessage.NewName("mailsec.protonmail.ch.")
	dkim1, _       = dnsmessage.NewName("protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.")
	dkim2, _       = dnsmessage.NewName("protonmail2.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.")
	dkim3, _       = dnsmessage.NewName("protonmail3.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.")
	Customizations = DomainCustomizations{
		"sslip.io.": {
			A: []dnsmessage.AResource{
				{A: [4]byte{78, 46, 204, 247}},
			},
			AAAA: []dnsmessage.AAAAResource{
				{AAAA: [16]byte{42, 1, 4, 248, 12, 23, 11, 143, 0, 0, 0, 0, 0, 0, 0, 2}},
			},
			MX: []dnsmessage.MXResource{
				{
					Pref: 10,
					MX:   mx1,
				},
				{
					Pref: 20,
					MX:   mx2,
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
				CNAME: dkim1,
			},
		},
		"protonmail2._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim2,
			},
		},
		"protonmail3._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim3,
			},
		},
	}
)

// Response Why do I have a crazy struct of fields of arrays of functions?
// It's because I can't use dnsmessage.Builder as I had hoped; specifically
// I need to set the Header _after_ I process the message, but Builder expects
// it to be set first, so I use the functions as a sort of batch process to
// create the Builder. What in Header needs to be tweaked? Certain TXT records
// need to unset the authoritative field, and queries for ANY record need
// to set the rcode.
type Response struct {
	Header      dnsmessage.Header
	Answers     []func(*dnsmessage.Builder) error
	Authorities []func(*dnsmessage.Builder) error
	Additionals []func(*dnsmessage.Builder) error
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
	var p dnsmessage.Parser
	var response = &Response{}

	if queryHeader, err = p.Start(queryBytes); err != nil {
		return nil, "", err
	}
	var q dnsmessage.Question
	// we only answer the first question even though there technically may be more than one;
	// de facto there's one and only one question
	if q, err = p.Question(); err != nil {
		return nil, "", err
	}
	response.Header = ResponseHeader(queryHeader, dnsmessage.RCodeSuccess)
	logMessage, err = processQuestion(q, response)
	if err != nil {
		return nil, "", err
	}

	b := dnsmessage.NewBuilder(nil, response.Header)
	b.EnableCompression()
	if err = b.StartQuestions(); err != nil {
		return nil, "", err
	}
	if err = b.Question(q); err != nil {
		return
	}
	if err = b.StartAnswers(); err != nil {
		return nil, "", err
	}
	for _, answer := range response.Answers {
		if err = answer(&b); err != nil {
			return nil, "", err
		}
	}
	if err = b.StartAuthorities(); err != nil {
		return nil, "", err
	}
	for _, authority := range response.Authorities {
		if err = authority(&b); err != nil {
			return nil, "", err
		}
	}
	if err = b.StartAdditionals(); err != nil {
		return nil, "", err
	}
	for _, additionals := range response.Additionals {
		if err = additionals(&b); err != nil {
			return nil, "", err
		}
	}
	if responseBytes, err = b.Finish(); err != nil {
		return nil, "", err
	}
	return responseBytes, logMessage, nil
}

func processQuestion(q dnsmessage.Question, response *Response) (logMessage string, _ error) {
	var err error
	logMessage = q.Type.String() + " " + q.Name.String() + " ? "
	if IsAcmeChallenge(q.Name.String()) { // thanks @NormanR
		// delegate everything to its stripped (remove "_acme-challenge.") address, e.g.
		// dig _acme-challenge.127-0-0-1.sslip.io mx → NS 127-0-0-1.sslip.io
		response.Header.Authoritative = false // we're delegating, so we're not authoritative
		return NSResponse(q.Name, response, logMessage)
	}
	switch q.Type {
	case dnsmessage.TypeA:
		{
			var nameToAs []dnsmessage.AResource
			nameToAs = NameToA(q.Name.String())
			if len(nameToAs) == 0 {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 or more A records; A records > 1 only available via Customizations
				func(b *dnsmessage.Builder) error {
					for _, nameToA := range nameToAs {
						err = b.AResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, nameToA)
						if err != nil {
							return err
						}
					}
					return nil
				})
			var logMessages []string
			for _, nameToA := range nameToAs {
				ip := net.IP(nameToA.A[:])
				logMessages = append(logMessages, ip.String())
			}
			return logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeAAAA:
		{
			var nameToAAAAs []dnsmessage.AAAAResource
			nameToAAAAs = NameToAAAA(q.Name.String())
			if len(nameToAAAAs) == 0 {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 or more AAAA records; AAAA records > 1 only available via Customizations
				func(b *dnsmessage.Builder) error {
					for _, nameToAAAA := range nameToAAAAs {
						err = b.AAAAResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeAAAA,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, nameToAAAA)
						if err != nil {
							return err
						}
					}
					return nil
				})
			var logMessages []string
			for _, nameToAAAA := range nameToAAAAs {
				ip := net.IP(nameToAAAA.AAAA[:])
				logMessages = append(logMessages, ip.String())
			}
			return logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeALL:
		{
			// We don't implement type ANY, so return "NotImplemented" like CloudFlare (1.1.1.1)
			// https://blog.cloudflare.com/rfc8482-saying-goodbye-to-any/
			// Google (8.8.8.8) returns every record they can find (A, AAAA, SOA, NS, MX, ...).
			response.Header.RCode = dnsmessage.RCodeNotImplemented
			return logMessage + "NotImplemented", nil
		}
	case dnsmessage.TypeCNAME:
		{
			// If there is a CNAME, there can only be 1, and only from Customizations
			var cname *dnsmessage.CNAMEResource
			cname = CNAMEResource(q.Name.String())
			if cname == nil {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 CNAME record, via Customizations
				func(b *dnsmessage.Builder) error {
					err = b.CNAMEResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypeCNAME,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, *cname)
					if err != nil {
						return err
					}
					return nil
				})
			return logMessage + cname.CNAME.String(), nil
		}
	case dnsmessage.TypeMX:
		{
			mailExchangers := MXResources(q.Name.String())
			var logMessages []string

			// We can be sure that len(mailExchangers) > 1, but we check anyway
			if len(mailExchangers) == 0 {
				return "", errors.New("no MX records, but there should be one")
			}
			response.Answers = append(response.Answers,
				// 1 or more A records; A records > 1 only available via Customizations
				func(b *dnsmessage.Builder) error {
					for _, mailExchanger := range mailExchangers {
						err = b.MXResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeMX,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, mailExchanger)
					}
					if err != nil {
						return err
					}
					return nil
				})
			for _, mailExchanger := range mailExchangers {
				logMessages = append(logMessages, strconv.Itoa(int(mailExchanger.Pref))+" "+mailExchanger.MX.String())
			}
			return logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeNS:
		{
			return NSResponse(q.Name, response, logMessage)
		}
	case dnsmessage.TypeSOA:
		{
			soaResource := SOAResource(q.Name)
			response.Answers = append(response.Answers,
				func(b *dnsmessage.Builder) error {
					err = b.SOAResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypeSOA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, soaResource)
					if err != nil {
						return err
					}
					return nil
				})
			return logMessage + soaLogMessage(soaResource), nil
		}
	case dnsmessage.TypeTXT:
		{
			// if it's an "_acme-challenge." TXT, we return no answer but an NS authority & not authoritative
			// if it's customized records, we return them in the Answers
			// otherwise we return no Answers and Authorities SOA
			if IsAcmeChallenge(q.Name.String()) {
				// No Answers, Not Authoritative, Authorities contain NS records
				response.Header.Authoritative = false
				nameServers := NSResources(q.Name.String())
				var logMessages []string
				for _, nameServer := range nameServers {
					response.Authorities = append(response.Authorities,
						// 1 or more A records; A records > 1 only available via Customizations
						func(b *dnsmessage.Builder) error {
							err = b.NSResource(dnsmessage.ResourceHeader{
								Name:   q.Name,
								Type:   dnsmessage.TypeNS,
								Class:  dnsmessage.ClassINET,
								TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
								Length: 0,
							}, nameServer)
							if err != nil {
								return err
							}
							return nil
						})
					logMessages = append(logMessages, nameServer.NS.String())
				}
				return logMessage + "nil, NS " + strings.Join(logMessages, ", "), nil
			}
			var txts []dnsmessage.TXTResource
			txts = TXTResources(q.Name.String())
			if len(txts) == 0 {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 or more TXT records via Customizations
				// Technically there can be more than one TXT record, but practically there can only be one record
				// but with multiple strings
				func(b *dnsmessage.Builder) error {
					for _, txt := range txts {
						err = b.TXTResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeTXT,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, txt)
						if err != nil {
							return err
						}
					}
					return nil
				})
			var logMessageTXTss []string
			for _, txt := range txts {
				var logMessageTXTs []string
				for _, TXTstring := range txt.TXT {
					logMessageTXTs = append(logMessageTXTs, TXTstring)
				}
				logMessageTXTss = append(logMessageTXTss, `["`+strings.Join(logMessageTXTs, `", "`)+`"]`)
			}
			return logMessage + strings.Join(logMessageTXTss, ", "), nil
		}
	default:
		{
			// default is the same case as an A/AAAA record which is not found,
			// i.e. we return no answers, but we return an authority section
			// No Answers, only 1 Authorities
			soaHeader, soaResource := SOAAuthority(q.Name)
			response.Authorities = append(response.Authorities,
				func(b *dnsmessage.Builder) error {
					if err = b.SOAResource(soaHeader, soaResource); err != nil {
						return err
					}
					return nil
				})
			return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
		}
	}
	// The following is flagged as "Unreachable code" in Goland, and that's expected
	return "", errors.New("unexpectedly fell through processQuestion()")
}

// NSResponse sets the Answers/Authorities depending whether we're delegating or authoritative
// (whether it's an "_acme-challenge." domain or not). Either way, it supplies the Additionals
// (IP addresses of the nameservers).
func NSResponse(name dnsmessage.Name, response *Response, logMessage string) (string, error) {
	nameServers := NSResources(name.String())
	var logMessages []string
	if response.Header.Authoritative {
		// we're authoritative, so we reply with the answers
		response.Answers = append(response.Answers,
			func(b *dnsmessage.Builder) error {
				for _, nameServer := range nameServers {
					err := b.NSResource(dnsmessage.ResourceHeader{
						Name:   name,
						Type:   dnsmessage.TypeNS,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, nameServer)
					if err != nil {
						return err
					}
				}
				return nil
			})
	} else {
		// we're NOT authoritative, so we reply who is authoritative
		response.Authorities = append(response.Authorities,
			func(b *dnsmessage.Builder) error {
				for _, nameServer := range nameServers {
					err := b.NSResource(dnsmessage.ResourceHeader{
						Name:   name,
						Type:   dnsmessage.TypeNS,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, nameServer)
					if err != nil {
						return err
					}
				}
				return nil
			})
		logMessage += "nil, NS " // we're not supplying an answer; we're supplying the NS record that's authoritative
	}
	response.Additionals = append(response.Additionals,
		func(b *dnsmessage.Builder) error {
			for _, nameServer := range nameServers {
				for _, aResource := range NameToA(nameServer.NS.String()) {
					err := b.AResource(dnsmessage.ResourceHeader{
						Name:   nameServer.NS,
						Type:   dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, aResource)
					if err != nil {
						return err
					}
				}
				for _, aaaaResource := range NameToAAAA(nameServer.NS.String()) {
					err := b.AAAAResource(dnsmessage.ResourceHeader{
						Name:   nameServer.NS,
						Type:   dnsmessage.TypeAAAA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, aaaaResource)
					if err != nil {
						return err
					}
				}
			}
			return nil
		})
	for _, nameServer := range nameServers {
		logMessages = append(logMessages, nameServer.NS.String())
	}
	return logMessage + strings.Join(logMessages, ", "), nil
}

// ResponseHeader returns a pre-fab DNS response header.
// We are almost always authoritative (exception: _acme-challenge TXT records)
// We are not recursing
// servers, so recursion is never available.  We're able to
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

// NameToA returns an []AResource that matched the hostname
func NameToA(fqdnString string) []dnsmessage.AResource {
	fqdn := []byte(fqdnString)
	// is it a customized A record? If so, return early
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.A) > 0 {
		return domain.A
	}
	for _, ipv4RE := range []*regexp.Regexp{ipv4REDashes, ipv4REDots} {
		if ipv4RE.Match(fqdn) {
			match := string(ipv4RE.FindSubmatch(fqdn)[2])
			match = strings.Replace(match, "-", ".", -1)
			ipv4address := net.ParseIP(match).To4()
			return []dnsmessage.AResource{
				{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}},
			}
		}
	}
	return []dnsmessage.AResource{}
}

// NameToAAAA returns an []AAAAResource that matched the hostname
func NameToAAAA(fqdnString string) []dnsmessage.AAAAResource {
	fqdn := []byte(fqdnString)
	// is it a customized AAAA record? If so, return early
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.AAAA) > 0 {
		return domain.AAAA
	}
	if !ipv6RE.Match(fqdn) {
		return []dnsmessage.AAAAResource{}
	}

	ipv6RE.Longest()
	match := string(ipv6RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ":", -1)
	ipv16address := net.ParseIP(match).To16()
	if ipv16address == nil {
		// We shouldn't reach here because `match` should always be valid, but we're not optimists
		return []dnsmessage.AAAAResource{}
	}

	AAAAR := dnsmessage.AAAAResource{}
	for i := range ipv16address {
		AAAAR.AAAA[i] = ipv16address[i]
	}
	return []dnsmessage.AAAAResource{AAAAR}
}

// CNAMEResource returns the CNAME via Customizations, otherwise nil
func CNAMEResource(fqdnString string) *dnsmessage.CNAMEResource {
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && domain.CNAME != (dnsmessage.CNAMEResource{}) {
		return &domain.CNAME
	}
	return nil
}

// MXResources returns either 1 or more MX records set via Customizations or
// an MX record pointing to the queried record
func MXResources(fqdnString string) []dnsmessage.MXResource {
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.MX) > 0 {
		return domain.MX
	}
	mx, _ := dnsmessage.NewName(fqdnString)
	return []dnsmessage.MXResource{
		{
			Pref: 0,
			MX:   mx,
		},
	}
}

func IsAcmeChallenge(fqdnString string) bool {
	if dns01ChallengeRE.MatchString(fqdnString) {
		ipv4s := NameToA(fqdnString)
		ipv6s := NameToAAAA(fqdnString)
		if len(ipv4s) > 0 || len(ipv6s) > 0 {
			return true
		}
	}
	return false
}

func NSResources(fqdnString string) []dnsmessage.NSResource {
	if IsAcmeChallenge(fqdnString) {
		strippedFqdn := dns01ChallengeRE.ReplaceAllString(fqdnString, "")
		ns, _ := dnsmessage.NewName(strippedFqdn)
		return []dnsmessage.NSResource{{NS: ns}}
	}
	return NameServers
}

// TXTResources returns TXT records from Customizations
func TXTResources(fqdnString string) []dnsmessage.TXTResource {
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok {
		return domain.TXT
	}
	return nil
}

func SOAAuthority(name dnsmessage.Name) (dnsmessage.ResourceHeader, dnsmessage.SOAResource) {
	return dnsmessage.ResourceHeader{
		Name:   name,
		Type:   dnsmessage.TypeSOA,
		Class:  dnsmessage.ClassINET,
		TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
		Length: 0,
	}, SOAResource(name)
}

// SOAResource returns the hard-coded (except MNAME) SOA
func SOAResource(name dnsmessage.Name) dnsmessage.SOAResource {
	return dnsmessage.SOAResource{
		NS:     name,
		MBox:   mbox,
		Serial: 2021011400,
		// cribbed the Refresh/Retry/Expire from google.com
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  300,
	}
}

// soaLogMessage returns an easy-to-read string for logging SOA Answers/Authorities
func soaLogMessage(soaResource dnsmessage.SOAResource) string {
	return soaResource.NS.String() + " " +
		soaResource.MBox.String() + " " +
		strconv.Itoa(int(soaResource.Serial)) + " " +
		strconv.Itoa(int(soaResource.Refresh)) + " " +
		strconv.Itoa(int(soaResource.Retry)) + " " +
		strconv.Itoa(int(soaResource.Expire)) + " " +
		strconv.Itoa(int(soaResource.MinTTL))
}
