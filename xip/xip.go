// Package xip provides functions to create a DNS server which, when queried
// with a hostname with an embedded IP address, returns that IP Address.  It
// was inspired by xip.io, which was created by Sam Stephenson
package xip

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

// Xip is meant to be a singleton that holds global state for the DNS server
type Xip struct {
	DnsAmplificationAttackDelay chan struct{}           // for throttling metrics.status.sslip.io
	Metrics                     Metrics                 // DNS server metrics
	BlocklistStrings            []string                // list of blacklisted strings that shouldn't appear in public hostnames
	BlocklistCIDRs              []net.IPNet             // list of blacklisted CIDRs; no A/AAAA records should resolve to IPs in these CIDRs
	BlocklistUpdated            time.Time               // The most recent time the Blocklist was updated
	NameServers                 []dnsmessage.NSResource // The list of authoritative name servers (NS)
	Public                      bool                    // Whether to resolve public IPs; set to false if security-conscious
}

// Metrics contains the counters of the important/interesting queries
type Metrics struct {
	Start                           time.Time
	Queries                         int
	TCPQueries                      int
	UDPQueries                      int
	AnsweredQueries                 int
	AnsweredAQueries                int
	AnsweredAAAAQueries             int
	AnsweredTXTSrcIPQueries         int
	AnsweredTXTVersionQueries       int
	AnsweredNSDNS01ChallengeQueries int
	AnsweredBlockedQueries          int
	AnsweredPTRQueriesIPv4          int
	AnsweredPTRQueriesIPv6          int
}

// DomainCustomization is a value that is returned for a specific query.
// The map key is the domain in question, e.g. "sslip.io." (always include trailing dot).
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
	NS    []dnsmessage.NSResource
	TXT   func(*Xip, net.IP) ([]dnsmessage.TXTResource, error)
	// Unlike the other record types, TXT is a function in order to enable more complex behavior
	// e.g. IP address of the query's source
}

// DomainCustomizations is a lookup table for specially-crafted records
// e.g. MX records for sslip.io.
// The string key should always be lower-cased
// DomainCustomizations{"sslip.io": ...} NOT DomainCustomizations{"sSLip.iO": ...}
// DNS hostnames are technically case-insensitive
type DomainCustomizations map[string]DomainCustomization

// There's nothing like global variables to make my heart pound with joy.
// Some of these are global because they are, in essence, constants which
// I don't want to waste time recreating with every function call.
var (
	ipv4REDots   = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d))($|[.-])`)
	ipv4REDashes = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?\d)?\d)-){3}(25[0-5]|(2[0-4]|1?\d)?\d))($|[.-])`)
	hexRE        = regexp.MustCompile(`(^|[.-])(\b[0-9a-fA-F]{8}\b)($|[.-])`)
	// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
	ipv6RE           = regexp.MustCompile(`(^|[.-])(([[:xdigit:]]{1,4}-){7}[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}-){1,7}-|([[:xdigit:]]{1,4}-){1,6}-[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}-){1,5}(-[[:xdigit:]]{1,4}){1,2}|([[:xdigit:]]{1,4}-){1,4}(-[[:xdigit:]]{1,4}){1,3}|([[:xdigit:]]{1,4}-){1,3}(-[[:xdigit:]]{1,4}){1,4}|([[:xdigit:]]{1,4}-){1,2}(-[[:xdigit:]]{1,4}){1,5}|[[:xdigit:]]{1,4}-((-[[:xdigit:]]{1,4}){1,6})|-((-[[:xdigit:]]{1,4}){1,7}|-)|fe80-(-[[:xdigit:]]{0,4}){0,4}%[\da-zA-Z]+|--(ffff(-0{1,4})?-)?((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d)|([[:xdigit:]]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d))($|[.-])`)
	ipv4ReverseRE    = regexp.MustCompile(`^(.*)\.in-addr\.arpa\.$`)
	ipv6ReverseRE    = regexp.MustCompile(`^(([[:xdigit:]]\.){32})ip6\.arpa\.`)
	dns01ChallengeRE = regexp.MustCompile(`(?i)_acme-challenge\.`) // (?i) → non-capturing case insensitive

	mbox, _       = dnsmessage.NewName("briancunnie.gmail.com.")
	mx1, _        = dnsmessage.NewName("mail.protonmail.ch.")
	mx2, _        = dnsmessage.NewName("mailsec.protonmail.ch.")
	dkim1Sslip, _ = dnsmessage.NewName("protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.")
	dkim2Sslip, _ = dnsmessage.NewName("protonmail2.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.")
	dkim3Sslip, _ = dnsmessage.NewName("protonmail3.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.")
	dkim1Nip, _   = dnsmessage.NewName("protonmail.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch.")
	dkim2Nip, _   = dnsmessage.NewName("protonmail2.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch.")
	dkim3Nip, _   = dnsmessage.NewName("protonmail3.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch.")

	VersionSemantic = "0.0.0"
	VersionDate     = "0001/01/01-99:99:99-0800"
	VersionGitHash  = "cafexxx"

	MetricsBufferSize = 200 // big enough to run our tests, and small enough to prevent DNS amplification attacks

	Customizations = DomainCustomizations{
		"nip.io.": {
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
			TXT: TXTNipIoSPF,
		},
		"sslip.io.": {
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
			TXT: TXTSslipIoSPF,
		},
		// nameserver addresses; we get queries for those every once in a while
		// CNAMEs for nip.io/sslip.io for DKIM signing
		"protonmail._domainkey.nip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim1Nip,
			},
		},
		"protonmail2._domainkey.nip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim2Nip,
			},
		},
		"protonmail3._domainkey.nip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim3Nip,
			},
		},
		"protonmail._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim1Sslip,
			},
		},
		"protonmail2._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim2Sslip,
			},
		},
		"protonmail3._domainkey.sslip.io.": {
			CNAME: dnsmessage.CNAMEResource{
				CNAME: dkim3Sslip,
			},
		},
		// Special-purpose TXT records
		"ip.sslip.io.": {
			TXT: TXTIp,
		},
		"version.status.sslip.io.": {
			TXT: func(x *Xip, _ net.IP) ([]dnsmessage.TXTResource, error) {
				x.Metrics.AnsweredTXTVersionQueries++
				return []dnsmessage.TXTResource{
					{TXT: []string{VersionSemantic}}, // e.g. "2.2.1'
					{TXT: []string{VersionDate}},     // e.g. "2021/10/03-15:08:54+0100"
					{TXT: []string{VersionGitHash}},  // e.g. "9339c0d"
				}, nil
			},
		},
		"_psl.sslip.io.": { // avoid Let's Encrypt rate limits by joining https://publicsuffix.org
			TXT: func(x *Xip, _ net.IP) ([]dnsmessage.TXTResource, error) {
				x.Metrics.AnsweredTXTVersionQueries++
				return []dnsmessage.TXTResource{
					{TXT: []string{"https://github.com/publicsuffix/list/pull/2206"}},
				}, nil
			},
		},

		"metrics.status.sslip.io.": {
			TXT: TXTMetrics,
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

// NewXip follows convention for constructors: https://go.dev/doc/effective_go#allocation_new
func NewXip(blocklistURL string, nameservers []string, addresses []string, delegates []string) (x *Xip, logmessages []string) {
	x = &Xip{Metrics: Metrics{Start: time.Now()}}

	// Download the blocklist
	logmessages = append(logmessages, x.downloadBlockList(blocklistURL))
	// re-download the blocklist every hour so I don't need to restart servers after updating blocklist
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			_ = x.downloadBlockList(blocklistURL) // uh-oh, I lose the log message.
		}
	}()

	// Parse and set our nameservers
	for _, ns := range nameservers {
		if len(ns) == 0 {
			logmessages = append(logmessages, fmt.Sprintf(`-nameservers: ignoring zero-length nameserver ""`))
			continue
		}
		// all nameservers must be absolute (end in ".")
		if ns[len(ns)-1] != '.' {
			ns += "."
		}
		// nameservers must be DNS-compliant
		nsName, err := dnsmessage.NewName(ns)
		if err != nil {
			logmessages = append(logmessages, fmt.Sprintf(`-nameservers: ignoring invalid nameserver "%s"`, ns))
			continue
		}
		x.NameServers = append(x.NameServers, dnsmessage.NSResource{
			NS: nsName})
		logmessages = append(logmessages, fmt.Sprintf(`Adding nameserver "%s"`, ns))
	}
	// Parse and set our addresses
	for _, address := range addresses {
		hostAddr := strings.Split(address, "=")
		if len(hostAddr) != 2 {
			logmessages = append(logmessages, fmt.Sprintf(`-addresses: arguments should be in the format "host=ip", not "%s"`, address))
			continue
		}
		host := hostAddr[0]
		ip := net.ParseIP(hostAddr[1])
		// all hosts must be absolute (end in ".")
		if host[len(host)-1] != '.' {
			host += "."
		}
		if ip == nil { // bad IP delegate
			logmessages = append(logmessages, fmt.Sprintf(`-addresses: "%s" is not assigned a valid IP`, hostAddr))
			continue
		}
		if ip.To4() != nil { // we have an IPv4
			var ABytes [4]byte
			// copy the _last_ four bytes of the 16-byte IP, not the first four bytes. Cost me 2 hours.
			copy(ABytes[0:4], ip[12:])
			// Thanks https://stackoverflow.com/questions/42605337/cannot-assign-to-struct-field-in-a-map
			var hostEntry = DomainCustomization{}
			if _, ok := Customizations[host]; ok {
				hostEntry = Customizations[host]
			}
			hostEntry.A = append(hostEntry.A, dnsmessage.AResource{A: ABytes})
			Customizations[host] = hostEntry
		} else {
			// We're pretty sure it's IPv6 at this point, but we check anyway
			if ip.To16() == nil { // it's not IPv6, and I don't know what it is
				logmessages = append(logmessages, fmt.Sprintf(`-addresses: "%s" is not IPv4 or IPv6 "%s"`, hostAddr, ip.String()))
				continue
			}
			var AAAABytes [16]byte
			copy(AAAABytes[0:16], ip)
			// Thanks https://stackoverflow.com/questions/42605337/cannot-assign-to-struct-field-in-a-map
			var hostEntry = DomainCustomization{}
			if _, ok := Customizations[host]; ok {
				hostEntry = Customizations[host]
			}
			hostEntry.AAAA = append(hostEntry.AAAA, dnsmessage.AAAAResource{AAAA: AAAABytes})
			Customizations[host] = hostEntry
		}
		// print out the added records in a manner similar to the way they're set on the cmdline
		logmessages = append(logmessages, fmt.Sprintf(`Adding record "%s=%s"`, host, ip))
	}
	// Parse and set the nameservers of our delegated domains
	for _, delegate := range delegates {
		if delegate == "" { // most common case: no delegates defined
			continue
		}
		delegatedDomainAndNameserver := strings.Split(strings.ToLower(delegate), "=")
		if len(delegatedDomainAndNameserver) != 2 {
			logmessages = append(logmessages, fmt.Sprintf(`-delegates: arguments should be in the format "delegatedDomain=nameserver", not "%s"`, delegate))
			continue
		}
		delegatedDomain := delegatedDomainAndNameserver[0]
		nameServer := delegatedDomainAndNameserver[1]
		// all domains & nameservers must be absolute (end in ".")
		if delegatedDomain[len(delegatedDomain)-1] != '.' {
			delegatedDomain += "."
		}
		if nameServer[len(nameServer)-1] != '.' {
			nameServer += "."
		}

		// nameservers must be DNS-compliant
		nsName, err := dnsmessage.NewName(nameServer)
		if err != nil {
			logmessages = append(logmessages, fmt.Sprintf(`-nameservers: ignoring invalid nameserver "%s"`, nameServer))
			continue
		}
		var domainEntry = DomainCustomization{}
		if _, ok := Customizations[delegatedDomain]; ok {
			domainEntry = Customizations[delegatedDomain]
		}
		domainEntry.NS = append(domainEntry.NS, dnsmessage.NSResource{NS: nsName})
		Customizations[delegatedDomain] = domainEntry
		// print out the added records in a manner similar to the way they're set on the cmdline
		logmessages = append(logmessages, fmt.Sprintf(`Adding delegated NS record "%s=%s"`, delegatedDomain, nsName.String()))
	}

	// We want to make sure that our DNS server isn't used in a DNS amplification attack.
	// The endpoint we're worried about is metrics.status.sslip.io, whose reply is
	// ~400 bytes with a query of ~100 bytes (4x amplification). We accomplish this by
	// using channels with a quarter-second delay. Max throughput 1.2 kBytes/sec.
	//
	// We want to balance this delay against our desire to run tests quickly, so we buffer
	// the channel with enough room to accommodate our tests.
	//
	// We also want to have fun playing with channels
	dnsAmplificationAttackDelay := make(chan struct{}, MetricsBufferSize)
	x.DnsAmplificationAttackDelay = dnsAmplificationAttackDelay
	go func() {
		// fill up the channel's buffer so that our tests aren't slowed down (~85 tests)
		for i := 0; i < MetricsBufferSize; i++ {
			dnsAmplificationAttackDelay <- struct{}{}
		}
		// now put on the brakes for users trying to leverage our server in a DNS amplification attack
		for {
			dnsAmplificationAttackDelay <- struct{}{}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	return x, logmessages
}

// QueryResponse takes in a raw (packed) DNS query and returns a raw (packed)
// DNS response, a string (for logging) that describes the query and the
// response, and an error. It takes in the raw data to offload as much as
// possible from main(). main() is hard to unit test, but functions like
// QueryResponse are not as hard.
//
// Examples of log strings returned:
//
//	78.46.204.247.33654: TypeA 127-0-0-1.sslip.io ? 127.0.0.1
//	78.46.204.247.33654: TypeA non-existent.sslip.io ? nil, SOA
//	78.46.204.247.33654: TypeNS www.example.com ? NS
//	78.46.204.247.33654: TypeSOA www.example.com ? SOA
//	2600::.33654: TypeAAAA --1.sslip.io ? ::1
func (x *Xip) QueryResponse(queryBytes []byte, srcAddr net.IP) (responseBytes []byte, logMessage string, err error) {
	var queryHeader dnsmessage.Header
	var p dnsmessage.Parser
	var response Response

	if queryHeader, err = p.Start(queryBytes); err != nil {
		return nil, "", err
	}
	var q dnsmessage.Question
	// we only answer the first question even though there technically may be more than one;
	// de facto there's one and only one question
	if q, err = p.Question(); err != nil {
		return nil, "", err
	}
	response, logMessage, err = x.processQuestion(q, srcAddr)
	if err != nil {
		return nil, "", err
	}
	response.Header.ID = queryHeader.ID
	response.Header.RecursionDesired = queryHeader.RecursionDesired
	x.Metrics.Queries++

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

func (x *Xip) processQuestion(q dnsmessage.Question, srcAddr net.IP) (response Response, logMessage string, err error) {
	logMessage = q.Type.String() + " " + q.Name.String() + " ? "
	response = Response{
		Header: dnsmessage.Header{
			ID:                 0, // this will later be replaced with query.ID
			Response:           true,
			OpCode:             0,
			Authoritative:      true, // We're able to white label domains by always being authoritative
			Truncated:          false,
			RecursionDesired:   false,                   // this will later be replaced with query.RecursionDesired
			RecursionAvailable: false,                   // We are not recursing servers, so recursion is never available. Prevents DDOS
			RCode:              dnsmessage.RCodeSuccess, // assume success, may be replaced later
		},
	}
	if IsDelegated(q.Name.String()) {
		// if xip.pivotal.io has been delegated to ns-437.awsdns-54.com.
		// and a query comes in for 127-0-0-1.cloudfoundry.xip.pivotal.io
		// then don't resolve the A record; instead, return the delegated
		// NS record, ns-437.awsdns-54.com.
		response.Header.Authoritative = false
		return x.NSResponse(q.Name, response, logMessage)
	}
	if IsAcmeChallenge(q.Name.String()) && !x.blocklist(q.Name.String()) {
		// thanks, @NormanR
		// delegate everything to its stripped (remove "_acme-challenge.") address, e.g.
		// dig _acme-challenge.127-0-0-1.sslip.io mx → NS 127-0-0-1.sslip.io
		response.Header.Authoritative = false
		return x.NSResponse(q.Name, response, logMessage)
	}
	switch q.Type {
	case dnsmessage.TypeA:
		{
			return x.nameToAwithBlocklist(q, response, logMessage)
		}
	case dnsmessage.TypeAAAA:
		{
			return x.nameToAAAAwithBlocklist(q, response, logMessage)
		}
	case dnsmessage.TypeALL:
		{
			// We don't implement type ANY, so return "NotImplemented" like CloudFlare (1.1.1.1)
			// https://blog.cloudflare.com/rfc8482-saying-goodbye-to-any/
			// Google (8.8.8.8) returns every record they can find (A, AAAA, SOA, NS, MX, ...).
			response.Header.RCode = dnsmessage.RCodeNotImplemented
			return response, logMessage + "NotImplemented", nil
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
				return response, logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			x.Metrics.AnsweredQueries++
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
			return response, logMessage + cname.CNAME.String(), nil
		}
	case dnsmessage.TypeMX:
		{
			mailExchangers := MXResources(q.Name.String())
			var logMessages []string

			// We can be sure that len(mailExchangers) > 1, but we check anyway
			if len(mailExchangers) == 0 {
				return response, "", errors.New("no MX records, but there should be one")
			}
			x.Metrics.AnsweredQueries++
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
			return response, logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeNS:
		{
			return x.NSResponse(q.Name, response, logMessage)
		}
	case dnsmessage.TypeSOA:
		{
			x.Metrics.AnsweredQueries++
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
			return response, logMessage + soaLogMessage(soaResource), nil
		}
	case dnsmessage.TypeTXT:
		{
			// if it's an "_acme-challenge." TXT, we return no answer but an NS authority & not authoritative
			// if it's customized records, we return them in the Answers
			// otherwise we return no Answers and Authorities SOA
			if IsAcmeChallenge(q.Name.String()) {
				// No Answers, Not Authoritative, Authorities contain NS records
				response.Header.Authoritative = false
				nameServers := x.NSResources(q.Name.String())
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
				return response, logMessage + "nil, NS " + strings.Join(logMessages, ", "), nil
			}
			var txts []dnsmessage.TXTResource
			txts, err = x.TXTResources(q.Name.String(), srcAddr)
			if err != nil {
				return response, "", err
			}
			if len(txts) > 0 {
				x.Metrics.AnsweredQueries++
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
							TTL:    180, // 3 minutes to allow key-value to propagate
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
			if len(logMessageTXTss) == 0 {
				return response, logMessage + "nil, SOA " + soaLogMessage(SOAResource(q.Name)), nil
			}
			return response, logMessage + strings.Join(logMessageTXTss, ", "), nil
		}
	case dnsmessage.TypePTR:
		{
			var ptr *dnsmessage.PTRResource
			ptr = x.PTRResource([]byte(q.Name.String()))
			if ptr == nil {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(dnsmessage.MustNewName("sslip.io."))
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return response, logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			//x.Metrics.AnsweredQueries++
			response.Answers = append(response.Answers,
				// 1 CNAME record, via Customizations
				func(b *dnsmessage.Builder) error {
					err = b.PTRResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypePTR,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, *ptr)
					if err != nil {
						return err
					}
					return nil
				})
			return response, logMessage + ptr.PTR.String(), nil
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
			return response, logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
		}
	}
}

// NSResponse sets the Answers/Authorities depending upon whether we're delegating or authoritative
func (x *Xip) NSResponse(name dnsmessage.Name, response Response, logMessage string) (Response, string, error) {
	nameServers := x.NSResources(name.String())
	var logMessages []string
	if response.Header.Authoritative {
		// we're authoritative, so we reply with the answers
		// but we rotate the nameservers every second so one server doesn't bear the brunt of the traffic
		epoch := time.Now().UTC().Unix()
		index := int(epoch) % len(x.NameServers)
		rotatedNameservers := append(x.NameServers[index:], x.NameServers[0:index]...)
		response.Answers = append(response.Answers,
			func(b *dnsmessage.Builder) error {
				return buildNSRecords(b, name, rotatedNameservers)
			})
	} else {
		// we're NOT authoritative, so we reply who is authoritative
		response.Authorities = append(response.Authorities,
			func(b *dnsmessage.Builder) error {
				return buildNSRecords(b, name, nameServers)
			})
		logMessage += "nil, NS " // we're not supplying an answer; we're supplying the NS record that's authoritative
	}
	response.Additionals = append(response.Additionals,
		func(b *dnsmessage.Builder) error {
			for _, nameServer := range nameServers {
				for _, aResource := range NameToA(nameServer.NS.String(), true) {
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
				for _, aaaaResource := range NameToAAAA(nameServer.NS.String(), true) {
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
	return response, logMessage + strings.Join(logMessages, ", "), nil
}

func buildNSRecords(b *dnsmessage.Builder, name dnsmessage.Name, nameServers []dnsmessage.NSResource) error {
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
}

// NameToA returns an []AResource that matched the hostname; it returns an array of zero-or-one records
// possibly more if it's a customized record (e.g. the addresses of "ns.sslip.io.")
// if "allowPublicIPs" is false, and the IP address is public, it'll return an empty array
func NameToA(fqdnString string, allowPublicIPs bool) []dnsmessage.AResource {
	fqdn := []byte(fqdnString)
	// is it a customized A record? If so, return early
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.A) > 0 {
		return domain.A
	}
	for _, ipv4RE := range []*regexp.Regexp{ipv4REDashes, ipv4REDots, hexRE} {
		if ipv4RE.Match(fqdn) {
			match := string(ipv4RE.FindSubmatch(fqdn)[2])
			match = strings.Replace(match, "-", ".", -1)

			if ipv4RE == hexRE {
				hexip, err := HexToIPv4(match)
				if err != nil {
					log.Printf("----> Invalid hex IP in %s: %s\n", fqdn, err)
					return []dnsmessage.AResource{}
				}
				match = hexip
			}

			ipv4address := net.ParseIP(match).To4()
			// We shouldn't reach here because `match` should always be valid, but we're not optimists
			if ipv4address == nil {
				// e.g. "ubuntu20.04.235.249.181-notify.sslip.io." <- the leading zero is the problem
				log.Printf("----> Should be valid A but isn't: %s\n", fqdn) // TODO: delete this
				return []dnsmessage.AResource{}
			}
			if (!allowPublicIPs) && IsPublic(ipv4address) {
				return []dnsmessage.AResource{}
			}
			return []dnsmessage.AResource{
				{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}},
			}
		}
	}
	return []dnsmessage.AResource{}
}

// NameToAAAA returns an []AAAAResource that matched the hostname; it returns an array of zero-or-one records
// possibly more if it's a customized record (e.g. the addresses of "ns.sslip.io.")
// if "allowPublicIPs" is false, and the IP address is public, it'll return an empty array
func NameToAAAA(fqdnString string, allowPublicIPs bool) []dnsmessage.AAAAResource {
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
		log.Printf("----> Should be valid AAAA but isn't: %s\n", fqdn) // TODO: delete this
		return []dnsmessage.AAAAResource{}
	}
	if (!allowPublicIPs) && IsPublic(ipv16address) {
		return []dnsmessage.AAAAResource{}
	}
	AAAAR := dnsmessage.AAAAResource{}
	for i := range ipv16address {
		AAAAR.AAAA[i] = ipv16address[i]
	}
	return []dnsmessage.AAAAResource{AAAAR}
}

func HexToIPv4(hexIP string) (string, error) {
	// Decode the hex string into bytes
	ipBytes, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex IP: %v", err)
	}

	// Ensure the decoded bytes are exactly 4 bytes (IPv4 address)
	if len(ipBytes) != 4 {
		return "", fmt.Errorf("invalid decoded IP length: %d", len(ipBytes))
	}

	// Format the bytes as an IPv4 address
	return fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]), nil
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
	fqdnStringLowerCased := strings.ToLower(fqdnString)
	if dns01ChallengeRE.MatchString(fqdnStringLowerCased) {
		ipv4s := NameToA(fqdnStringLowerCased, true)
		ipv6s := NameToAAAA(fqdnStringLowerCased, true)
		if len(ipv4s) > 0 || len(ipv6s) > 0 {
			return true
		}
	}
	return false
}

func IsDelegated(fqdnString string) bool {
	fqdnStringLowerCased := strings.ToLower(fqdnString)
	for domain := range Customizations {
		if Customizations[domain].NS == nil { // no nameserver? then it can't be delegated
			continue
		}
		// the "." prevents "where.com" from being mistakenly recognized as a subdomain of "here.com"
		if strings.HasSuffix(fqdnStringLowerCased, "."+domain) || fqdnStringLowerCased == domain {
			return true
		}
	}
	return false
}

func (x *Xip) NSResources(fqdnString string) []dnsmessage.NSResource {
	fqdnStringLowerCased := strings.ToLower(fqdnString)
	if x.blocklist(fqdnStringLowerCased) {
		x.Metrics.AnsweredQueries++
		x.Metrics.AnsweredBlockedQueries++
		return x.NameServers
	}
	// Is this a delegated domain? Let's return the delegated nameservers
	for domain := range Customizations {
		if Customizations[domain].NS == nil { // no nameserver? then it can't be delegated
			continue
		}
		// the "." prevents "where.com" from being mistakenly recognized as a subdomain of "here.com"
		if strings.HasSuffix(fqdnStringLowerCased, "."+domain) || fqdnStringLowerCased == domain {
			return Customizations[domain].NS
		}
	}
	if IsAcmeChallenge(fqdnStringLowerCased) {
		x.Metrics.AnsweredNSDNS01ChallengeQueries++
		strippedFqdn := dns01ChallengeRE.ReplaceAllString(fqdnStringLowerCased, "")
		ns, _ := dnsmessage.NewName(strippedFqdn)
		return []dnsmessage.NSResource{{NS: ns}}
	}
	x.Metrics.AnsweredQueries++
	return x.NameServers
}

// TXTResources returns TXT records from Customizations
func (x *Xip) TXTResources(fqdn string, ip net.IP) ([]dnsmessage.TXTResource, error) {
	if domain, ok := Customizations[strings.ToLower(fqdn)]; ok {
		// Customizations[strings.ToLower(fqdn)] returns a _function_,
		// we call that function, which has the same return signature as this method
		if domain.TXT != nil {
			return domain.TXT(x, ip)
		}
	}
	return nil, nil
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
		Serial: 20250615,
		// cribbed the Refresh/Retry/Expire from google.com.
		// MinTTL was 300, but I dropped to 180 for faster
		// key-value propagation
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  180,
	}
}

// PTRResource returns the PTR record, otherwise nil
func (x *Xip) PTRResource(fqdn []byte) *dnsmessage.PTRResource {
	// "reverse", for example, means "1.0.0.127", as in "1.0.0.127.in-addr.arpa"
	// the regular IP would be "127.0.0.1"
	if ipv4ReverseRE.Match(fqdn) {
		reversedIPv4 := ipv4ReverseRE.FindSubmatch(fqdn)[1]
		reversedIPv4address := net.ParseIP(string(reversedIPv4)).To4()
		if reversedIPv4address == nil {
			return nil
		}
		ip := netip.AddrFrom4([4]byte{
			reversedIPv4address[3],
			reversedIPv4address[2],
			reversedIPv4address[1],
			reversedIPv4address[0],
		})
		ptrName, err := dnsmessage.NewName(strings.ReplaceAll(ip.String(), ".", "-") + ".sslip.io.")
		if err != nil {
			return nil
		}
		x.Metrics.AnsweredQueries++
		x.Metrics.AnsweredPTRQueriesIPv4++
		return &dnsmessage.PTRResource{
			PTR: ptrName,
		}
	}
	if ipv6ReverseRE.Match(fqdn) {
		b := ipv6ReverseRE.FindSubmatch(fqdn)[1]
		reversed := []byte{
			b[62], b[60], b[58], b[56], ':',
			b[54], b[52], b[50], b[48], ':',
			b[46], b[44], b[42], b[40], ':',
			b[38], b[36], b[34], b[32], ':',
			b[30], b[28], b[26], b[24], ':',
			b[22], b[20], b[18], b[16], ':',
			b[14], b[12], b[10], b[8], ':',
			b[6], b[4], b[2], b[0],
		}
		ip := net.ParseIP(string(reversed)).To16()
		if ip == nil {
			return nil
		}
		ptrName, err := dnsmessage.NewName(strings.ReplaceAll(ip.String(), ":", "-") + ".sslip.io.")
		if err != nil {
			return nil
		}
		x.Metrics.AnsweredQueries++
		x.Metrics.AnsweredPTRQueriesIPv6++
		return &dnsmessage.PTRResource{
			PTR: ptrName,
		}
	}
	return nil
}

// TXTSslipIoSPF SPF records for nip.io
func TXTNipIoSPF(_ *Xip, _ net.IP) ([]dnsmessage.TXTResource, error) {
	// Although multiple TXT records with multiple strings are allowed, we're sticking
	// with a multiple TXT records with a single string apiece because that's what ProtonMail requires
	// and that's what google.com does.
	return []dnsmessage.TXTResource{
		{TXT: []string{"protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313"}}, // ProtonMail verification; don't delete
		{TXT: []string{"v=spf1 include:_spf.protonmail.ch mx ~all"}},
	}, nil // Sender Policy Framework
}

// TXTSslipIoSPF SPF records for sslio.io
func TXTSslipIoSPF(_ *Xip, _ net.IP) ([]dnsmessage.TXTResource, error) {
	// Although multiple TXT records with multiple strings are allowed, we're sticking
	// with a multiple TXT records with a single string apiece because that's what ProtonMail requires
	// and that's what google.com does.
	return []dnsmessage.TXTResource{
		{TXT: []string{"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26"}}, // ProtonMail verification; don't delete
		{TXT: []string{"v=spf1 include:_spf.protonmail.ch mx ~all"}},
	}, nil // Sender Policy Framework
}

// TXTIp when TXT for "ip.sslip.io" is queried, return the IP address of the querier
func TXTIp(x *Xip, srcAddr net.IP) ([]dnsmessage.TXTResource, error) {
	x.Metrics.AnsweredTXTSrcIPQueries++
	return []dnsmessage.TXTResource{{TXT: []string{srcAddr.String()}}}, nil
}

// TXTMetrics when TXT for "metrics.sslip.io" is queried, return the cumulative metrics
func TXTMetrics(x *Xip, _ net.IP) (txtResources []dnsmessage.TXTResource, err error) {
	<-x.DnsAmplificationAttackDelay
	var metrics []string
	uptime := time.Since(x.Metrics.Start)
	metrics = append(metrics, fmt.Sprintf("Uptime: %.0f", uptime.Seconds()))
	metrics = append(metrics, fmt.Sprintf("Blocklist: %s %d,%d",
		x.BlocklistUpdated.Format("2006-01-02 15:04:05-07"),
		len(x.BlocklistStrings),
		len(x.BlocklistCIDRs)))
	metrics = append(metrics, fmt.Sprintf("Queries: %d (%.1f/s)", x.Metrics.Queries, float64(x.Metrics.Queries)/uptime.Seconds()))
	metrics = append(metrics, fmt.Sprintf("TCP/UDP: %d/%d", x.Metrics.TCPQueries, x.Metrics.UDPQueries))
	metrics = append(metrics, fmt.Sprintf("Answer > 0: %d (%.1f/s)", x.Metrics.AnsweredQueries, float64(x.Metrics.AnsweredQueries)/uptime.Seconds()))
	metrics = append(metrics, fmt.Sprintf("A: %d", x.Metrics.AnsweredAQueries))
	metrics = append(metrics, fmt.Sprintf("AAAA: %d", x.Metrics.AnsweredAAAAQueries))
	metrics = append(metrics, fmt.Sprintf("TXT Source: %d", x.Metrics.AnsweredTXTSrcIPQueries))
	metrics = append(metrics, fmt.Sprintf("TXT Version: %d", x.Metrics.AnsweredTXTVersionQueries))
	metrics = append(metrics, fmt.Sprintf("PTR IPv4/IPv6: %d/%d", x.Metrics.AnsweredPTRQueriesIPv4, x.Metrics.AnsweredPTRQueriesIPv6))
	metrics = append(metrics, fmt.Sprintf("NS DNS-01: %d", x.Metrics.AnsweredNSDNS01ChallengeQueries))
	metrics = append(metrics, fmt.Sprintf("Blocked: %d", x.Metrics.AnsweredBlockedQueries))
	for _, metric := range metrics {
		txtResources = append(txtResources, dnsmessage.TXTResource{TXT: []string{metric}})
	}
	return txtResources, nil
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

// MostlyEquals compares all fields except `Start` (timestamp)
func (a Metrics) MostlyEquals(b Metrics) bool {
	if a.Queries == b.Queries &&
		a.TCPQueries == b.TCPQueries &&
		a.UDPQueries == b.UDPQueries &&
		a.AnsweredQueries == b.AnsweredQueries &&
		a.AnsweredAQueries == b.AnsweredAQueries &&
		a.AnsweredAAAAQueries == b.AnsweredAAAAQueries &&
		a.AnsweredTXTSrcIPQueries == b.AnsweredTXTSrcIPQueries &&
		a.AnsweredTXTVersionQueries == b.AnsweredTXTVersionQueries &&
		a.AnsweredPTRQueriesIPv4 == b.AnsweredPTRQueriesIPv4 &&
		a.AnsweredPTRQueriesIPv6 == b.AnsweredPTRQueriesIPv6 &&
		a.AnsweredNSDNS01ChallengeQueries == b.AnsweredNSDNS01ChallengeQueries &&
		a.AnsweredBlockedQueries == b.AnsweredBlockedQueries {
		return true
	}
	return false
}

func (x *Xip) downloadBlockList(blocklistURL string) string {
	var err error
	var blocklistReader io.ReadCloser
	// file protocol's purpose: so I can run tests while flying with no internet
	// secondary purpose: don't hammer GitHub when running tests
	fileProtocolRE := regexp.MustCompile(`^file://`)
	if fileProtocolRE.MatchString(blocklistURL) {
		blocklistPath := strings.TrimPrefix(blocklistURL, "file://")
		blocklistReader, err = os.Open(blocklistPath)
		if err != nil {
			return fmt.Sprintf(`failed to open blocklist "%s": %s`, blocklistPath, err.Error())
		}
		//noinspection GoUnhandledErrorResult
		defer blocklistReader.Close()
	} else {
		resp, err := http.Get(blocklistURL)
		if err != nil {
			return fmt.Sprintf(`failed to download blocklist "%s": %s`, blocklistURL, err.Error())
		}
		blocklistReader = resp.Body
		//noinspection GoUnhandledErrorResult
		defer blocklistReader.Close()
		if resp.StatusCode > 299 {
			return fmt.Sprintf(`failed to download blocklist "%s", HTTP status: "%d"`, blocklistURL, resp.StatusCode)
		}
	}
	blocklistStrings, blocklistCIDRs, err := ReadBlocklist(blocklistReader)
	if err != nil {
		return fmt.Sprintf(`failed to parse blocklist "%s": %s`, blocklistURL, err.Error())
	}
	x.BlocklistStrings = blocklistStrings
	x.BlocklistCIDRs = blocklistCIDRs
	x.BlocklistUpdated = time.Now()
	return fmt.Sprintf("Successfully downloaded blocklist from %s: %v, %v", blocklistURL, x.BlocklistStrings, x.BlocklistCIDRs)
}

// ReadBlocklist "sanitizes" the block list, removing comments, invalid characters
// and lowercasing the names to be blocked.
// public to make testing easier
func ReadBlocklist(blocklist io.Reader) (stringBlocklists []string, cidrBlocklists []net.IPNet, err error) {
	scanner := bufio.NewScanner(blocklist)
	comments := regexp.MustCompile(`#.*`)
	invalidDNSchars := regexp.MustCompile(`[^-\da-z]`)
	invalidDNScharsWithSlashesDotsAndColons := regexp.MustCompile(`[^-_\da-z/.:]`)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ToLower(line)
		line = comments.ReplaceAllString(line, "")                                // strip comments
		line = invalidDNScharsWithSlashesDotsAndColons.ReplaceAllString(line, "") // strip invalid characters
		_, ipcidr, err := net.ParseCIDR(line)
		if err != nil {
			line = invalidDNSchars.ReplaceAllString(line, "") // strip invalid DNS characters
			if line == "" {
				continue
			}
			stringBlocklists = append(stringBlocklists, line)
		} else {
			cidrBlocklists = append(cidrBlocklists, *ipcidr)
		}
	}
	if err = scanner.Err(); err != nil {
		return []string{}, []net.IPNet{}, err
	}
	return stringBlocklists, cidrBlocklists, nil
}

func (x *Xip) blocklist(hostname string) bool {
	aResources := NameToA(hostname, true)
	aaaaResources := NameToAAAA(hostname, true)
	if len(aResources) == 0 && len(aaaaResources) == 0 {
		return false
	}
	var ip net.IP
	if len(aResources) == 1 {
		ip = aResources[0].A[:]
	}
	if len(aaaaResources) == 1 {
		ip = aaaaResources[0].AAAA[:]
	}
	if ip == nil { // placate linter who worries ip is nil; it should never be nil
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	for _, blockstring := range x.BlocklistStrings {
		if strings.Contains(hostname, blockstring) {
			return true
		}
	}
	for _, blockCIDR := range x.BlocklistCIDRs {
		if blockCIDR.Contains(ip) {
			return true
		}
	}
	return false
}

func (x *Xip) nameToAwithBlocklist(q dnsmessage.Question, response Response, logMessage string) (_ Response, _ string, err error) {
	var nameToAs []dnsmessage.AResource
	nameToAs = NameToA(q.Name.String(), x.Public)
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
		return response, logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
	}
	if x.blocklist(q.Name.String()) {
		x.Metrics.AnsweredQueries++
		x.Metrics.AnsweredBlockedQueries++
		response.Answers = append(response.Answers,
			// 1 or more A records; A records > 1 only available via Customizations
			func(b *dnsmessage.Builder) error {
				err = b.AResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, Customizations["blocked.sslip.io."].A[0])
				if err != nil {
					return err
				}
				return nil
			})
		return response, logMessage + net.IP(Customizations["blocked.sslip.io."].A[0].A[:]).String(), nil
	}
	x.Metrics.AnsweredQueries++
	x.Metrics.AnsweredAQueries++
	response.Answers = append(response.Answers,
		// 1 or more A records; A records > 1 only available via Customizations
		func(b *dnsmessage.Builder) error {
			for _, nameToA := range nameToAs {
				err = b.AResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					TTL:    3600, // 60 * 60 == 1 hour; short TTL in case we need to block them
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
	return response, logMessage + strings.Join(logMessages, ", "), nil
}

func IsPublic(ip net.IP) (isPublic bool) {
	if ip.IsPrivate() { // RFC 1918, 4193
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 loopback
		if ip4[0] == 127 {
			return false
		}
		// IPv4 link-local
		if ip4[0] == 169 && ip4[1] == 254 {
			return false
		}
		// CG-NAT
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 {
			return false
		}
		return true
	}
	// IPv6 loopback ::1
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 &&
		ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && ip[15] == 1 {
		return false
	}
	// IPv6 link-local fe80::/10
	if ip[0] == 0xfe && ip[1] == 0x80 && ip[2]&0xc0 == 0 {
		return false
	}
	// IPv4/IPv6 Translation private internet 64:ff9b:1::/48
	if ip[0] == 0 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 1 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 {
		return false
	}
	// Teredo Tunneling 2001::/32
	// ORCHIDv2 (?) 2001:20::/28
	if ip[0] == 0x20 && ip[1] == 1 && ip[2] == 0 && ip[3]&0xf0 == 0x20 {
		return false
	}
	// Documentation 2001:db8::/32
	if ip[0] == 0x20 && ip[1] == 1 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	// Private internets fc00::/7

	return true
}

func (x *Xip) nameToAAAAwithBlocklist(q dnsmessage.Question, response Response, logMessage string) (_ Response, _ string, err error) {
	var nameToAAAAs []dnsmessage.AAAAResource
	nameToAAAAs = NameToAAAA(q.Name.String(), x.Public)
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
		return response, logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
	}
	if x.blocklist(q.Name.String()) {
		x.Metrics.AnsweredQueries++
		x.Metrics.AnsweredBlockedQueries++
		response.Answers = append(response.Answers,
			// 1 or more A records; A records > 1 only available via Customizations
			func(b *dnsmessage.Builder) error {
				err = b.AAAAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
					Length: 0,
				}, Customizations["blocked.sslip.io."].AAAA[0])
				if err != nil {
					return err
				}
				return nil
			})
		return response, logMessage + net.IP(Customizations["blocked.sslip.io."].AAAA[0].AAAA[:]).String(), nil
	}
	x.Metrics.AnsweredQueries++
	x.Metrics.AnsweredAAAAQueries++
	response.Answers = append(response.Answers,
		// 1 or more AAAA records; AAAA records > 1 only available via Customizations
		func(b *dnsmessage.Builder) error {
			for _, nameToAAAA := range nameToAAAAs {
				err = b.AAAAResource(dnsmessage.ResourceHeader{
					Name:   q.Name,
					Type:   dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					TTL:    3600, // 60 * 60 == 1 hour; short TTL in case we need to block them
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
	return response, logMessage + strings.Join(logMessages, ", "), nil
}
