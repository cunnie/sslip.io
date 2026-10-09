package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"xip/xip"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	var blocklistURL = flag.String("blocklistURL",
		"https://raw.githubusercontent.com/cunnie/sslip.io-blocklist/main/blocklist.txt",
		`URL containing a list of non-resolvable IPs/names/CIDRs, usually phishing or scamming sites. ` +
		`Examples: "file:///dev/null", "file://etc/blocklist.txt"`)
	var nameservers = flag.String("nameservers", "",
		"(deprecated in favor of -ns) comma-separated list of FQDNs of nameservers")
	var addresses = flag.String("addresses", "",
		"(deprecated in favor of -a and -aaaa) comma-separated list of hosts and corresponding IPv4 and/or IPv6 address(es)")
	var delegates = flag.String("delegates", "", "(deprecated in favor of -ns) comma-separated list of domains and their delegated nameservers")
	var bindPort = flag.Int("port", 53, "port the DNS server should bind to")
	var quiet = flag.Bool("quiet", false, "suppresses logging of each DNS response. Use this to avoid Google Cloud charging you $30/month to retain the logs of your GKE-based sslip.io server")
	var public = flag.Bool("public", true, "allows resolution of public IP addresses. If false, only resolves private IPs including localhost (127/8, ::1), link-local (169.254/16, fe80::/10), CG-NAT (100.64/12), private (10/8, 172.16/12, 192.168/16, fc/7). Set to false if you don't want miscreants impersonating you via public IPs. If unsure, set to false")
	var ptrDomain = flag.String("ptr-domain", "nip.io.", "the domain to use for PTR records, e.g. if 'nip.io',  127-0-0-1.nip.io.")
	var dnstapSocket = flag.String("dnstap", "", `enables dnstap logging of queries that return an A or AAAA record; argument is the destination socket, either a Unix socket path (e.g. "/var/run/dnstap.sock") or a TCP address (e.g. "127.0.0.1:6000" or "[::1]:6000")`)
	var records = newRecordFlags(xip.Customizations)
	flag.Func("a", `A record as "hostname=ipv4", e.g. "-a nip.io=192.168.1.1 -a nip.io=172.31.0.1"`, records.addA)
	flag.Func("aaaa", `AAAA record as "hostname=ipv6", e.g. "-aaaa nip.io=2600:: -aaaa nip.io=2601::`, records.addAAAA)
	flag.Func("mx", `MX record as "domain=preference,host", e.g. "-mx nip.io=10 mail.protonmail.ch. -mx nip.io=20,mailsec.protonmail.ch."`, records.addMX)
	flag.Func("txt", `TXT record as "domain=text", e.g. '-txt nip.io="protonmail-verification=19b0837c" -txt nip.io="v=spf1 include:_spf.protonmail.ch mx -all"`, records.addTXT)
	flag.Func("ns", `NS record as "domain=nameserver", often used to acquire wildcard certificates from Let's Encrypt via DNS-01 challenge, e.g. "-ns _acme-challenge.73-189-219-4.xip.nono.io.=ns-437.awsdns-54.com. -ns nip.io=ns-00.nip.io -ns nip.io=ns-ovh.sslip.io."`, records.addNS)
	flag.Parse()
	log.Printf("%s version %s starting", os.Args[0], xip.VersionSemantic)
	for _, logMessage := range records.logMessages {
		log.Println(logMessage)
	}
	log.Printf("blocklist URL: %s, name servers: %s, bind port: %d, quiet: %t",
		*blocklistURL, *nameservers, *bindPort, *quiet)

	x, logmessages := xip.NewXip(*blocklistURL, strings.Split(*nameservers, ","), strings.Split(*addresses, ","), strings.Split(*delegates, ","), *ptrDomain)
	x.Public = *public
	for _, logmessage := range logmessages {
		log.Println(logmessage)
	}

	var dw *DnstapWriter
	if *dnstapSocket != "" {
		var err error
		dw, err = NewDnstapWriter(*dnstapSocket)
		if err != nil {
			log.Printf("dnstap: warning: could not connect to %q: %v", *dnstapSocket, err)
			dw = nil
		}
		log.Printf("dnstap: connected to %q", *dnstapSocket)
		defer dw.Close()
	}

	var udpConns []*net.UDPConn
	var tcpListeners []*net.TCPListener
	var unboundUDPIPs []string
	var unboundTCPIPs []string
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *bindPort})
	switch {
	case err == nil: // success! We've bound to all interfaces
		udpConns = append(udpConns, udpConn)
	case isErrorPermissionsError(err):
		log.Printf("Try invoking me with `sudo` because I don't have permission to bind to UDP port %d.\n", *bindPort)
		log.Fatal(err.Error())
	case isErrorAddressAlreadyInUse(err):
		log.Printf("I couldn't bind via UDP to \"[::]:%d\" (INADDR_ANY, all interfaces), so I'll try to bind to each address individually.\n", *bindPort)
		udpConns, unboundUDPIPs = bindUDPAddressesIndividually(*bindPort)
		if len(unboundUDPIPs) > 0 {
			log.Printf(`I couldn't bind via UDP to the following IPs: "%s"`, strings.Join(unboundUDPIPs, `", "`))
		}
	default:
		log.Fatal(err.Error())
	}
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: *bindPort})
	switch {
	case err == nil: // success! We've bound to all interfaces
		tcpListeners = append(tcpListeners, tcpListener)
	case isErrorPermissionsError(err): // unnecessary because it should've bombed out earlier when attempting to bind UDP
		log.Printf("Try invoking me with `sudo` because I don't have permission to bind to TCP port %d.\n", *bindPort)
		log.Println(err.Error())
	case isErrorAddressAlreadyInUse(err):
		log.Printf("I couldn't bind via TCP to \"[::]:%d\" (INADDR_ANY, all interfaces), so I'll try to bind to each address individually.\n", *bindPort)
		tcpListeners, unboundTCPIPs = bindTCPAddressesIndividually(*bindPort)
		if len(unboundTCPIPs) > 0 {
			log.Printf(`I couldn't bind via TCP to the following IPs: "%s"`, strings.Join(unboundTCPIPs, `", "`))
		}
	default:
		log.Println(err.Error()) // Unlike UDP, we don't exit on TCP errors, we merely log
	}
	if len(tcpListeners) == 0 {
		// unlike UDP failure to bind, we don't exit because TCP is optional, UDP, mandatory
		log.Printf("I couldn't bind via TCP to any IPs on port %d", *bindPort)
	}

	// Log the list of IPs that we've bound to because it helps troubleshooting
	var boundUDPIPs []string
	for _, udpConn := range udpConns {
		boundUDPIPs = append(boundUDPIPs, udpConn.LocalAddr().String())
	}
	log.Printf(`I bound via UDP to the following IPs: "%s"`, strings.Join(boundUDPIPs, `", "`))
	var boundTCPIPs []string
	for _, tcpListener := range tcpListeners {
		boundTCPIPs = append(boundTCPIPs, tcpListener.Addr().String())
	}
	log.Printf(`I bound via TCP to the following IPs: "%s"`, strings.Join(boundTCPIPs, `", "`))

	if len(udpConns) == 0 { // couldn't bind to UDP anywhere? exit
		log.Fatalf("I couldn't bind via UDP to any IPs on port %d, so I'm exiting", *bindPort)
	}
	if len(tcpListeners) == 0 { // couldn't bind to TCP anywhere? don't exit; TCP is optional
		log.Printf("I couldn't bind via TCP to any IPs on port %d", *bindPort)
	}

	// Read from the UDP connections & TCP Listeners
	// use goroutines to read from all the UDP connections EXCEPT the first; we don't use a goroutine for that
	// one because we use the first one to keep this program from exiting
	for _, udpConn := range udpConns[1:] {
		go readFromUDP(udpConn, x, *quiet, dw)
	}
	for _, tcpListener := range tcpListeners {
		go readFromTCP(tcpListener, x, *quiet, dw)
	}
	log.Printf("Ready to answer queries")
	readFromUDP(udpConns[0], x, *quiet, dw) // refrain from exiting; There should always be a udpConns[0], and readFromUDP() _never_ returns
}

// recordFlags parses the -a, -aaaa, -mx, -txt, and -ns flags into DomainCustomizations.
// The first flag of a given type for a domain replaces that domain's built-in records of
// that type (e.g. nip.io's protonmail MX records); subsequent flags append.
type recordFlags struct {
	customizations xip.DomainCustomizations
	replaced       map[string]bool     // "type domain", e.g. "MX nip.io."
	txts           map[string][]string // domain → TXT strings, read at query time
	logMessages    []string
}

func newRecordFlags(customizations xip.DomainCustomizations) *recordFlags {
	return &recordFlags{
		customizations: customizations,
		replaced:       map[string]bool{},
		txts:           map[string][]string{},
	}
}

// splitRecordFlag splits "domain=value" into a lower-cased, absolute domain and the value
func splitRecordFlag(arg string) (domain, value string, err error) {
	domain, value, found := strings.Cut(arg, "=")
	if !found || domain == "" || value == "" {
		return "", "", fmt.Errorf(`should be in the format "domain=value", not %q`, arg)
	}
	return absolute(strings.ToLower(domain)), value, nil
}

// absolute appends the trailing "." if missing
func absolute(name string) string {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// update applies f to the domain's customization, clearing the built-in records of
// recordType the first time a flag of that type is seen for that domain
func (r *recordFlags) update(recordType, domain string, f func(dc *xip.DomainCustomization, first bool)) {
	key := recordType + " " + domain
	first := !r.replaced[key]
	r.replaced[key] = true
	dc := r.customizations[domain]
	f(&dc, first)
	r.customizations[domain] = dc
}

func (r *recordFlags) addA(arg string) error {
	domain, value, err := splitRecordFlag(arg)
	if err != nil {
		return err
	}
	ip := net.ParseIP(value).To4()
	if ip == nil {
		return fmt.Errorf("%q is not a valid IPv4 address", value)
	}
	r.update("A", domain, func(dc *xip.DomainCustomization, first bool) {
		if first {
			dc.A = nil
		}
		dc.A = append(dc.A, dnsmessage.AResource{A: [4]byte(ip)})
	})
	r.logMessages = append(r.logMessages, fmt.Sprintf(`Adding A record "%s=%s"`, domain, ip))
	return nil
}

func (r *recordFlags) addAAAA(arg string) error {
	domain, value, err := splitRecordFlag(arg)
	if err != nil {
		return err
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() != nil {
		return fmt.Errorf("%q is not a valid IPv6 address", value)
	}
	r.update("AAAA", domain, func(dc *xip.DomainCustomization, first bool) {
		if first {
			dc.AAAA = nil
		}
		dc.AAAA = append(dc.AAAA, dnsmessage.AAAAResource{AAAA: [16]byte(ip)})
	})
	r.logMessages = append(r.logMessages, fmt.Sprintf(`Adding AAAA record "%s=%s"`, domain, ip))
	return nil
}

func (r *recordFlags) addMX(arg string) error {
	domain, value, err := splitRecordFlag(arg)
	if err != nil {
		return err
	}
	prefString, host, found := strings.Cut(value, ",")
	if !found {
		return fmt.Errorf(`should be in the format "domain=preference,host", not %q`, arg)
	}
	pref, err := strconv.ParseUint(prefString, 10, 16)
	if err != nil {
		return fmt.Errorf("%q is not a valid MX preference (0-65535)", prefString)
	}
	mx, err := dnsmessage.NewName(absolute(host))
	if err != nil {
		return fmt.Errorf("%q is not a valid mail exchanger: %w", host, err)
	}
	r.update("MX", domain, func(dc *xip.DomainCustomization, first bool) {
		if first {
			dc.MX = nil
		}
		dc.MX = append(dc.MX, dnsmessage.MXResource{Pref: uint16(pref), MX: mx})
	})
	r.logMessages = append(r.logMessages, fmt.Sprintf(`Adding MX record "%s=%d,%s"`, domain, pref, mx))
	return nil
}

func (r *recordFlags) addTXT(arg string) error {
	domain, value, err := splitRecordFlag(arg)
	if err != nil {
		return err
	}
	// allow, but don't require, the text to be double-quoted
	if strings.HasPrefix(value, `"`) {
		if value, err = strconv.Unquote(value); err != nil {
			return fmt.Errorf("%q is not a properly-quoted string: %w", arg, err)
		}
	}
	if value == "" {
		return fmt.Errorf("TXT record for %q is empty", domain)
	}
	r.update("TXT", domain, func(dc *xip.DomainCustomization, first bool) {
		if first {
			r.txts[domain] = nil
		}
		dc.TXT = func(*xip.Xip, net.IP) ([]dnsmessage.TXTResource, error) {
			var txts []dnsmessage.TXTResource
			for _, txt := range r.txts[domain] {
				txts = append(txts, dnsmessage.TXTResource{TXT: chunk(txt, 255)})
			}
			return txts, nil
		}
	})
	r.txts[domain] = append(r.txts[domain], value)
	r.logMessages = append(r.logMessages, fmt.Sprintf(`Adding TXT record %s=%q`, domain, value))
	return nil
}

func (r *recordFlags) addNS(arg string) error {
	domain, value, err := splitRecordFlag(arg)
	if err != nil {
		return err
	}
	ns, err := dnsmessage.NewName(absolute(strings.ToLower(value)))
	if err != nil {
		return fmt.Errorf("%q is not a valid nameserver: %w", value, err)
	}
	r.update("NS", domain, func(dc *xip.DomainCustomization, first bool) {
		if first {
			dc.NS = nil
		}
		dc.NS = append(dc.NS, dnsmessage.NSResource{NS: ns})
	})
	r.logMessages = append(r.logMessages, fmt.Sprintf(`Adding NS record "%s=%s"`, domain, ns))
	return nil
}

// chunk splits s into strings of at most size bytes; a TXT record's strings can't exceed 255 bytes
func chunk(s string, size int) (chunks []string) {
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	return append(chunks, s)
}

func readFromUDP(conn *net.UDPConn, x *xip.Xip, quiet bool, dw *DnstapWriter) {
	for {
		query := make([]byte, 512)
		n, addr, err := conn.ReadFromUDP(query)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func() {
			queryTime := time.Now()
			response, logMessage, err := x.QueryResponse(query, addr.IP)
			if err != nil {
				log.Println(err.Error())
				return
			}
			_, err = conn.WriteToUDP(response, addr)
			if err != nil {
				log.Println(err.Error())
				return
			}
			if !quiet {
				log.Printf("%v.%d %s", addr.IP, addr.Port, logMessage)
			}
			if dw != nil && ResponseHasAorAAAA(response) {
				responseTime := time.Now()
				if err := dw.SendDnstap(query[:n], response, addr.IP, addr.Port, true, queryTime, responseTime); err != nil {
					log.Printf("dnstap send error: %v", err)
				}
			}
			x.Metrics.UDPQueries += 1
		}()
	}
}

// RFC 7766 §6.2.3 suggests an idle timeout of "a few seconds"; we choose 10
const tcpIdleTimeout = 10 * time.Second

func readFromTCP(tcpListener *net.TCPListener, x *xip.Xip, quiet bool, dw *DnstapWriter) {
	for {
		tcpConn, err := tcpListener.AcceptTCP()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		// hand off immediately: a slow or silent client must never block the accept loop
		go handleTCPConn(tcpConn, x, quiet, dw)
	}
}

func handleTCPConn(tcpConn *net.TCPConn, x *xip.Xip, quiet bool, dw *DnstapWriter) {
	defer func() {
		// a panic in one connection's goroutine would otherwise crash the entire server
		if r := recover(); r != nil {
			log.Printf("recovered from panic handling TCP connection from %s: %v", tcpConn.RemoteAddr(), r)
		}
	}()
	defer func(tcpConn *net.TCPConn) {
		_ = tcpConn.Close()
	}(tcpConn)
	remoteAddrPort := tcpConn.RemoteAddr().String()
	addr, port, err := net.SplitHostPort(remoteAddrPort)
	if err != nil {
		log.Println(err.Error())
		return
	}
	lengthPrefix := make([]byte, 2)
	for { // RFC 7766: support multiple queries per connection
		_ = tcpConn.SetDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err = io.ReadFull(tcpConn, lengthPrefix); err != nil {
			return // EOF or idle timeout: the normal end of a connection
		}
		queryLength := binary.BigEndian.Uint16(lengthPrefix)
		if queryLength == 0 {
			return
		}
		query := make([]byte, queryLength)
		if _, err = io.ReadFull(tcpConn, query); err != nil {
			log.Println(err.Error())
			return
		}
		queryTime := time.Now()
		response, logMessage, err := x.QueryResponse(query, net.ParseIP(addr))
		if err != nil {
			log.Println(err.Error())
			return
		}
		// insert the 2-byte length to the beginning of the response
		framedResponse := make([]byte, 2, 2+len(response))
		binary.BigEndian.PutUint16(framedResponse, uint16(len(response)))
		framedResponse = append(framedResponse, response...)
		if _, err = tcpConn.Write(framedResponse); err != nil {
			log.Println(err.Error())
			return
		}
		if !quiet {
			log.Printf("%s.%s %s", addr, port, logMessage)
		}
		if dw != nil && ResponseHasAorAAAA(response) {
			portNum, _ := strconv.Atoi(port)
			responseTime := time.Now()
			if err := dw.SendDnstap(query, response, net.ParseIP(addr), portNum, false, queryTime, responseTime); err != nil {
				log.Printf("dnstap send error: %v", err)
			}
		}
		x.Metrics.TCPQueries += 1
	}
}

func bindUDPAddressesIndividually(bindPort int) (udpConns []*net.UDPConn, unboundIPs []string) {
	// typical value of net.Addr.String() → "::1/128" "172.19.0.17/23"
	// (don't worry about the port numbers in https://pkg.go.dev/net#Addr; they won't appear)
	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf(`I couldn't get the local interface addresses: "%s"`, err.Error())
		return nil, nil
	}
	for _, interfaceAddr := range interfaceAddrs {
		ip, _, err := net.ParseCIDR(interfaceAddr.String())
		if err != nil {
			log.Printf(`I couldn't parse the local interface "%s".`, interfaceAddr.String())
			continue
		}
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   ip,
			Port: bindPort,
			Zone: "",
		})
		if err != nil {
			unboundIPs = append(unboundIPs, ip.String())
		} else {
			udpConns = append(udpConns, udpConn)
		}
	}
	return udpConns, unboundIPs
}

func bindTCPAddressesIndividually(bindPort int) (tcpListeners []*net.TCPListener, unboundIPs []string) {
	// typical value of net.Addr.String() → "::1/128" "172.19.0.17/23"
	// (don't worry about the port numbers in https://pkg.go.dev/net#Addr; they won't appear)
	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf(`I couldn't get the local interface addresses: "%s"`, err.Error())
		return nil, nil
	}
	for _, interfaceAddr := range interfaceAddrs {
		ip, _, err := net.ParseCIDR(interfaceAddr.String())
		if err != nil {
			log.Printf(`I couldn't parse the local interface "%s".`, interfaceAddr.String())
			continue
		}
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: bindPort})
		if err != nil {
			unboundIPs = append(unboundIPs, ip.String())
		} else {
			tcpListeners = append(tcpListeners, listener)
		}
	}
	return tcpListeners, unboundIPs
}

// Thanks https://stackoverflow.com/a/52152912/2510873
func isErrorAddressAlreadyInUse(err error) bool {
	var eOsSyscall *os.SyscallError
	if !errors.As(err, &eOsSyscall) {
		return false
	}
	var errErrno syscall.Errno // doesn't need a "*" (ptr) because it's already a ptr (uintptr)
	if !errors.As(eOsSyscall, &errErrno) {
		return false
	}
	if errors.Is(errErrno, syscall.EADDRINUSE) {
		return true
	}
	const WSAEADDRINUSE = 10048
	if runtime.GOOS == "windows" && errErrno == WSAEADDRINUSE {
		return true
	}
	return false
}

func isErrorPermissionsError(err error) bool {
	var eOsSyscall *os.SyscallError
	if errors.As(err, &eOsSyscall) {
		if os.IsPermission(eOsSyscall) {
			return true
		}
	}
	return false
}
