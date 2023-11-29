package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"xip/xip"
)

func main() {
	var blocklistURL = flag.String("blocklistURL",
		"https://raw.githubusercontent.com/cunnie/sslip.io/main/etc/blocklist.txt",
		`URL containing a list of non-resolvable IPs/names/CIDRs, usually phishing or scamming sites. Example "file://../../etc/blocklist.txt"`)
	var nameservers = flag.String("nameservers", "ns-aws.sslip.io.,ns-azure.sslip.io.,ns-gce.sslip.io.",
		"comma-separated list of FQDNs of nameservers. If you're running your own sslip.io nameservers, set them here")
	var addresses = flag.String("addresses",
		"sslip.io=78.46.204.247,"+
			"sslip.io=2a01:4f8:c17:b8f::2,"+
			"ns.sslip.io=52.0.56.137,"+
			"ns.sslip.io=52.187.42.158,"+
			"ns.sslip.io=104.155.144.4,"+
			"ns.sslip.io=2600:1f18:aaf:6900::a,"+
			"ns-aws.sslip.io=52.0.56.137,"+
			"ns-aws.sslip.io=2600:1f18:aaf:6900::a,"+
			"ns-azure.sslip.io=52.187.42.158,"+
			"ns-gce.sslip.io=104.155.144.4",
		"comma-separated list of hosts and corresponding IPv4 and/or IPv6 address(es). If you're running your own sslip.io nameservers, add their hostnames and addresses here. If unsure, add to the list rather than replace")
	var bindPort = flag.Int("port", 53, "port the DNS server should bind to")
	var quiet = flag.Bool("quiet", false, "suppresses logging of each DNS response. Use this to avoid Google Cloud charging you $30/month to retain the logs of your GKE-based sslip.io server")
	flag.Parse()
	log.Printf("%s version %s starting", os.Args[0], xip.VersionSemantic)
	log.Printf("blocklist URL: %s, name servers: %s, bind port: %d, quiet: %t",
		*blocklistURL, *nameservers, *bindPort, *quiet)

	x, logmessages := xip.NewXip(*blocklistURL, strings.Split(*nameservers, ","), strings.Split(*addresses, ","))
	for _, logmessage := range logmessages {
		log.Println(logmessage)
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
		go readFromUDP(udpConn, x, *quiet)
	}
	for _, tcpListener := range tcpListeners {
		go readFromTCP(tcpListener, x, *quiet)
	}
	log.Printf("Ready to answer queries")
	readFromUDP(udpConns[0], x, *quiet) // refrain from exiting; There should always be a udpConns[0], and readFromUDP() _never_ returns
}

func readFromUDP(conn *net.UDPConn, x *xip.Xip, quiet bool) {
	for {
		query := make([]byte, 512)
		_, addr, err := conn.ReadFromUDP(query)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func() {
			response, logMessage, err := x.QueryResponse(query, addr.IP)
			if err != nil {
				log.Println(err.Error())
				return
			}
			_, err = conn.WriteToUDP(response, addr)
			if !quiet {
				log.Printf("%v.%d %s", addr.IP, addr.Port, logMessage)
			}
			x.Metrics.UDPQueries += 1
		}()
	}
}

func readFromTCP(tcpListener *net.TCPListener, x *xip.Xip, quiet bool) {
	for {
		query := make([]byte, 65535) // 2-byte length field means largest size is 65535
		tcpConn, err := tcpListener.AcceptTCP()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		_, err = tcpConn.Read(query)
		query = query[2:] // remove the 2-byte length at the beginning of the query
		if err != nil {
			log.Println(err.Error())
			continue
		}
		remoteAddrPort := tcpConn.RemoteAddr().String()
		addr, port, err := net.SplitHostPort(remoteAddrPort)

		go func() {
			defer tcpConn.Close()
			response, logMessage, err := x.QueryResponse(query, net.ParseIP(addr))
			if err != nil {
				log.Println(err.Error())
				return
			}
			// insert the 2-byte length to the beginning of the response
			responseSize := uint16(len(response))
			responseSizeBigEndianBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(responseSizeBigEndianBytes, responseSize)
			response = append(responseSizeBigEndianBytes, response...)
			_, err = tcpConn.Write(response)
			if !quiet {
				log.Printf("%s.%s %s", addr, port, logMessage)
			}
			x.Metrics.TCPQueries += 1
		}()
	}
}

func bindUDPAddressesIndividually(bindPort int) (udpConns []*net.UDPConn, unboundIPs []string) {
	ipCIDRs := listLocalIPCIDRs()
	for _, ipCIDR := range ipCIDRs {
		ip, _, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			log.Printf(`I couldn't parse the local interface "%s".`, ipCIDR)
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
	ipCIDRs := listLocalIPCIDRs()
	for _, ipCIDR := range ipCIDRs {
		ip, _, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			log.Printf(`I couldn't parse the local interface "%s".`, ipCIDR)
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

// TODO: replace this function with net.InterfaceAddrs() ([]Addr, error)
// typical addr "10.9.9.161/24"
func listLocalIPCIDRs() []string {
	var ifaces []net.Interface
	var cidrStrings []string
	var err error
	if ifaces, err = net.Interfaces(); err != nil {
		panic(err)
	}
	for _, iface := range ifaces {
		var cidrs []net.Addr
		if cidrs, err = iface.Addrs(); err != nil {
			panic(err)
		}
		for _, cidr := range cidrs {
			cidrStrings = append(cidrStrings, cidr.String())
		}
	}
	return cidrStrings
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
	if errErrno == syscall.EADDRINUSE {
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
