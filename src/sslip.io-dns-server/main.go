package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"xip/xip"
)

func main() {
	var wg sync.WaitGroup
	var blocklistURL = flag.String("blocklistURL", "https://raw.githubusercontent.com/cunnie/sslip.io/main/etc/blocklist.txt", `URL containing a list of "forbidden" names/CIDRs`)
	var nameservers = flag.String("nameservers", "ns-aws.sslip.io.,ns-azure.sslip.io.,ns-gce.sslip.io.", "comma-separated list of nameservers")
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
			"ns-gce.sslip.io=104.155.144.4", "comma-separated list of hosts and corresponding IPv4 and/or IPv6 address(es). If unsure, add to the list rather than replace")
	var bindPort = flag.Int("port", 53, "port the DNS server should bind to")
	var quiet = flag.Bool("quiet", false, "suppresses logging of each DNS response")
	flag.Parse()
	log.Printf("%s version %s starting", os.Args[0], xip.VersionSemantic)
	log.Printf("blocklist URL: %s, name servers: %s, bind port: %d, quiet: %t",
		*blocklistURL, *nameservers, *bindPort, *quiet)

	x, logmessages := xip.NewXip(*blocklistURL, strings.Split(*nameservers, ","), strings.Split(*addresses, ","))
	for _, logmessage := range logmessages {
		log.Println(logmessage)
	}

	connUdp, err := net.ListenUDP("udp", &net.UDPAddr{Port: *bindPort})
	//  common err hierarchy: net.OpError → os.SyscallError → syscall.Errno
	switch {
	case err == nil:
		log.Printf("Successfully bound via UDP to all IPs, port %d.\n", *bindPort)
		wg.Add(1)
		go readFrom(connUdp, &wg, x, *quiet)
	case isErrorPermissionsError(err):
		log.Printf("Try invoking me with `sudo` because I don't have permission to bind to port %d.\n", *bindPort)
		log.Fatal(err.Error())
	case isErrorAddressAlreadyInUse(err):
		log.Printf("I couldn't bind via UDP to \"0.0.0.0:%d\" (INADDR_ANY, all interfaces), so I'll try to bind to each address individually.\n", *bindPort)
		ipCIDRs := listLocalIPCIDRs()
		var boundIPsPorts, unboundIPs []string
		for _, ipCIDR := range ipCIDRs {
			ip, _, err := net.ParseCIDR(ipCIDR)
			if err != nil {
				log.Printf(`I couldn't parse the local interface "%s".`, ipCIDR)
				continue
			}
			connUdp, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   ip,
				Port: *bindPort,
				Zone: "",
			})
			if err != nil {
				unboundIPs = append(unboundIPs, ip.String())
			} else {
				wg.Add(1)
				boundIPsPorts = append(boundIPsPorts, connUdp.LocalAddr().String())
				go readFrom(connUdp, &wg, x, *quiet)
			}
		}
		if len(boundIPsPorts) == 0 {
			log.Fatalf("I couldn't bind via UDP to any IPs on port %d, so I'm exiting", *bindPort)
		}
		log.Printf(`I bound via UDP to the following IPs: "%s"`, strings.Join(boundIPsPorts, `", "`))
		if len(unboundIPs) > 0 {
			log.Printf(`I couldn't bind via UDP to the following IPs: "%s"`, strings.Join(unboundIPs, `", "`))
		}
	default:
		log.Fatal(err.Error())
	}
	log.Printf("Ready to answer queries")
	wg.Wait()
}

func readFrom(conn *net.UDPConn, wg *sync.WaitGroup, x *xip.Xip, quiet bool) {
	defer wg.Done()
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
		}()
	}
}

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
