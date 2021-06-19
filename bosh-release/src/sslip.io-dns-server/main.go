package main

import (
	"errors"
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
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	//  common err hierarchy: net.OpError → os.SyscallError → syscall.Errno
	switch {
	case err == nil:
		log.Println(`Successfully bound to all interfaces, port 53.`)
		wg.Add(1)
		readFrom(conn, &wg)
	case isErrorPermissionsError(err):
		log.Println("Try invoking me with `sudo` because I don't have permission to bind to port 53.")
		log.Fatal(err.Error())
	case isErrorAddressAlreadyInUse(err):
		log.Println(`I couldn't bind to "0.0.0.0:53" (INADDR_ANY, all interfaces), so I'll try to bind to each address individually.`)
		ipCIDRs := listLocalIPCIDRs()
		var boundIPsPorts, unboundIPs []string
		for _, ipCIDR := range ipCIDRs {
			ip, _, err := net.ParseCIDR(ipCIDR)
			if err != nil {
				log.Printf(`I couldn't parse the local interface "%s".`, ipCIDR)
				continue
			}
			conn, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   ip,
				Port: 53,
				Zone: "",
			})
			if err != nil {
				unboundIPs = append(unboundIPs, ip.String())
			} else {
				wg.Add(1)
				boundIPsPorts = append(boundIPsPorts, conn.LocalAddr().String())
				go readFrom(conn, &wg)
			}
		}
		if len(boundIPsPorts) > 0 {
			log.Printf(`I bound to the following: "%s"`, strings.Join(boundIPsPorts, `", "`))
		}
		if len(unboundIPs) > 0 {
			log.Printf(`I couldn't bind to the following IPs: "%s"`, strings.Join(unboundIPs, `", "`))
		}
	default:
		log.Fatal(err.Error())
	}
	wg.Wait()
}

func readFrom(conn *net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		query := make([]byte, 512)
		_, addr, err := conn.ReadFromUDP(query)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		go func() {
			response, logMessage, err := xip.QueryResponse(query, addr.IP)
			if err != nil {
				log.Println(err.Error())
				return
			}
			_, err = conn.WriteToUDP(response, addr)
			log.Printf("%v.%d %s", addr.IP, addr.Port, logMessage)
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
