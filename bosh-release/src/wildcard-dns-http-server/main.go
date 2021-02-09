package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/dns/dnsmessage"
)

var txts = []string{`Set this TXT record: curl -X POST http://localhost/update -d  '{"txt":"Certificate Authority validation token"}'`}

// Txt is for parsing the JSON POST to set the DNS TXT record
type Txt struct {
	Txt string `json:"txt"`
}

func main() {
	var wg sync.WaitGroup
	log.Println("DNS: starting up.")
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	switch {
	case err == nil:
		log.Println(`DNS: Successfully bound to all interfaces, port 53.`)
		wg.Add(1)
		go dnsServer(conn, &wg)
	case isErrorPermissionsError(err):
		log.Println("DNS: Try invoking me with `sudo` because I don't have permission to bind to port 53.")
		log.Fatal("DNS: " + err.Error())
	case isErrorAddressAlreadyInUse(err):
		log.Println(`DNS: I couldn't bind to "0.0.0.0:53" (INADDR_ANY, all interfaces), so I'll try to bind to each address individually.`)
		ipCIDRs := listLocalIPCIDRs()
		var boundIPsPorts, unboundIPs []string
		for _, ipCIDR := range ipCIDRs {
			ip, _, err := net.ParseCIDR(ipCIDR)
			if err != nil {
				log.Printf(`DNS: I couldn't parse the local interface "%s".`, ipCIDR)
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
				go dnsServer(conn, &wg)
			}
		}
		if len(boundIPsPorts) > 0 {
			log.Printf(`DNS: I bound to the following: "%s"`, strings.Join(boundIPsPorts, `", "`))
		}
		if len(unboundIPs) > 0 {
			log.Printf(`DNS: I couldn't bind to the following IPs: "%s"`, strings.Join(unboundIPs, `", "`))
		}
	default:
		log.Fatal("DNS: " + err.Error())
	}
	wg.Add(1)
	go httpServer(&wg)
	wg.Wait()
}

func dnsServer(conn *net.UDPConn, group *sync.WaitGroup) {
	var query dnsmessage.Message

	defer group.Done()
	queryRaw := make([]byte, 512)
	for {
		_, addr, err := conn.ReadFromUDP(queryRaw)
		if err != nil {
			log.Println("DNS: " + err.Error())
			continue
		}
		err = query.Unpack(queryRaw)
		if err != nil {
			log.Println("DNS: " + err.Error())
			continue
		}
		// Technically, there can be multiple questions in a DNS message; practically, there's only one
		if len(query.Questions) != 1 {
			log.Printf("DNS: I expected one question but got %d.\n", len(query.Questions))
			continue
		}
		// We only return answers to TXT queries, nothing else
		if query.Questions[0].Type != dnsmessage.TypeTXT {
			log.Println("DNS: I expected a question for a TypeTXT record but got a question for a " + query.Questions[0].Type.String() + " record.")
			continue
		}
		var txtAnswers = []dnsmessage.Resource{}
		for _, txt := range txts {
			txtAnswers = append(txtAnswers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  query.Questions[0].Name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.TXTResource{TXT: []string{txt}},
			})
		}
		reply := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               query.ID,
				Response:         true,
				Authoritative:    true,
				RecursionDesired: query.RecursionDesired,
			},
			Questions: query.Questions,
			Answers:   txtAnswers,
		}
		replyRaw, err := reply.Pack()
		if err != nil {
			log.Println("DNS: " + err.Error())
			continue
		}
		_, err = conn.WriteToUDP(replyRaw, addr)
		if err != nil {
			log.Println("DNS: " + err.Error())
			continue
		}
		log.Printf("DNS: %v.%d %s → \"%v\"\n", addr.IP, addr.Port, query.Questions[0].Type.String(), txts)
	}
}

func httpServer(group *sync.WaitGroup) {
	defer group.Done()
	log.Println("HTTP: starting up.")
	http.HandleFunc("/", usageHandler)
	http.HandleFunc("/update", updateTxtHandler)
	log.Fatal("HTTP: " + http.ListenAndServe(":80", nil).Error())
}

func usageHandler(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintln(w, `Set the TXT record: curl -X POST http://localhost/update -d  '{"txt":"Certificate Authority's validation token"}'`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("HTTP: " + err.Error())
	}
	log.Printf("HTTP: wrong path (%s) with method (%s).\n", r.URL.Path, r.Method)
}

func updateTxtHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	if r.Method != http.MethodPost {
		err = errors.New("/update requires POST method, not " + r.Method + " method")
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println("HTTP: " + err.Error())
		return
	}
	var body []byte
	if body, err = ioutil.ReadAll(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("HTTP: " + err.Error())
		return
	}
	var updateTxt Txt
	if err := json.Unmarshal(body, &updateTxt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("HTTP: " + err.Error())
		return
	}
	if body, err = json.Marshal(updateTxt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("HTTP: " + err.Error())
		return
	}
	if _, err = fmt.Fprintf(w, string(body)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("HTTP: " + err.Error())
		return
	}
	log.Println("HTTP: Creating new TXT record \"" + updateTxt.Txt + "\".")
	// this is the money shot, where we create a new DNS TXT record to what was in the POST request
	txts = append(txts, updateTxt.Txt)
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
