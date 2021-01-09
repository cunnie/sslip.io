package main

import (
	"log"
	"net"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

var txt = `Set this TXT record: curl -X POST http://localhost/update -d  '{"txt":"Certificate Authority's validation token"}'`

func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		log.Fatal(err.Error())
	}

	var group sync.WaitGroup
	group.Add(1)
	go dnsServer(conn, &group)
	group.Add(1)
	go httpServer(&group)
	group.Wait()
}

func dnsServer(conn *net.UDPConn, group *sync.WaitGroup) {
	var query dnsmessage.Message

	defer group.Done()
	log.Println("I'm firing up the DNS server.")
	queryRaw := make([]byte, 512)
	for {
		_, addr, err := conn.ReadFromUDP(queryRaw)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		err = query.Unpack(queryRaw)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		// Technically, there can be multiple questions in a DNS message; practically, there's only one
		if len(query.Questions) != 1 {
			log.Printf("I expected one question but got %d.\n", len(query.Questions))
			continue
		}
		// We only return answers to TXT records, nothing else
		if query.Questions[0].Type != dnsmessage.TypeTXT {
			log.Println("I expected a question for a TypeTXT record but got a question for a " + query.Questions[0].Type.String() + " record.")
			continue
		}
		reply := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               query.ID,
				Response:         true,
				Authoritative:    true,
				RecursionDesired: query.RecursionDesired,
			},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  query.Questions[0].Name,
						Type:  dnsmessage.TypeTXT,
						Class: dnsmessage.ClassINET,
					},
					Body: &dnsmessage.TXTResource{TXT: []string{txt}},
				},
			},
		}
		replyRaw, err := reply.Pack()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		_, err = conn.WriteToUDP(replyRaw, addr)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		log.Printf("%v.%d %s → \"%s\"\n", addr.IP, addr.Port, query.Questions[0].Type.String(), txt)
	}
}

func httpServer(group *sync.WaitGroup) {
	defer group.Done()
	log.Println("I'm firing up the HTTP server.")
}
