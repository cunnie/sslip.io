package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

var txts = []string{`Set this TXT record: curl -X POST http://localhost/update -d  '{"txt":"Certificate Authority validation token"}'`}

// Txt is for parsing the JSON POST to set the DNS TXT record
type Txt struct {
	Txt string `json:"txt"`
}

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
		// We only return answers to TXT queries, nothing else
		if query.Questions[0].Type != dnsmessage.TypeTXT {
			log.Println("I expected a question for a TypeTXT record but got a question for a " + query.Questions[0].Type.String() + " record.")
			continue
		}
		var txtAnswers = []dnsmessage.Resource{}
		for _, txt := range txts {
			txtAnswers = append(txtAnswers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  query.Questions[0].Name,
						Type:  dnsmessage.TypeTXT,
						Class: dnsmessage.ClassINET,
						TTL: 60,
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
			Answers: txtAnswers,
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
		log.Printf("%v.%d %s → \"%v\"\n", addr.IP, addr.Port, query.Questions[0].Type.String(), txts)
	}
}

func httpServer(group *sync.WaitGroup) {
	defer group.Done()
	log.Println("I'm firing up the HTTP server.")
	http.HandleFunc("/", usageHandler)
	http.HandleFunc("/update", updateTxtHandler)
	log.Fatal(http.ListenAndServe(":80", nil))
}

func usageHandler(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprintln(w, `Set the TXT record: curl -X POST http://localhost/update -d  '{"txt":"Certificate Authority's validation token"}'`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
	}
}

func updateTxtHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	if r.Method != http.MethodPost {
		err = errors.New("/update requires POST method, not " + r.Method + " method")
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err.Error())
		return
	}
	var body []byte
	if body, err = ioutil.ReadAll(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}
	var updateTxt Txt
	if err := json.Unmarshal(body, &updateTxt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}
	if body, err = json.Marshal(updateTxt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}
	if _, err = fmt.Fprintf(w, string(body)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		return
	}
	log.Println("Creating new TXT record \"" + updateTxt.Txt + "\".")
	// this is the money shot, where we create a new DNS TXT record to what was in the POST request
	txts = append(txts, updateTxt.Txt)
}
