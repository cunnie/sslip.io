package main

import (
	"encoding/json"
	"github.com/cunnie/sslip.io/src/xip"
	"log"
)
import "net"
import "golang.org/x/net/dns/dnsmessage"

func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		log.Fatal(err.Error())
	}

	var m dnsmessage.Message
	buf := make([]byte, 512)

	for {
		_, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println(err.Error())
			break
		}
		err = m.Unpack(buf)
		if err != nil {
			log.Println(err.Error())
			break
		}
		for _, question := range m.Questions {
			jsonQuestion, err := json.Marshal(question)
			if err != nil {
				log.Println(err.Error())
			}
			answer, _ := xip.NameToA(question.GoString())
			jsonAnswer, err := json.Marshal(answer)
			log.Println(jsonQuestion)
			log.Println(jsonAnswer)
		}
	}
}
