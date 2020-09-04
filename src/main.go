package main

import (
	"github.com/cunnie/sslip.io/src/xip"
	"log"
	"net"
)

func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		log.Fatal(err.Error())
	}

	query := make([]byte, 512)

	for {
		_, addr, err := conn.ReadFromUDP(query)
		if err != nil {
			log.Println(err.Error())
			break
		}

		go func() {
			response, err := xip.QueryResponse(query)
			if err == nil {
				log.Println(err.Error())
			} else {
				_, err = conn.WriteToUDP(response, addr)
			}
		}()
	}
}
