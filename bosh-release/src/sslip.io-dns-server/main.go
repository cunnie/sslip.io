package main

import (
	"log"
	"net"
	"os"
	"errors"

	"xip/xip"
)

func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		//  err is usually a net.OpError wrapping an os.SyscallError
		var e *os.SyscallError
		if errors.As(err, &e) {
			if os.IsPermission(e) {
				log.Println("Invoke me with `sudo` because I don't have permission to bind to port 53.")
			}
		}
		log.Fatal(err.Error())
	}

	for {
		query := make([]byte, 512)
		_, addr, err := conn.ReadFromUDP(query)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		go func() {
			response, logMessage, err := xip.QueryResponse(query)
			if err != nil {
				log.Println(err.Error())
				return
			}
			_, err = conn.WriteToUDP(response, addr)
			log.Printf("%v.%d %s", addr.IP, addr.Port, logMessage)
		}()
	}
}
