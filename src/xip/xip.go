package xip

import (
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"regexp"
	"strings"
)

// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
var ipv4RE = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.-]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)
var ipv6RE = regexp.MustCompile(`(^|[.-])(([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)

func QueryResponse(queryBytes []byte) ([]byte, error) {
	var query dnsmessage.Message

	err := query.Unpack(queryBytes)
	if err != nil {
		return nil, err
	}

	response := dnsmessage.Message{
		Header:    ResponseHeader(query),
		Questions: query.Questions,
	}
	responseBytes, err := response.Pack()
	// I couldn't figure a way to test the error condition in Ginkgo
	if err != nil {
		return nil, err
	}
	return responseBytes, nil
}

func ResponseHeader(query dnsmessage.Message) dnsmessage.Header {
	return dnsmessage.Header{
		ID:                 query.ID,
		Response:           true,
		OpCode:             0,
		Authoritative:      true,
		Truncated:          false,
		RecursionDesired:   query.RecursionDesired,
		RecursionAvailable: false,
	}
}

func NameToA(fqdnString string) (dnsmessage.AResource, error) {
	fqdn := []byte(fqdnString)
	if !ipv4RE.Match(fqdn) {
		return dnsmessage.AResource{}, errors.New("ENOTFOUND") // I can't help it; I love the old-style UNIX errors
	}

	match := string(ipv4RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ".", -1)
	ipv4address := net.ParseIP(match).To4()

	return dnsmessage.AResource{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}}, nil
}

func NameToAAAA(fqdnString string) (dnsmessage.AAAAResource, error) {
	fqdn := []byte(fqdnString)
	if !ipv6RE.Match(fqdn) {
		return dnsmessage.AAAAResource{}, errors.New("ENOTFOUND") // I can't help it; I love the old-style UNIX errors
	}

	match := string(ipv6RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ":", -1)
	ipv16address := net.ParseIP(match).To16()

	AAAAR := dnsmessage.AAAAResource{}
	for i, _ := range ipv16address {
		AAAAR.AAAA[i] = ipv16address[i]
	}
	return AAAAR, nil
}
