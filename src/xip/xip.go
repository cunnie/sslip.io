package xip

import (
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"regexp"
	"strings"
)

// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
var ipv4RE= regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])[.-]){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))($|[.-])`)

func NameToA (fqdnString string) (dnsmessage.AResource, error) {
	fqdn:=[]byte(fqdnString)
	if ! ipv4RE.Match(fqdn) {
		return dnsmessage.AResource{}, errors.New("ENOTFOUND") // I can't help it; I love the old-style UNIX errors
	}

	match := string(ipv4RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ".", -1)
	ipv4address := net.ParseIP(match).To4()

	return dnsmessage.AResource{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}}, nil
}
