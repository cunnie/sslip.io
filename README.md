# sslip.io

[![Production Nameservers](https://github.com/cunnie/sslip.io/actions/workflows/nameservers.yml/badge.svg)](https://github.com/cunnie/sslip.io/actions/workflows/nameservers.yml)
[![CI Tests](https://github.com/cunnie/sslip.io/actions/workflows/ci-tests.yml/badge.svg)](https://github.com/cunnie/sslip.io/actions/workflows/ci-tests.yml)
![QPS Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cunnie/67dc2a78c9ac6032db05027727c63ea1/raw/qps.json)

_sslip.io_ is a DNS server that maps specially-crafted DNS A records to IP
addresses (e.g. "127-0-0-1.sslip.io" maps to 127.0.0.1). It is similar to, and
inspired by the now-defunct xip.io.

If you'd like to use sslip.io _as a service_, refer to the website
([nip.io](https://nip.io)) for more information. This README targets
developers; the website targets users.

## Quick Start

```bash
git clone https://github.com/cunnie/sslip.io.git
cd sslip.io
go mod tidy
sudo go run .
 # sudo is required to bind to privileged port 53
```

In another window:

```bash
dig @localhost 192.168.0.1.sslip.io +short
 # should return "192.168.0.1"
```

### Quick Start Tests

```bash
go mod tidy
go generate
go install github.com/onsi/ginkgo/v2/ginkgo
go get github.com/onsi/gomega/...
 # exclude subdir "spec/", used for testing sslip.io service not code
~/go/bin/ginkgo -r -p --skip-package=spec .
```

## Running Your Own Nameservers

We can customize our nameserver and address records (NS, A, and AAAA). This can
be done with a combination of the `-ns`, `-a`, and `-aaaa` flags.

For example, let's say we're the DNS admin for pivotal.io and our email is
dns-admin\@pivotal.io, and we'd like to have a subdomain, "xip.pivotal.io",
that does sslip.io-style lookups (e.g. "127.0.0.1.xip.pivotal.io" would resolve
to "127.0.0.1"). Let's say we have two servers that we've set aside for this
purpose:

- ns-ip-0.pivotal.io, 10.8.8.8 (IPv4)
- ns-ip-1.pivotal.io, fc88:: (IPv6)

First, we delegate the subdomain "xip.pivotal.io" to our two nameservers, and
then we run the following command run on each of the two servers:

```bash
 # after we've cloned our repo & cd'ed into it
go run . \
  -ns=.=ns-ip-0.pivotal.io \
  -ns=.=ns-ip-1.pivotal.io \
  -a=ns-ip-0.pivotal.io=10.8.8.8 \
  -aaaa=ns-ip-1.pivotal.io=fc88:: \
  -soa=ns-ip-0.pivotal.io,dns-admin.pivotal.io,20261001,900,900,604800,180 \
  -blocklistURL=file:///dev/null \
  -ptr-domain=xip.pivotal.io
```

Note: These nameservers are not general-purpose nameservers; for example,
they won't look up google.com. They are not recursive. **Don't ever configure a
client to use these nameservers**.

### Running with Docker

Probably the easiest way to run the nameserver is with the official Docker
image,
[cunnie/sslip.io-dns-server](https://hub.docker.com/r/cunnie/sslip.io-dns-server).
Using our DNS servers from the previous example, we run the following, setting our port to 5553 so we can run unprivileged:

```bash
docker run \
  -it \
  --rm \
  -p 5553:53/udp \
  cunnie/sslip.io-dns-server \
  -ns=.=ns-ip-0.pivotal.io \
  -ns=.=ns-ip-1.pivotal.io \
  -a=ns-ip-0.pivotal.io=10.8.8.8 \
  -aaaa=ns-ip-1.pivotal.io=fc88:: \
  -soa=ns-ip-0.pivotal.io,dns-admin.pivotal.io,20261001,900,900,604800,180 \
  -blocklistURL=file:///dev/null \
  -ptr-domain=xip.pivotal.io
```

From our machine, we look up the DNS NS records for "127.0.0.1.com", and we
see the expected reply:

```bash
dig ns 127.0.0.1.com @localhost -p 5553
...
  ;; ANSWER SECTION:
  127.0.0.1.com.  604800 IN NS ns-ip-1.pivotal.io.
  127.0.0.1.com.  604800 IN NS ns-ip-0.pivotal.io.

  ;; ADDITIONAL SECTION:
  ns-ip-0.pivotal.io. 604800 IN A 10.8.8.8
  ns-ip-1.pivotal.io. 604800 IN AAAA fc88::
```

The Docker image is multi-platform, supporting both x86_64 architecture as well
as ARM64 (AWS Graviton, Apple M1–M6).

## Command-line Flags

- `-port` overrides the default port, 53, which the server binds to. This can
  be especially useful when running as a non-privileged user, unable to bind to
  privileged ports (<1024) ("`listen udp :53: bind: permission denied`"). For
  example, to run the server on port 9553: `go run main.go -port 9553`. To
  query, `dig @localhost 127.0.0.1.sslip.io -p 9553`
- `-ns` sets NS records as `domain=nameserver`. If the domain is `.`, it sets
  the nameservers returned for every query, e.g. `-ns=.=ns1.example.com
  -ns=.=ns2.example.com`. If you're running your own nameservers, you probably
  want to set this; otherwise no NS records are returned. Don't forget to set
  address records for your nameservers with the `-a` and `-aaaa` flags (see
  below). For any other domain, `-ns` delegates that domain and its subdomains
  to the nameserver, often used to acquire wildcard certificates from Let's
  Encrypt via the DNS-01 challenge, e.g.
  `-ns=_acme-challenge.73-189-219-4.xip.nono.io=ns-437.awsdns-54.com`
- `-a` sets an A (IPv4) record as `hostname=ipv4`, e.g.
  `-a=ns1.example.com=10.8.8.8`. Repeat the flag to set many addresses for a
  single host, e.g. `-a=ns1.example.com=1.1.1.1 -a=ns1.example.com=8.8.8.8`
- `-aaaa` sets an AAAA (IPv6) record as `hostname=ipv6`, e.g.
  `-aaaa=ns1.example.com=fc::8888`
- `-soa` sets the SOA record returned for every domain as
  `mname,rname,serial,refresh,retry,expire,minimum`, e.g.
  `-soa=ns1.example.com,dns-admin.example.com,20261001,900,900,604800,180`.
  Unlike the other record flags, there's only one SOA, and it always has a
  default: `ns-01.nip.io.,dns.nip.io.,20261001,900,900,604800,180`
- `-mx` sets an MX record as `domain=preference,host`, e.g.
  `-mx=example.com=10,mail.example.com -mx=example.com=20,mail2.example.com`.
  Without it, the MX record is the queried hostname with a preference of 0
- `-txt` sets a TXT record as `domain=text`; the surrounding double quotes are
  optional, e.g. `-txt=example.com="v=spf1 mx -all"`. Text longer than 255
  bytes is split into multiple strings within the record
- `-cname` sets a CNAME record as `domain=target`, e.g.
  `-cname=www.example.com=example.com`. A domain can have only one CNAME
- `-blocklistURL` overrides the default block list,
  (<https://raw.githubusercontent.com/cunnie/sslip.io/main/etc/blocklist.txt>).
  The blocklist is not a show-stopper: if the DNS server can't download the
  blocklist, it logs a message and continues to serve DNS queries
- `-ptr-domain` the domain to use for PTR records. For example, if you set
  `-ptr-domain=ip.example.com` and then do a reverse-lookup (PTR record), e.g.
  `dig -x 127.0.0.1`, the result will be `127-0-0-1.ip.example.com`. Best
  practice: make sure the forward lookup matches the reverse lookup, e.g. `dig
  127-0-0-1.ip.example.com` should return an A record of `127.0.0.1`.
- `-public` controls whether public addresses are resolved. If unsure, set
  `-public=false`, which means only private IP addresses will resolve, e.g.
  `10.9.9.30`, `192.168.0.1`, `169.254.169.254`. Let's say you run a bank, and
  your nip.io-style subdomain is `ip.wellsfargo.com`, you don't a phisher
  scammer to spin up a VM with a public IP address and get a certificate for
  that IP address's hostname `52-0-56-137.ip.wellsfargo.com` and use it to
  phish your customers. `-public=false` prevents that scenario.
- `-quiet` suppresses logging of each DNS response, which can save you money
  if your cloud provider charges you to retain logs
- `-dnstap` enables [dnstap](https://dnstap.info/) logging of queries that
  return an A or AAAA record; its argument is the destination socket, either a
  Unix socket path (e.g. `/var/run/dnstap.sock`) or a TCP address (e.g.
  `127.0.0.1:6000`)

In the record flags (`-ns`, `-a`, `-aaaa`, `-soa`, `-mx`, `-txt`, `-cname`),
names are case-insensitive, and the trailing dot is optional. You can repeat
`-ns`, `-a`, `-aaaa`, `-mx`, and `-txt` to set several records for the same
domain.

## DNS Server Miscellany

- It binds to both UDP and TCP.
- It returns the same SOA record for every domain (see `-soa`).
- There are no SRV records

## Running Tests

- `spec/` contains the tests for the production nameservers. To ensure the production nameservers are running properly:

  ```bash
  DOMAINS=nip.io,sslip.io ginkgo -r -p spec/
  ```

- To test the code (if you've made changes) without testing the production nameservers:

```bash
ginkgo -r -p --skip-package=spec
```

- `k8s/document_root_nip.io/` contains the HTML content of the nip.io
  website.

### Acknowledgements

- The late, great Roopinder Singh (nip.io), Sam Stephenson (xip.io), and the
  other DNS developers out there
- The contributors (@normanr, @jpambrun come to mind) who improved sslip.io
- Let's Encrypt for bumping our rate limits many, many times
