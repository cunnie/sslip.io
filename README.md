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

We can customize our nameserver and address records (NS, A, and AAAA), which
can be particularly useful in an internetless (air-gapped) environment. This can
be done with a combination of the `-nameservers` flag and the `-addresses` flag.

For example, let's say we're the DNS admin for pivotal.io, and we'd like to
have a subdomain, "xip.pivotal.io", that does sslip.io-style lookups (e.g.
"127.0.0.1.xip.pivotal.io" would resolve to "127.0.0.1"). Let's say we have two
servers that we've set aside for this purpose:

- ns-ip-0.pivotal.io, 10.8.8.8 (IPv4)
- ns-ip-1.pivotal.io, fc88:: (IPv6)

First, we delegate the subdomain "xip.pivotal.io" to our two nameservers, and
then we run the following command run on each of the two servers:

```bash
# after we've cloned our repo & cd'ed into it
go run main.go \
  -nameservers=ns-ip-0.pivotal.io,ns-ip-1.pivotal.io \
  -addresses ns-ip-0.pivotal.io=10.8.8.8,ns-ip-1.pivotal.io=fc88:: \
  -ptr-domain=xip.pivotal.io
```

**Note: These nameservers are not general-purpose nameservers; for example,
they won't look up google.com. They are not recursive.** Don't ever configure a
client to use these nameservers.

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
    -nameservers=ns-ip-0.pivotal.io,ns-ip-1.pivotal.io \
    -addresses ns-ip-0.pivotal.io=10.8.8.8,ns-ip-1.pivotal.io=fc88:: \
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
as ARM64 (AWS Graviton, Apple M1/M2).

## Command-line Flags

- `-port` overrides the default port, 53, which the server binds to. This can
  be especially useful when running as a non-privileged user, unable to bind to
  privileged ports (<1024) ("`listen udp :53: bind: permission denied`"). For
  example, to run the server on port 9553: `go run main.go -port 9553`. To
  query, `dig @localhost 127.0.0.1.sslip.io -p 9553`
- `-nameservers` overrides the default NS records `ns-00.nip.io`,
  `ns-01.nip.io`, and `ns-ovh.sslip.io`; flag, e.g. `go run main.go
  -nameservers ns1.example.com,ns2.example.com`). If you're running your own
  nameservers, you probably want to set this. Don't forget to set address
  records for the new name servers with the `-addresses` flag (see below).
- `-addresses` overrides the default A/AAAA (IPv4/IPv6) address records. For
  example, here's how we set the IPv4 record & IPv6 record for our nameserver
  (in the `-nameservers` example above), ns1.example.com: `-addresses
  ns1.example.com=10.8.8.8,ns1.example.com=fc::8888`. Note that you can set
  many addresses for a single host, e.g.
  `ns1.example.com=1.1.1.1,ns1.example.com=8.8.8.8,ns1.example.com=9.9.9.9`
- `-blocklistURL` overrides the default block list,
  (<https://raw.githubusercontent.com/cunnie/sslip.io/main/etc/blocklist.txt>).
  The blocklist is not a show-stopper: if the DNS server can't download the
  blocklist, it logs a message and continues to serve DNS queries
- `ptr-domain` the domain to use for PTR records. For example, if you set
  `ptr-domain=ip.example.com` and then do a reverse-lookup (PTR record), e.g.
  `dig -x 127.0.0.1`, the result will be `127-0-0-1.ip.example.com`. Best
  practice: make sure the forward lookup matches the reverse lookup, e.g. `dig
  127-0-0-1.ip.example.com` should return an A record of `127.0.0.1`.
- `public` controls whether public addresses are resolved. If unsure, set
  `-public=false`, which means only private IP addresses will resolve, e.g.
  `10.9.9.30`, `192.168.0.1`, `169.254.169.254`. Let's say you run a bank, and
  your nip.io-style subdomain is `ip.wellsfargo.com`, you don't a phisher
  scammer to spin up a VM with a public IP address and get a certificate for
  that IP address's hostname `52-0-56-137.ip.wellsfargo.com` and use it to
  phish your customers. `-public=false` prevents that scenario.

## DNS Server Miscellany

- it binds to both UDP and TCP.
- The SOA record is hard-coded except the _MNAME_ (primary master name server)
  record, which is set to the queried hostname (e.g. `dig big.apple.com
  @ns.sslip.io` would return an SOA with an _MNAME_ record of
  `big.apple.com.`
- The MX records are hard-coded to the queried hostname with a preference of 0,
  except `sslip.io` itself, which has custom MX records to enable email
  delivery to ProtonMail
- There are no SRV records

## Directory Structure

- `spec/` contains the tests for the production nameservers. To run
  the tests locally:

  ```bash
  DOMAINS=nip.io,sslip.io ginkgo -r -p spec/
  ```

- `k8s/document_root_nip.io/` contains the HTML content of the nip.io
  website.

### Acknowledgements

- The late, great Roopinder Singh (nip.io), Sam Stephenson (xip.io), and the
  other DNS developers out there
- The contributors (@normanr, @jpambrun come to mind) who improved sslip.io
- Let's Encrypt for bumping our rate limits many, many times
