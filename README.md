# sslip.io

| Test Type | Status |
|---|---|
| Production Nameservers | [![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/dns-servers/badge)](https://ci.nono.io/teams/main/pipelines/sslip.io) |
| DNS Server Unit Tests | [![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/unit/badge)](https://ci.nono.io/teams/main/pipelines/sslip.io) |

*sslip.io* is a DNS server that maps specially-crafted DNS A records to IP
addresses (e.g. "127-0-0-1.sslip.io" maps to 127.0.0.1). It is similar to, and
inspired by, [xip.io](http://xip.io/).

If you'd like to use sslip.io _as a service_, refer to the website
([sslip.io](https://sslip.io)) for more information. This README targets
developers; the website targets users.

## Quick Start

```bash
git clone https://github.com/cunnie/sslip.io.git
cd sslip.io/src/sslip.io-dns-server/
sudo go run main.go
 # sudo is required on Linux, but not on macOS, to bind to privileged port 53
```

In another window:
```bash
dig @localhost 192.168.0.1.sslip.io +short
 # should return "192.168.0.1"
```

## Quick Start Tests

```bash
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go get github.com/onsi/gomega/...
~/go/bin/ginkgo -r -p .
```

## Customizing Your Own Nameservers

You can customize your nameserver and address records (NS, A, and AAAA), which
can be particularly useful in an internetless (air-gapped) environment. This can
be done with a combination of the `-nameservers` flag and the `-addresses` flag.

For example, let's say you're the DNS admin for pivotal.io, and you'd like to
have a subdomain, "xip.pivotal.io", that does sslip.io-style lookups (e.g.
"127.0.0.1.xip.pivotal.io" would resolve to "127.0.0.1"). Let's say you have two
servers that you've set aside for this purpose:

- ns-sslip-0.pivotal.io, 10.8.8.8 (IPv4)
- ns-sslip-1.pivotal.io, fc88:: (IPv6)

First, you'd delegate the subdomain "xip.pivotal.io" to those nameservers, and
then you'd run the following command run on each of the two servers:

```bash
go run main.go \
  -nameservers=ns-sslip-0.pivotal.io,ns-sslip-1.pivotal.io \
  -addresses ns-sslip-0.pivotal.io=10.8.8.8,ns-sslip-1.pivotal.io=fc88::
```

**Note: These nameservers are not general-purpose nameservers; for example,
they won't look up google.com. They are not recursive.** Don't ever configure a
machine to point to these nameservers.

## Directory Structure

- `src/` contains the source code to the DNS server
- `ci/` contains the [Concourse](https://concourse.ci/) continuous integration
  (CI) pipeline and task
- `spec/` contains the tests for the production nameservers.  To run
  the tests locally:
  ```bash
  DOMAIN=sslip.io rspec --format documentation --color spec/
  ```
- `k8s/document_root_sslip.io/` contains the HTML content of the sslip.io website. Please
  run `tidy -im -w 120 k8s/document_root_sslip.io/index.html` before submitting pull
  requests
- `bosh-release/` _[deprecated]_ contains the [BOSH](https://bosh.io/docs/)
  release. BOSH is the mechanism we previously used to deploy the servers, and
  the sslip.io BOSH release is a packaging of the DNS server (analogous to a
  `.msi`, `.pkg`, `.deb` or `.rpm`)

## DNS Server

The DNS server is written in Golang and can be configured via flags passed to
the command line.

- it binds to port 53, but can be overridden on the command line with the
  `-port`, e.g. `go run main.go -port 9553`
- it only binds to UDP (no TCP, sorry)
- The NS records default to `ns-aws.sslip.io`, `ns-azure.sslip.io`,
  `ns-gce.sslip.io`; however, they can be overridden via the `-nameservers`
  flag, e.g. `go run main.go -nameservers ns1.example.com,ns2.example.com`). If
  you override the name servers, don't forget to set address records for the
  new name servers with the `-addresses` flag. Exception: `_acme-challenge`
  records are handled differently to accommodate the procurement of Let's
  Encrypt wildcard certificates; you can read more about that procedure
  [here](docs/wildcard.md)
- You can add custom records via the `-addresses` flag; here's a typical
  example where we set an IPv4 record & IPv6 record for a single host:
  `-addresses
  ns-aws.sslip.io.=52.0.56.137,ns-aws.sslip.io.=2600:1f18:aaf:6900::a`
- The SOA record is hard-coded except the _MNAME_ (primary master name server)
  record, which is set to the queried hostname (e.g. `dig big.apple.com
  @ns-aws.nono.io` would return an SOA with an _MNAME_ record of
  `big.apple.com.`
- The MX records are hard-coded to the queried hostname with a preference of 0,
  except `sslip.io` itself, which has custom MX records to enable email
  delivery to ProtonMail
- There are no SRV records

### Acknowledgements

- Sam Stephenson (xip.io), Roopinder Singh (nip.io), and the other DNS
  developers out there
- The contributors (@normanr, @jpambrun come to mind) who improved sslip.io
- Jenessa Petersen of Let's Encrypt who bumped the rate limits
- Natalia Ershova of JetBrains who provided a free license for [open source
  development](https://www.jetbrains.com/community/opensource/#support)
