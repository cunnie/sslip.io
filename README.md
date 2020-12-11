# sslip.io

| Test Type | Status |
|---|---|
| Production Nameservers | [![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/check-dns/badge)](https://ci.nono.io/?groups=sslip.io) |
| DNS Server Unit Tests | _placeholder_ |

*sslip.io* is a DNS server that maps specially-crafted DNS A records to IP addresses
(e.g. "127-0-0-1.sslip.io" maps to 127.0.0.1). It is similar to, and inspired by,
[xip.io](http://xip.io/).

If you'd like to use sslip.io _as a service_, refer to the website
([sslip.io](https://sslip.io)) for more information. This README targets
developers; the website targets users.

- `src/` contains the source code to the DNS server.
- `ci/` contains the [Concourse](https://concourse.ci/) continuous integration
  (CI) pipeline and task.
- `spec/` contains the tests for the production nameservers.  To run
  the tests locally:
  ```bash
  DOMAIN=sslip.io rspec --format documentation --color spec/
  ```
- `k8s/document_root/` contains the HTML content of the sslip.io website. Please
  run `tidy -im -w 120 k8s/document_root/index.html` before submitting pull
  requests.
- `bosh-release/` contains the [BOSH](https://bosh.io/docs/) release. BOSH is
  the mechanism we use to deploy the servers, and the sslip.io BOSH release is a
  packaging of the DNS server (analogous to a `.msi`, `.pkg`, `.deb` or `.rpm`)
- `conf/sslip.io+nono.io.yml` ***(deprecated)*** contains the
  [PowerDNS's](https://www.powerdns.com/) [pipe
  backend's](https://doc.powerdns.com/md/authoritative/backend-pipe/)
  configuration in YAML format for use with [BOSH](https://bosh.io). The
  `pdns_pipe` key is the pipe backend script, and `pdns_pipe_conf` is its
  configuration file.

## DNS Server

The DNS server is written in Golang and is not configurable without modifying
the source:

- it binds to port 53 (you can't change it)
- it only binds to UDP (no TCP, sorry)
- if the hostname queried doesn't match, it doesn't return an _Answer_ section;
  instead, it returns an _Authorities_ section with an SOA.
- The SOA record is hard-coded with the exception of the _MNAME_ (primary master
  name server) record, which is set to the queried hostname (e.g. `dig
  big.apple.com @localhost` would have an SOA with an _MNAME_ record of
  `big.apple.com.`.
- The NS records are hard-coded
- The MX records are hard-coded with the exception of `sslip.io` itself, which
  has custom MX records to enable email delivery.
- There are no TXT records, or SRV. If those records (or any other unknown ones)
  are queried, the server returns no _Answers_ but an _Authorities_ section with
  the SOA

To run the unit tests:
```
cd src
go get github.com/onsi/ginkgo/ginkgo
go get github.com/onsi/gomega/...
ginkgo -r .
```

To run the server on, say, a Mac, you must first start the server:
```
cd src
go run main.go
```
And then, in another window, run a query, e.g.:
```
dig +short 127.0.0.1.sslip.io @localhost
```
Which will return the expected IP address:
```
127.0.0.1
```
You will also see a log message in the server window, similar to the
following:
```
2020/11/22 03:45:44 ::1.62302 TypeA 127.0.0.1.sslip.io. ? 127.0.0.1
```
