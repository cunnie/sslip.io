# sslip.io

[![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/check-dns/badge)](https://ci.nono.io/?groups=sslip.io)

*sslip.io* is a domain that maps specially-crafted DNS A records to IP addresses
(e.g. "127-0-0-1.sslip.io" maps to 127.0.0.1). It is similar to, inspired by,
and uses much of the code of [xip.io](http://xip.io/).

Refer to the website ([sslip.io](https://sslip.io)) for more information.

- `k8s/document_root/` contains the HTML content of the sslip.io website
- `ci/` contains the [Concourse](https://concourse.ci/) continuous integration
  (CI) pipeline and task.
- `spec/` contains the RSpec files for test driven development (TDD).
  To run the tests:
```bash
DOMAIN=sslip.io rspec --format documentation --color spec
```
- `conf/sslip.io+nono.io.yml` contains the
  [PowerDNS](https://www.powerdns.com/)'s [pipe
  backend](https://doc.powerdns.com/md/authoritative/backend-pipe/)'s
  configuration in YAML format for use with [BOSH](https://bosh.io). The
  `pdns_pipe` key is the pipe backend script, and `pdns_pipe_conf` is its
  configuration file.

## Golang DNS Server

An experimental bare-bones DNS server written in Golang is available.

This Golang server is currently not configurable:

- it binds to port 53 (you can't change it)
- it only binds to UDP (no TCP, sorry)
- if the hostname queried doesn't match, it doesn't return an _Answer_ section;
  instead, it returns an _Authorities_ section with an SOA.
- The SOA record is hard-coded (e.g. _Serial_ is `2020090400`) with the
  exception of the _NS_ record, which is set to the queried hostname (e.g. `dig
  big.apple.com @localhost` would have an SOA with an _NS_ record of
  `big.apple.com.`.
- The NS, MX records are hard-coded.
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
You will also see a log message in the server window, something similar to the
following:
```
2020/11/22 03:45:44 ::1.62302 TypeA 127.0.0.1.sslip.io. ? 127.0.0.1
```
