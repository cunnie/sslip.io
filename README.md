# sslip.io

[![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/check-dns/badge)](https://ci.nono.io/?groups=sslip.io)

*sslip.io* is a domain that maps specially-crafted DNS A records to IP addresses
(e.g. "127-0-0-1.sslip.io" maps to 127.0.0.1). It is similar to, inspired by,
and uses much of the code of [xip.io](http://xip.io/).

Refer to the website ([sslip.io](https://sslip.io)) for more information.

- `document_root/` contains the HTML content of the sslip.io website
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
