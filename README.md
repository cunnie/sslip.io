# sslip.io [![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/check-dns/badge)](https://ci.nono.io/?groups=sslip.io)

*sslip.io* is a domain that maps specially-crafted DNS A records to IP addresses
(e.g. "127-0-0-1.sslip.io" maps to 127.0.0.1). It is similar to, and inspired
by, [xip.io](http://xip.io/).

Refer to the website ([sslip.io](https://sslip.io)) for more information.

- `document_root/` contains the HTML content of the sslip.io website
- `ci/` contains the Concourse CI pipeline and task
