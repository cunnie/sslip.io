### sslip.io

Operational Status: [![ci.nono.io](https://ci.nono.io/api/v1/pipelines/sslip.io/jobs/check-dns/badge)](https://ci.nono.io/?groups=sslip.io)
<sup><a href="#status" class="alert-link">[Status]</a></sup>

_sslip.io_ is a DNS ([Domain Name
System](https://en.wikipedia.org/wiki/Domain_Name_System)) service that, when
queried with a hostname with an embedded IP address, returns that IP Address.
It was inspired by and uses much of the code of [xip.io](http://xip.io), which
was created by [Sam Stephenson](https://github.com/sstephenson)

Here are some examples:

| hostname                          | IP Address               | Notes                    |
| ----------                        | ------------             | -------                  |
| 192.168.0.1.sslip.io              | 192.168.0.1              | dot separators           |
| 192-168-0-1.sslip.io              | 192.168.0.1              | dash separators          |
| www.192.168.0.1.sslip.io          | 192.168.0.1              | subdomain                |
| www.192-168-0-1.sslip.io          | 192.168.0.1              |                          |
| www-192-168-0-1.sslip.io          | 192.168.0.1              | embedded                         |
| --1.sslip.io                      | ::1                      | IPv6 — always use dashes |
| 2607-f8b0-400a-800--200e.sslip.io | 2607:f8b0:400a:800::200e | IPv6                     |

### BRANDING

sslip.io can be used to brand your own site (you don't need to use the sslip.io
domain).  For example, say you own the domain "example.com", and you want your
subdomain, "xip.example.com" to have xip.io-style features. To accomplish this,
you'd need to set the following four DNS servers as NS records for the
subdomain "xip.example.com"

| hostname              | IP address    | Location  |
| --------------------- | ------------- | --------  |
| `ns-aws.nono.io.`     | 52.0.56.137   | USA       |
| `ns-gce.nono.io.`     | 104.155.144.4 | USA       |
| `ns-azure.nono.io.`   | 52.187.42.158 | Singapore |
| `ns-he.nono.io.`      | 78.46.204.247 | Germany   |

Let's test it from the command line using `dig`:

```
dig +short 169-254-169-254.xip.example.com @ns-gce.nono.io.
```

Yields (hopefully
<sup><a href="#timeout" class="alert-link">[connection timed out]</a></sup>
):

```
169.254.169.254
```

#### TLS (Transport Layer Security)

If you have a wildcard certificate for your sslip.io-style subdomain, you may
install it on your machines for TLS-verified connections.

<div class="alert alert-warning" role="alert">
  When using a TLS wildcard certificate in conjunction with your branded
  sslip.io style subdomain, you must <b>use dashes not dots</b> as separators.
  For example, if you have the TLS certificate for <i>\*.xip.example.com</i>,
  you could browse to https://https://52-0-56-137.xip.example.com/ but not
  https://52.0.56.137.xip.example.com/.
</div>

For a real-world example of a TLS wildcard cert and sslip.io domain, browse
[https://52-0-56-137.sslip.io]( https://52-0-56-137.sslip.io).

Pivotal employees can download the sslip.io TLS private key
[here](https://drive.google.com/open?id=0ByweFu4TspftMWJPdE1US0hQTGc).

---

#### Footnotes

<a name="status"><sup>[Status]</sup></a>
A status of "build failing" rarely means the system is failing.  It's more
often an indication that when the servers were last checked (currently every
six hours), the CI (continuous integration)
[server](https://ci.nono.io/teams/main/pipelines/sslip.io) had difficulty
reaching one of the four sslip.io nameservers.  That's normal.
<sup><a href="#timeout" class="alert-link">[connection timed out]</a></sup>

<a name="timeout"><sup>[connection timed out]</sup></a>

DNS runs over [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) which
has no guaranteed delivery, and it's not uncommon for the packets to get lost
in transmission. DNS clients are programmed to seamlessly query a different
server when that happens. That's why DNS, by fiat, requires at least two
nameservers (for redundancy). From [IETF (Internet Engineering Task Force) RFC
(Request for Comment) 1034](https://tools.ietf.org/html/rfc1034):

> A given zone will be available from several name servers to insure its
availability in spite of host or communication link failure.  By administrative
fiat, we require every zone to be available on at least two servers, and many
zones have more redundancy than that.
