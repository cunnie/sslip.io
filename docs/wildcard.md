## Procuring a Wildcard Certificate

### Using a White Label Domain

Let's say you have a domain that is hosted on Amazon Route53, lets call it
`example.com`. You have a few DNS entries set up like `foo.example.com`, and then
you have `xip.example.com` which is an NS record to `ns-ovh.sslip.io`. So you
are able to use both regular DNS records that are hardcoded, and then when you
need to use sslip you simply use your xip subdomain.

To get a wildcard certificate for `*.xip.example.com`, simply go through the regular
Let's Encrypt DNS-01 challenge process.

Let's Encrypt will query your name servers for the TXT record
`_acme-challenge.xip.example.com`, then your DNS server will respond with the
TXT record _that should have been created on Route53 as part of the challenge_,
otherwise it'll return the delegated nameservers (ns-ovh.sslip.io and so on).

### Using the sslip.io domain

You can procure a [wildcard](https://en.wikipedia.org/wiki/Wildcard_certificate)
certificate (e.g. `*.52-0-56-137.sslip.io`) from a certificate authority (e.g.
Let's Encrypt) using the [DNS-01
challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

You'll need the following:

- An internet-accessible DNS server that's authoritative for its `sslip.io`
  subdomain For example, if the DNS server's IP address is `52.187.42.158`, the
  DNS server would need to be authoritative for the domain
  `52-187-42-158.sslip.io`.  Pro-tip: it only needs to be authoritative for the
  `_acme-challenge` subdomain, e.g. `_acme-challenge.52-187-42-158.sslip.io`;
  furthermore, it only needs to return TXT records.

  How to test that your DNS server is working properly (assuming you've set a
  TXT record, "I love my dog"):

  ```
  dig _acme-challenge.52-187-42-158.sslip.io txt
  ...
  _acme-challenge.52-187-42-158.sslip.io	604800	IN	TXT	"I love my dog"
  ...
  ```

- An [ACME
  v2](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment)
  protocol client; I use [acme.sh](https://github.com/acmesh-official/acme.sh).
  The ACME client must be able to update the TXT records of your DNS server.

### Using the Wildcard Certificate

Once you've procured the wildcard certificate, you can install it on your
internal webservers for URLS of the following format:
https://*internal-ip.external-ip*.sslip.io (e.g.
<https://www-192-168-0-10.52-187-42-158.sslip.io>). Note that the _internal-ip_
portion of the URL _must_ be dash-separated, not dot-separated, for the wildcard
certificate to work properly.

Tech note: wildcard certificates can be used for development for machines behind
a firewall using non-routable IP addresses (10/8, 172.16/12, 192.168/16) by
taking advantage of the manner which `sslip.io` parses hostnames with embedded
IP addresses: left-to-right. The internal IP address is parsed first and
returned as the IP address of the hostname.

### How Do I Set Up an External DNS Server?

The external IP might be from your local network (forward port 53 at your
router), or from a cloud provider (GCP, AWS, etc.). It might even be from a
public DNS service (e.g. [Cloudflare](https://www.cloudflare.com/), [AWS Route
53](https://aws.amazon.com/route53/), my perennial favorite
[easyDNS](https://easydns.com/), etc.).  If not using a public DNS service, you
need to run your own DNS server (e.g.
[acme-dns](https://github.com/joohoi/acme-dns), the venerable
[BIND](https://en.wikipedia.org/wiki/BIND), the opinionated
[djbdns](https://cr.yp.to/djbdns.html), or my personal
[wildcard-dns-http-server](https://github.com/cunnie/sslip.io/tree/main/src/wildcard-dns-http-server),
etc.).  You can use any ACME client
([acme.sh](https://github.com/acmesh-official/acme.sh),
[Certbot](https://certbot.eff.org/), etc.), but you must configure it to request
a wildcard certificate for \*._external-ip_.sslip.io, which requires configuring
the DNS-01 challenge to use DNS server chosen.

#### Example

In the following example, we create a webserver on Google Cloud Platform (GCP)
to acquire a wildcard certificate. We use the ACME client acme.sh and the
DNS server wildcard-dns-http-server:

```bash
gcloud auth login
 # set your project; mine is "blabbertabber"
gcloud config set project blabbertabber
 # create your VM
gcloud compute instances create \
  --image-project "ubuntu-os-cloud" \
  --image-family "ubuntu-2004-lts" \
  --machine-type f1-micro \
  --boot-disk-size 40 \
  --boot-disk-type pd-ssd \
  --zone "us-west1-a" \
  sslip
 # get the IP, e.g. 35.199.174.9
export NAT_IP=$(gcloud compute instances list --filter="name=('sslip')" --format=json | \
  jq -r '.[0].networkInterfaces[0].accessConfigs[0].natIP')
echo $NAT_IP
 # get the fully-qualified domain name, e.g. 35-199-174-9.sslip.io
export FQDN=${NAT_IP//./-}.sslip.io
echo $FQDN
 # set IP & FQDN on the VM because we'll need them later
gcloud compute ssh --command="echo export FQDN=$FQDN IP=$IP >> ~/.bashrc" --zone=us-west1-a sslip
 # create the rules to allow DNS (and ICMP/ping) inbound
gcloud compute firewall-rules create sslip-io-allow-dns \
  --allow udp:53,icmp \
  --network=default \
  --source-ranges 0.0.0.0/0 \
 # ssh onto the VM
gcloud compute ssh sslip -- -A
 # install docker
sudo apt update && sudo apt upgrade -y && sudo apt install -y docker.io jq
 # add us to the docker group
sudo addgroup $USER docker
newgrp docker
 # Create the necessary directories
mkdir -p tls/
 # disable systemd-resolved to fix "Error starting userland proxy: listen tcp 0.0.0.0:53: bind: address already in use."
 # thanks https://askubuntu.com/questions/907246/how-to-disable-systemd-resolved-in-ubuntu
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf
 # Let's start it up:
docker run -it --rm --name wildcard \
 -p 53:53/udp                       \
 -p 80:80                           \
 cunnie/wildcard-dns-http-server &
dig +short TXT does.not.matter.example.com @localhost
 # You should see `"Set this TXT record ..."`
export ACMEDNS_UPDATE_URL="http://localhost/update"
docker run --rm -it \
  -v $PWD/tls:/acme.sh \
  -e ACMEDNS_UPDATE_URL \
  --net=host \
  neilpang/acme.sh \
    --issue \
    --debug \
    -d $FQDN \
    -d *.$FQDN \
    --dns dns_acmedns
ls tls/$FQDN  # you'll see the new cert, key, certificate
openssl x509 -in tls/$FQDN/$FQDN.cer -noout -text # read the cert info
```

Save the cert, key, certificate, intermediate ca, fullchain cert. They are in
`tls/$FQDN/`.

Clean-up:

```
gcloud compute firewall-rules delete sslip-io-allow-dns
gcloud compute instances delete sslip
```

#### Troubleshooting / Debugging

Run the server in one window so you can see the output, and then ssh into
another window and watch the log output in realtime.

```
gcloud compute ssh sslip -- -A
docker run -it --rm --name wildcard \
 -p 53:53/udp                       \
 -p 80:80                           \
 cunnie/wildcard-dns-http-server
```

Notes about the logging output: any line that has the string "`TypeTXT →`" is
output from the DNS server; everything else is output from the HTTP server which
is used to create TXT records which the DNS server serves.

Use `acme.sh`'s `--staging` flag to make sure it works (so you don't run into
Let's Encrypt's [rate limits](https://letsencrypt.org/docs/rate-limits/) with
failed attempts).

```
docker run --rm -it \
  -v $PWD/tls:/acme.sh \
  -e ACMEDNS_UPDATE_URL \
  --net=host \
  neilpang/acme.sh \
    --issue \
    --staging \
    --debug \
    -d *.$FQDN \
    --dns dns_acmedns
```
