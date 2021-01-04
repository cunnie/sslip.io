In the following example, we create a webserver on Google Cloud Platform (GCP)
to acquire a wildcard certificate:

**Do Not Use** these instructions; they don't work. They are a work in progress.

```
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
export FQDN=${IP//./-}.sslip.io
echo $FQDN
 # set IP & FQDN on the VM because we'll need them later
gcloud compute ssh --command="echo export FQDN=$FQDN IP=$IP >> ~/.bashrc" --zone=us-west1-a sslip
 # create the rules to allow SSH, DNS, HTTP(S) inbound
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
 # Let's install the acme-dns Docker image
docker pull joohoi/acme-dns
 # Create the necessary directories
mkdir -p config/ data/ tls/
 # Grab the generic config
curl -L https://raw.githubusercontent.com/joohoi/acme-dns/master/config.cfg -o config/config.cfg
 # customize the config
sed -i "s/auth.example.org/$FQDN/g" config/config.cfg
 # disable systemd-resolved to fix "Error starting userland proxy: listen tcp 0.0.0.0:53: bind: address already in use."
 # thanks https://askubuntu.com/questions/907246/how-to-disable-systemd-resolved-in-ubuntu
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf
 # listen to port 53 on all interfaces (INADDR_ANY)
sed -i 's/^listen = "127.0.0.1:53"/listen = "0.0.0.0:53"/' config/config.cfg
sed -i "s/198.51.100.1/$IP/" config/config.cfg
 # webserver: listen to port 80, no TLS
sed -i 's/^tls = .*/tls = "none"/' config/config.cfg
sed -i 's/^port = .*/port = "80"/' config/config.cfg
 # Let's start 'er up:
docker run --rm --name acmedns     \
 -p 53:53                          \
 -p 53:53/udp                      \
 -p 80:80                          \
 -v $HOME/config:/etc/acme-dns:ro  \
 -v $HOME/data:/var/lib/acme-dns   \
 -d joohoi/acme-dns
 # sanity check; response should be "35-199-174-9.sslip.io." and "35.199.174.9"
dig +short ns $FQDN @localhost
dig +short $FQDN @localhost
 # Set up the acme.sh Let's Encrypt variables
curl -s -X POST http://$FQDN/register > /tmp/acme-dns.json
export ACMEDNS_UPDATE_URL="http://$FQDN/update"
export ACMEDNS_USERNAME=$(jq -r .username /tmp/acme-dns.json)
export ACMEDNS_PASSWORD=$(jq -r .password /tmp/acme-dns.json)
export ACMEDNS_SUBDOMAIN=$(jq -r .subdomain /tmp/acme-dns.json)
docker run --rm -it \
  -v $PWD/tls:/acme.sh \
  -e ACMEDNS_UPDATE_URL \
  -e ACMEDNS_USERNAME \
  -e ACMEDNS_PASSWORD \
  -e ACMEDNS_SUBDOMAIN \
  --net=host \
  neilpang/acme.sh \
    --issue \
    --staging \
    --debug \
    -d $FQDN \
    -d *.$FQDN \
    --dns dns_acmedns
```

Clean-up:
```
gcloud compute firewall-rules delete sslip-io-allow-dns-http-ssh
gcloud compute firewall-rules delete sslip-io-allow-dns-http
gcloud compute firewall-rules delete sslip-io-allow-dns
gcloud compute instances delete
```
