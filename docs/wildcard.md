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
    --staging \
    --debug \
    -d $FQDN \
    -d *.$FQDN \
    --dns dns_acmedns
```

Clean-up:
```
gcloud compute firewall-rules delete sslip-io-allow-dns
gcloud compute instances delete sslip
```