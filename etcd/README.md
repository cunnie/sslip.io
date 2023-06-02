### Setting Up `etcd`

We set up `etcd` as a backing database for our `sslip.io` webserver.

#### Generate Certificates

We need to generate certificates for our etcd cluster (our cluster will
communicate over TLS, but our clients won't).

- `ca-config.json`. We set the certificates it issues to expire in 30
  years (262800 hours) because we don't want to go through a certificate
  rotation. Trust me on this one.
- `ca-csr.json`. Again, 30 years.

```shell
cfssl gencert -initca ca-csr.json | cfssljson -bare etcd-ca
```

The key is saved in LastPass as `etcd-ca-key.pem`.

Let's use our newly-created CA to generate the etcd certificates. Note
that we throw almost every IP address/hostname we can think of into the
SANs field (why not?):

```shell
GKE_NODE_PUBLIC_IPv4=$(gcloud compute instances list --format=json |
  jq -r '[.[].networkInterfaces[0].accessConfigs[0].natIP] | join(",")')
PUBLIC_HOSTNAMES=ns-aws.sslip.io,ns-azure.sslip.io,ns-gce.sslip.io
HOSTNAMES=ns-aws,ns-azure,ns-gce
IPv4=127.0.0.1,52.0.56.137,52.187.42.158,104.155.144.4,$GKE_NODE_PUBLIC_IPv4
IPv6=::1,2600:1f18:aaf:6900::a
cfssl gencert \
  -ca=ca.pem \
  -ca-key=etcd-ca-key.pem \
  -config=ca-config.json \
  -hostname=${PUBLIC_HOSTNAMES},${HOSTNAMES},${IPv4},${IPv6} \
  -profile=etcd \
  etcd-csr.json | cfssljson -bare etcd
```

The key is saved in LastPass as `etcd-key.pem`.

#### Generating a New Cert for a New etcd Node

Let's say you've introduced _new_ IPv4 addresses, or that you've recreated your
GKE clusters, and all the addresses have changed, then you'll need to
regenerate the certificates:

```
lpass show --note etcd-ca-key.pem > etcd-ca-key.pem
lpass show --note etcd-key.pem > etcd-key.pem
GKE_NODE_PUBLIC_IPv4=$(gcloud compute instances list --format=json |
  jq -r '[.[].networkInterfaces[0].accessConfigs[0].natIP] | join(",")')
PUBLIC_HOSTNAMES=ns-aws.sslip.io,ns-azure.sslip.io,ns-gce.sslip.io
HOSTNAMES=ns-aws,ns-azure,ns-gce
IPv4=127.0.0.1,52.0.56.137,52.187.42.158,104.155.144.4,$GKE_NODE_PUBLIC_IPv4
IPv6=::1,2600:1f18:aaf:6900::a

cfssl gencsr \
  -key=etcd-key.pem \
  -hostname=${PUBLIC_HOSTNAMES},${HOSTNAMES},${IPv4},${IPv6} \
  -cert=etcd.pem | cfssljson -bare etcd
cfssl sign \
  -ca=ca.pem \
  -ca-key=etcd-ca-key.pem \
  -config=ca-config.json \
  -profile=etcd \
  etcd.csr | cfssljson -bare etcd
```

#### Configure ns-aws.sslip.io & ns-azure.sslip.io

Now let's set up etcd on either ns-aws or ns-azure:

```shell
sudo mkdir /etc/etcd # default's okay: root:root 755
IAAS=${HOST/ns-/}
cd /etc/etcd
sudo curl -OL https://raw.githubusercontent.com/cunnie/sslip.io/main/etcd/ca.pem
sudo curl -OL https://raw.githubusercontent.com/cunnie/sslip.io/main/etcd/etcd.pem
sudo curl -o /etc/default/etcd -L https://raw.githubusercontent.com/cunnie/sslip.io/main/etcd/etcd-$IAAS.conf
lpass login brian.cunnie@gmail.com --trust
lpass show --note etcd-key.pem | sudo tee etcd-key.pem
sudo chmod 400 *key*
sudo chown etcd:etcd *key*
```

Let's fire up etcd:

```shell
sudo systemctl daemon-reload
sudo systemctl enable etcd
sudo systemctl stop etcd
sudo systemctl start etcd
sudo journalctl -xefu etcd # look for any errors on startup
sudo systemctl restart sslip.io-dns
dig @localhost metrics.status.sslip.io txt +short | grep "Key-value store:" # should be "etcd"
```

If the messages look innocuous (ignore "serving client traffic insecurely; this
is strongly discouraged!").

Check the cluster:

```shell
export ETCDCTL_API=3
etcdctl member list # first time: "8e9e05c52164694d, started, default, http://localhost:2380, http://localhost:2379, false"
  # existing cluster:
  660f0ebfd9c21a95: name=ns-aws peerURLs=https://ns-aws.sslip.io:2380 clientURLs=http://localhost:2379 isLeader=true
  6e7e4616e1032417: name=ns-azure peerURLs=https://ns-azure.sslip.io:2380 clientURLs=http://localhost:2379 isLeader=false
  b77b5c23840fa42b: name=ns-gce peerURLs=https://ns-gce.sslip.io:2380 clientURLs= isLeader=false
```

### Wiping old data

ns-aws & ns-azure:

```
sudo systemctl stop etcd
sudo rm -rf /var/lib/etcd/default/member
sudo systemctl start etcd
```

### Deleting and Re-adding ns-azure

This needs to be done when, for example, ns-azure is rebuilt from scratch.

```bash
ssh ns-aws
export ETCDCTL_API=3
etcdctl member list
 # 6e7e4616e1032417: name=ns-azure peerURLs=https://ns-azure.sslip.io:2380 clientURLs=http://localhost:2379 isLeader=false
etcdctl member remove 6e7e4616e1032417
etcdctl member add ns-azure --peer-urls=https://ns-azure.sslip.io:2380
exit
ssh ns-azure
sudo systemctl stop etcd
sudo rm -rf /var/lib/etcd/default/member
sudo -E nvim /etc/default/etcd
 # ETCD_INITIAL_CLUSTER_STATE="existing"
sudo systemctl start etcd
etcdctl member list
sudo du -sH /var/lib/etcd/default/member
```

### Updating the GKE PEM

This needs to be done every darn time the nodes are upgraded (there _must_ be a better way)

```bash
cd etcd/
lpass show --note etcd-ca-key.pem > etcd-ca-key.pem
lpass show --note etcd-key.pem > etcd-key.pem
GKE_NODE_PUBLIC_IPv4=$(gcloud compute instances list --format=json |
  jq -r '[.[].networkInterfaces[0].accessConfigs[0].natIP] | join(",")')
PUBLIC_HOSTNAMES=ns-aws.sslip.io,ns-azure.sslip.io,ns-gce.sslip.io
HOSTNAMES=ns-aws,ns-azure,ns-gce
IPv4=127.0.0.1,52.0.56.137,52.187.42.158,104.155.144.4,$GKE_NODE_PUBLIC_IPv4
IPv6=::1,2600:1f18:aaf:6900::a

cfssl gencsr \
  -key=etcd-key.pem \
  -hostname=${PUBLIC_HOSTNAMES},${HOSTNAMES},${IPv4},${IPv6} \
  -cert=etcd.pem | cfssljson -bare etcd
cfssl sign \
  -ca=ca.pem \
  -ca-key=etcd-ca-key.pem \
  -config=ca-config.json \
  -profile=etcd \
  etcd.csr | cfssljson -bare etcd

kubectl delete secret etcd-peer-tls
kubectl create secret generic etcd-peer-tls \
  --from-file=ca.pem=<(curl -L https://raw.githubusercontent.com/cunnie/sslip.io/main/etcd/ca.pem) \
  --from-file=etcd.pem=etcd.pem \
  --from-file=etcd-key.pem=<(lpass show --note etcd-key.pem)
kubectl get secret etcd-peer-tls -o json | \
  jq -r '.data."etcd.pem"' | \
  base64 -d | \
  openssl x509 -noout -text
kubectl rollout restart deployment/k-v.io
sleep 60 && kubectl rollout restart deployment/sslip.io # give time for etcd to come up
git status
git add -p
git ci -m"Update GKE node public IP addrs (etcd.pem)"
git push
```

### Troubleshooting

If `sudo journalctl -xefu etcd` errors with `member xxx has already been
bootstrapped`, then edit `/etc/default/etcd` and set
`ETCD_INITIAL_CLUSTER_STATE="existing"` (previously was `"new"`).
