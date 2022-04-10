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
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

The key is saved in LastPass as `etcd-ca-key.pem`

Let's use our newly-created CA to generate the etcd certificates. Note
that we throw almost every IP address/hostname we can think of into the
SANs field (why not?):

```shell
PUBLIC_HOSTNAMES=ns-aws.sslip.io,ns-azure.sslip.io,ns-gce.sslip.io
HOSTNAMES=ns-aws,ns-azure,ns-gce
IPv4=127.0.0.1,52.0.56.137,52.187.42.158,104.155.144.4
IPv6=::1,2600:1f18:aaf:6900::a
cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=${PUBLIC_HOSTNAMES},${HOSTNAMES},${IPv4},${IPv6} \
  -profile=etcd \
  etcd-csr.json | cfssljson -bare etcd
```

The key is saved in LastPass as `etcd-key.pem`

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

### Troubleshooting

If `sudo journalctl -xefu etcd` errors with `member xxx has already been
bootstrapped`, then edit `/etc/default/etcd` and set
`ETCD_INITIAL_CLUSTER_STATE="existing"` (previously was `"new"`).
