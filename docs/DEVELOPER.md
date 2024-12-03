## Release Procedure

These instructions are meant primarily for me when deploying a new release;
they might not make sense unless you're on my workstation.

```bash
export OLD_VERSION=3.2.4
export VERSION=3.2.5
cd ~/workspace/sslip.io
git pull -r --autostash
# update the version number for the TXT record for version.status.sslip.io
sed -i '' "s/$OLD_VERSION/$VERSION/g" \
  bin/make_all \
  spec/check-dns_spec.rb
# update the download instructions on the website
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" \
  k8s/document_root_sslip.io/index.html \
  k8s/Dockerfile-sslip.io-dns-server
```

Optional: Update the version for the ns-aws, ns-azure, ns-gce, ns-ovh install scripts

```bash
pushd ~/bin
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" \
  ~/bin/install_ns-{aws,azure,gce,hetzner,ovh}.sh
git add -p
git ci -m"Update sslip.io DNS server $OLD_VERSION → $VERSION"
git push
popd
```

Build & start the new executables:

```bash
bin/make_all
# Start the server, assuming macOS M1. Adjust path for GOOS, GOARCH. Linux requires `sudo`
bin/sslip.io-dns-server-darwin-arm64
```

Test from another window:

```bash
export DNS_SERVER_IP=127.0.0.1
export VERSION=3.2.5
# quick sanity test
dig +short 127.0.0.1.example.com @$DNS_SERVER_IP
echo 127.0.0.1
# NS ordering might be rotated
dig +short ns example.com @$DNS_SERVER_IP
printf "ns-gce.sslip.io.\nns-hetzner.sslip.io.\nns-ovh.sslip.io.\n"
dig +short mx example.com @$DNS_SERVER_IP
echo "0 example.com."
dig +short mx sslip.io @$DNS_SERVER_IP
printf "10 mail.protonmail.ch.\n20 mailsec.protonmail.ch.\n"
dig +short txt sslip.io @$DNS_SERVER_IP
printf "\"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26\"\n\"v=spf1 include:_spf.protonmail.ch mx ~all\"\n"
dig +short txt 127.0.0.1.sslip.io @$DNS_SERVER_IP # no records
dig +short cname sslip.io @$DNS_SERVER_IP # no records
dig +short cname protonmail._domainkey.sslip.io @$DNS_SERVER_IP
echo protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.
dig a _Acme-ChallengE.127-0-0-1.sslip.io @$DNS_SERVER_IP | grep "^127"
echo "127-0-0-1.sslip.io.	604800	IN	A	127.0.0.1"
dig +short sSlIp.Io
echo 78.46.204.247
dig @$DNS_SERVER_IP txt ip.sslip.io +short | tr -d '"'
echo 127.0.0.1
dig @$DNS_SERVER_IP txt version.status.sslip.io +short | grep $VERSION
echo "\"$VERSION\""
echo " ===" # separator because the results are too similar
dig @$DNS_SERVER_IP 1.0.0.127.in-addr.arpa ptr +short
echo "127-0-0-1.sslip.io."
dig @$DNS_SERVER_IP _psl.sslip.io txt +short
echo "\"https://github.com/publicsuffix/list/pull/2206\""
dig @$DNS_SERVER_IP metrics.status.sslip.io txt +short | grep '"Queries: '
echo '"Queries: 13 (?.?/s)"'
```

Review the output then close the second window. Stop the server in the
original window. Commit our changes:

```bash
git add -p
git ci -vm"$VERSION: Minor bugfixes, tweaks"
git tag $VERSION
git push
git push --tags
scp bin/sslip.io-dns-server-linux-arm64 ns-aws:
scp bin/sslip.io-dns-server-linux-amd64 ns-azure:
scp bin/sslip.io-dns-server-linux-amd64 ns-gce:
scp bin/sslip.io-dns-server-linux-amd64 ns-hetzner:
scp bin/sslip.io-dns-server-linux-amd64 ns-ovh:
ssh ns-aws sudo install sslip.io-dns-server-linux-arm64 /usr/bin/sslip.io-dns-server
ssh ns-aws sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-aws.sslip.io version.status.sslip.io +short; do sleep 5; done # wait until it's back up before rebooting ns-azure
ssh ns-azure sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-azure sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-azure.sslip.io version.status.sslip.io +short; do sleep 5; done # wait until it's back up before rebooting ns-gce
ssh ns-gce sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-gce sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-gce.sslip.io version.status.sslip.io +short; do sleep 5; done # wait until it's back up before rebooting ns-hetzner
ssh ns-hetzner sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-hetzner sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-hetzner.sslip.io version.status.sslip.io +short; do sleep 5; done # wait until it's back up before rebooting ns-ovh
ssh ns-ovh sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-ovh sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-ovh.sslip.io version.status.sslip.io +short; do sleep 5; done
```

- Browse to <https://github.com/cunnie/sslip.io/releases/new> to draft a new release
- Drag and drop the executables in `bin/` to the _Attach binaries..._ section.
- Click "Publish release"

```bash
fly -t nono trigger-job -j sslip.io/build-and-push-sslip.io-dns-server
```

Update the webservers with the HTML with new versions:

```bash
ssh nono.io curl -L -o /www/sslip.io/document_root/index.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_sslip.io/index.html
for HOST in ns-{aws,azure,gce,hetzner,ovh}.sslip.io; do
  ssh $HOST curl -L -o /var/nginx/sslip.io/index.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_sslip.io/index.html
done
```

Browse to <https://ci.nono.io/teams/main/pipelines/sslip.io> and check that everything is green.
