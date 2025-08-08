## Release Procedure

These instructions are meant primarily for me when deploying a new release;
they might not make sense unless you're on my workstation.

```bash
export OLD_VERSION=4.1.1
export VERSION=4.2.0
cd ~/workspace/sslip.io
git pull -r --autostash
# update the version number for the TXT record for version.status.sslip.io
sed -i '' "s/$OLD_VERSION/$VERSION/g" \
  bin/make_all \
  spec/check-dns_spec.rb
# update the download instructions on the website
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" \
  Docker/sslip.io-dns-server/Dockerfile
```

Optional: Update the version for the ns-gce, ns-hetzner, and ns-ovh install scripts

```bash
pushd ~/bin
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" \
  ~/bin/install_ns-{gce,hetzner,ovh}.sh ~/bin/install_common.sh
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
export VERSION=4.2.0
# quick sanity test
( dig +short 127.0.0.1.example.com @$DNS_SERVER_IP
echo 127.0.0.1 ) | uniq -c
# NS ordering might be rotated
( dig +short ns example.com @$DNS_SERVER_IP
printf "ns-do-sg.sslip.io.\nns-gce.sslip.io.\nns-hetzner.sslip.io.\nns-ovh.sslip.io.\n" ) | sort | uniq -c
( dig +short mx sslip.io @$DNS_SERVER_IP
printf "10 mail.protonmail.ch.\n20 mailsec.protonmail.ch.\n" ) | sort | uniq -c
( dig +short txt sslip.io @$DNS_SERVER_IP
printf "\"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26\"\n\"v=spf1 include:_spf.protonmail.ch mx ~all\"\n" ) | sort | uniq -c
( dig +short txt nip.io @$DNS_SERVER_IP
printf "\"protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313\"\n\"v=spf1 include:_spf.protonmail.ch mx ~all\"\n" ) | sort | uniq -c
dig +short txt 127.0.0.1.sslip.io @$DNS_SERVER_IP # no records
dig +short cname sslip.io @$DNS_SERVER_IP # no records
( dig +short cname protonmail._domainkey.sslip.io @$DNS_SERVER_IP
echo protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch. ) | uniq -c
( dig a _Acme-ChallengE.127-0-0-1.sslip.io @$DNS_SERVER_IP | grep "^127"
printf "127-0-0-1.sslip.io.\t604800\tIN\tA\t127.0.0.1" ) | uniq -c
( dig +short sSlIp.Io
echo 78.46.204.247 ) | uniq -c
( dig @$DNS_SERVER_IP txt ip.sslip.io +short | tr -d '"'
echo 127.0.0.1 ) | uniq -c
( dig @$DNS_SERVER_IP txt version.status.sslip.io +short | grep $VERSION
echo "\"$VERSION\"" ) | uniq -c
( dig @$DNS_SERVER_IP 1.0.0.127.in-addr.arpa ptr +short
echo "127-0-0-1.nip.io." ) | uniq -c
( dig @$DNS_SERVER_IP 7f000001.nip.io +short
echo 127.0.0.1 ) | uniq -c
dig @$DNS_SERVER_IP metrics.status.sslip.io txt +short | grep '"Queries: '
echo '"Queries: 13 (?.?/s)"'
```

Review the output then close the second window. Stop the server in the
original window. Commit our changes:

```bash
GIT_MESSAGE="$VERSION: -ptr-domain flag sets PTR domain, which now defaults to nip.io"
git add -p
git ci -vm"$GIT_MESSAGE"
git tag $VERSION
git push
git push --tags
scp bin/sslip.io-dns-server-linux-amd64 ns-do-sg:
scp bin/sslip.io-dns-server-linux-amd64 ns-gce:
scp bin/sslip.io-dns-server-linux-amd64 ns-hetzner:
scp bin/sslip.io-dns-server-linux-amd64 ns-ovh:
ssh ns-do-sg sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-do-sg sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-do-sg.sslip.io version.status.sslip.io +short; do sleep 5; done
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

Trigger a new workflow to publish the Docker image: <https://github.com/cunnie/sslip.io/actions/workflows/docker-sslip.io-dns-server.yml>

Update the webservers with the HTML with new versions:

```bash
ssh nono.io
cd /www/sslip.io/
git pull -r
exit
for HOST in {blocked,ns-do-sg,ns-gce,ns-hetzner,ns-ovh}.sslip.io; do
  ssh $HOST curl -L -o /var/nginx/sslip.io/index.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_sslip.io/index.html
done
```

Browse to <https://github.com/cunnie/sslip.io/actions/workflows/nameservers.yml>, trigger the workflow, and check that everything is green.
