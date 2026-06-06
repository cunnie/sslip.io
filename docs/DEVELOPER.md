# Release Procedure

These instructions are meant primarily for me when deploying a new release;
they might not make sense unless you're on my workstation.

```bash
export OLD_VERSION=5.1.3
export VERSION=5.1.4
cd ~/workspace/sslip.io
git pull -r --autostash
# update the hard-coded version numbers
sed -i '' "s/$OLD_VERSION/$VERSION/g" \
  bin/make_all \
  spec/spec_suite_test.go \
  k8s/document_root_sslip.io/experimental.html \
  k8s/document_root_sslip.io/index.html \
  Docker/sslip.io-dns-server/Dockerfile \
  terraform/ns-00/cloud-init.yaml \
  terraform/ns-01/cloud-init.yaml
```

```bash
pushd ~/bin
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" \
  ~/bin/install_common.sh
git add -p
git ci -m"Update sslip.io DNS server $OLD_VERSION → $VERSION"
git push
popd
```

Build & start the new executables:

```bash
bin/make_all
bin/sslip.io-dns-server-darwin-arm64 --port 5333
```

Test from another window:

```bash
DNS_SERVER_IP=127.0.0.1
VERSION=5.1.4
PORT=5333
# quick sanity test
( dig +short 127.0.0.1.example.com @$DNS_SERVER_IP -p $PORT
echo 127.0.0.1 ) | uniq -c
# NS ordering might be rotated
( dig +short ns example.com @$DNS_SERVER_IP -p $PORT
printf "ns-00.nip.io.\nns-01.nip.io.\nns-ovh.sslip.io.\n" ) | sort | uniq -c
( dig +short mx sslip.io @$DNS_SERVER_IP -p $PORT
printf "10 mail.protonmail.ch.\n20 mailsec.protonmail.ch.\n" ) | sort | uniq -c
( dig +short txt nip.io @$DNS_SERVER_IP -p $PORT
printf "\"protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313\"\n\"v=spf1 include:_spf.protonmail.ch mx -all\"\n" ) | sort | uniq -c
( dig +short txt sslip.io @$DNS_SERVER_IP -p $PORT
printf "\"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26\"\n\"v=spf1 include:_spf.protonmail.ch mx -all\"\n" ) | sort | uniq -c
( dig +short txt _dmarc.nip.io. @$DNS_SERVER_IP -p $PORT ;
  dig +short txt _dmarc.sslip.io. @$DNS_SERVER_IP -p $PORT ;
  printf "\"v=DMARC1; p=reject\"\n"
  printf "\"v=DMARC1; p=reject\"\n" ; ) | sort | uniq -c
dig +short txt 127.0.0.1.sslip.io @$DNS_SERVER_IP -p $PORT # no records
dig +short cname sslip.io @$DNS_SERVER_IP -p $PORT # no records
( dig +short cname protonmail._domainkey.sslip.io @$DNS_SERVER_IP -p $PORT
echo protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch. ) | uniq -c
( dig a _Acme-ChallengE.127-0-0-1.sslip.io @$DNS_SERVER_IP -p $PORT | grep "^127"
printf "127-0-0-1.sslip.io.\t604800\tIN\tA\t127.0.0.1" ) | uniq -c
( dig +short sSlIp.Io @$DNS_SERVER_IP -p $PORT
echo 78.46.204.247 ) | uniq -c
( dig +short txt ip.sslip.io @$DNS_SERVER_IP -p $PORT | tr -d '"'
echo 127.0.0.1 ) | uniq -c
( dig +short txt version.status.sslip.io @$DNS_SERVER_IP -p $PORT | grep $VERSION
echo "\"$VERSION\"" ) | uniq -c
( dig +short ptr 1.0.0.127.in-addr.arpa @$DNS_SERVER_IP -p $PORT
echo "127-0-0-1.nip.io." ) | uniq -c
( dig +short ns-00.nip.io @$DNS_SERVER_IP -p $PORT
dig +short ns-do-sg.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short aaaa ns-00.nip.io @$DNS_SERVER_IP -p $PORT
dig +short aaaa ns-do-sg.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short ns-01.nip.io @$DNS_SERVER_IP -p $PORT
dig +short ns-hetzner.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short aaaa ns-01.nip.io @$DNS_SERVER_IP -p $PORT
dig +short aaaa ns-hetzner.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short ns-00.nip.io @$DNS_SERVER_IP -p $PORT
dig +short ns-do-sg.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short aaaa ns-00.nip.io @$DNS_SERVER_IP -p $PORT
dig +short aaaa ns-do-sg.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short ns-01.nip.io @$DNS_SERVER_IP -p $PORT
dig +short ns-hetzner.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short aaaa ns-01.nip.io @$DNS_SERVER_IP -p $PORT
dig +short aaaa ns-hetzner.sslip.io @$DNS_SERVER_IP -p $PORT ) | uniq -c
( dig +short 7f000001.nip.io @$DNS_SERVER_IP -p $PORT
echo 127.0.0.1 ) | uniq -c
dig +short txt metrics.status.sslip.io @$DNS_SERVER_IP -p $PORT | grep '"Queries: '
echo '"Queries: 32 (?.?/s)"'
```

Review the output then close the second window. Stop the server in the
original window. Commit our changes:

```bash
GIT_MESSAGE="$VERSION: new NS records: ns-0{0,1}.nip.io"
git add -p
git ci -vm"$GIT_MESSAGE"
git tag $VERSION
git push
git push --tags
for HOST in ns-00.nip.io ns-01.nip.io; do
  ssh $HOST sudo dnf upgrade -y
done
for HOST in 5.78.115.44 ns-ovh.sslip.io ; do
  ssh $HOST sudo apt-get update
  ssh $HOST sudo apt-get upgrade -y
  ssh $HOST sudo apt-get autoremove -y
done
scp bin/sslip.io-dns-server-linux-amd64 ns-00:
scp bin/sslip.io-dns-server-linux-amd64 ns-01:
scp bin/sslip.io-dns-server-linux-amd64 ns-ovh:
scp bin/sslip.io-dns-server-linux-amd64 5.78.115.44:
ssh ns-00 sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-00 sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-00.nip.io version.status.sslip.io +short; do sleep 5; done
ssh ns-01 sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-01 sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-01.nip.io version.status.sslip.io +short; do sleep 5; done # wait until it's back up before rebooting ns-ovh
ssh ns-ovh sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-ovh sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @ns-ovh.sslip.io version.status.sslip.io +short; do sleep 5; done
ssh 5.78.115.44 sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh 5.78.115.44 sudo shutdown -r now
 # check version number:
sleep 10; while ! dig txt @5.78.115.44 version.status.sslip.io +short; do sleep 5; done
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
for HOST in blocked.sslip.io; do
  ssh $HOST curl -L -o /var/nginx/sslip.io/index.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_sslip.io/index.html
  ssh $HOST curl -L -o /var/nginx/sslip.io/experimental.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_sslip.io/experimental.html
done
```

Browse to <https://github.com/cunnie/sslip.io/actions/workflows/nameservers.yml>, trigger the workflow, and check that everything is green.
