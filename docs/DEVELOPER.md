# Release Procedure

These instructions are meant primarily for me when deploying a new release;
they might not make sense unless you're on my workstation.

```bash
export OLD_VERSION=6.0.1
export VERSION=6.1.0
cd ~/workspace/sslip.io
git pull -r --autostash
# update the hard-coded version numbers
sed -i '' "s/$OLD_VERSION/$VERSION/g" \
  bin/make_all \
  spec/spec_suite_test.go \
  k8s/document_root_nip.io/experimental.html \
  k8s/document_root_nip.io/index.html \
  Docker/sslip.io-dns-server/Dockerfile \
  terraform/ns-00/cloud-init.yaml \
  terraform/ns-01/cloud-init.yaml \
  terraform/ns-ovh/cloud-init.sh
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
bin/sslip.io-dns-server-darwin-arm64 --port 5333 \
  -ns .=ns-00.nip.io. \
  -ns .=ns-01.nip.io. \
  -ns .=ns-ovh.sslip.io. \
  -blocklistURL=file:///dev/null \
  -a nip.io=78.46.204.247 \
  -a sslip.io=78.46.204.247 \
  -aaaa nip.io=2a01:4f8:c17:b8f::2 \
  -aaaa sslip.io=2a01:4f8:c17:b8f::2 \
  -a ns.nip.io=167.172.4.236 \
  -aaaa ns.nip.io=2400:6180:0:d2:0:2:e3e7:0 \
  -a ns.nip.io=5.78.28.211 \
  -aaaa ns.nip.io=2a01:4ff:1f2:10d:: \
  -a ns.nip.io=51.75.53.19 \
  -aaaa ns.nip.io=2001:41d0:602:2313::1 \
  -a ns.sslip.io=167.172.4.236 \
  -aaaa ns.sslip.io=2400:6180:0:d2:0:2:e3e7:0 \
  -a ns.sslip.io=5.78.28.211 \
  -aaaa ns.sslip.io=2a01:4ff:1f2:10d:: \
  -a ns.sslip.io=51.75.53.19 \
  -aaaa ns.sslip.io=2001:41d0:602:2313::1 \
  -a blocked.nip.io=64.176.22.9 \
  -aaaa blocked.nip.io=2001:19f0:c800:2315:: \
  -a ns-00.nip.io=167.172.4.236 \
  -aaaa ns-00.nip.io=2400:6180:0:d2:0:2:e3e7:0 \
  -a ns-01.nip.io=5.78.28.211 \
  -aaaa ns-01.nip.io=2a01:4ff:1f2:10d:: \
  -a ns-ovh.sslip.io=51.75.53.19 \
  -aaaa ns-ovh.sslip.io=2001:41d0:602:2313::1 \
  -mx nip.io=10,mail.protonmail.ch \
  -mx nip.io=20,mailsec.protonmail.ch \
  -mx sslip.io=10,mail.protonmail.ch \
  -mx sslip.io=20,mailsec.protonmail.ch \
  -txt nip.io=protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313 \
  -txt nip.io="v=spf1 include:_spf.protonmail.ch mx -all" \
  -txt sslip.io=protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26 \
  -txt sslip.io="v=spf1 include:_spf.protonmail.ch mx -all" \
  -txt _dmarc.nip.io="v=DMARC1; p=reject" \
  -txt _dmarc.sslip.io="v=DMARC1; p=reject" \
  -cname protonmail._domainkey.nip.io=protonmail.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch. \
  -cname protonmail._domainkey.sslip.io=protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch. \

```

Test from another window:

```bash
DNS_SERVER_IP=127.0.0.1
VERSION=6.1.0
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
 # no records
dig +short txt 127.0.0.1.sslip.io @$DNS_SERVER_IP -p $PORT
dig +short cname sslip.io @$DNS_SERVER_IP -p $PORT
( dig +short cname protonmail._domainkey.nip.io @$DNS_SERVER_IP -p $PORT
echo protonmail.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch. ) | uniq -c
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
( dig +short 7f000001.nip.io @$DNS_SERVER_IP -p $PORT
echo 127.0.0.1 ) | uniq -c
( dig +short blocked.nip.io @$DNS_SERVER_IP -p $PORT
echo 64.176.22.9 ) | uniq -c
( dig +short AAAA blocked.nip.io @$DNS_SERVER_IP -p $PORT
echo 2001:19f0:c800:2315:: ) | uniq -c
dig +short txt metrics.status.sslip.io @$DNS_SERVER_IP -p $PORT | grep '"Queries: '
echo '"Queries: 19 (?.?/s)"'
```

Review the output then close the second window. Stop the server in the
original window. Commit our changes:

```bash
GIT_MESSAGE="$VERSION: Remove hard-coded DNS records"
git add -p
git ci -vm"$GIT_MESSAGE"
git tag $VERSION
git push
git push --tags
for HOST in ns-00 ns-01 ns-ovh blocked; do
  ssh $HOST sudo dnf upgrade -y
done
scp bin/sslip.io-dns-server-linux-amd64 ns-00:
scp bin/sslip.io-dns-server-linux-amd64 ns-01:
scp bin/sslip.io-dns-server-linux-amd64 ns-ovh:
ssh ns-00 sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-00 sudo shutdown -r now
 # check version number; wait until it is back up before rebooting ns-01
sleep 10; while ! dig txt @ns-00.nip.io version.status.sslip.io +short; do sleep 5; done
ssh ns-01 sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-01 sudo shutdown -r now
 # check version number; wait until it is back up before rebooting ns-ovh
sleep 10; while ! dig txt @ns-01.nip.io version.status.sslip.io +short; do sleep 5; done
ssh ns-ovh sudo install sslip.io-dns-server-linux-amd64 /usr/bin/sslip.io-dns-server
ssh ns-ovh sudo shutdown -r now
 # check version number; wait until it is back up before rebooting blocked
sleep 10; while ! dig txt @ns-ovh.sslip.io version.status.sslip.io +short; do sleep 5; done
 # reboot blocked in case it has a new kernel
ssh blocked sudo shutdown -r now
sleep 10; while ! curl -sfI blocked.nip.io >/dev/null; do sleep 5; done
```

- Browse to <https://github.com/cunnie/sslip.io/releases/new> to draft a new release
- Drag and drop the executables in `bin/` to the _Attach binaries..._ section.
- Click "Publish release"

Trigger a new workflow to publish the Docker image: <https://github.com/cunnie/sslip.io/actions/workflows/docker-sslip.io-dns-server.yml>

Update the webservers' HTML with new versions:

```bash
ssh nono.io
cd /www/sslip.io/
git pull -r
BLOCKED_HOST=blocked
ssh $BLOCKED_HOST sudo curl -L -o /var/www/sslip.io/index.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_nip.io/index.html
ssh $BLOCKED_HOST sudo curl -L -o /var/www/sslip.io/experimental.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_nip.io/experimental.html
ssh $BLOCKED_HOST sudo curl -L -o /var/www/blocked/index.html https://raw.githubusercontent.com/cunnie/sslip.io/main/k8s/document_root_nip.io/blocked.html
```

Browse to <https://github.com/cunnie/sslip.io/actions/workflows/nameservers.yml>, trigger the workflow, and check that everything is green.
