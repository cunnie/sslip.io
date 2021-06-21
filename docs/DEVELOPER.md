## Updating BOSH Releases

These instructions are meant primarily for me when deploying a new BOSH release;
they might not make sense unless you're on my workstation.

```zsh
export OLD_VERSION=2.1.2
export VERSION=2.2.0
cd ~/go/src/github.com/cunnie/sslip.io
git pull -r --autostash
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" k8s/document_root/index.html # update the download instructions on the website
cd bosh-release/
lpass show a # refresh LastPass token
. ~/workspace/deployments/.envrc # set BOSH auth
export BOSH_DEPLOYMENT=sslip.io-dns-server
bosh create-release --force
bosh upload-release
bosh -n -d sslip.io-dns-server deploy ~/workspace/deployments/sslip.io-dns-server.yml --recreate
bosh instances # record the IP address of the instance
IP=10.0.250.22
dig +short 127.0.0.1.example.com @$IP
echo 127.0.0.1
dig +short ns example.com @$IP
printf "ns-aws.nono.io.\nns-azure.nono.io.\nns-gce.nono.io.\n"
dig +short mx example.com @$IP
echo "0 example.com."
dig +short mx sslip.io @$IP
printf "10 mail.protonmail.ch.\n20 mailsec.protonmail.ch.\n"
dig +short txt sslip.io @$IP
printf "\"protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26\"\n\"v=spf1 include:_spf.protonmail.ch mx ~all\"\n"
dig +short txt 127.0.0.1.sslip.io @$IP # no records
dig +short cname sslip.io @$IP # no records
dig +short cname protonmail._domainkey.sslip.io @$IP
echo protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.
dig a _Acme-ChallengE.127-0-0-1.sslip.io @$IP | grep "^127"
echo "127-0-0-1.sslip.io.	604800	IN	A	127.0.0.1"
dig +short sSlIp.Io
echo 78.46.204.247
dig @ns-aws.nono.io txt . +short | tr -d '"'
curl curlmyip.org; echo
git add -p
git ci -vm"BOSH release: 2.2.0: TXT records return IP addrs"
bosh upload-blobs
bosh create-release \
  --final \
  --tarball ~/Downloads/sslip.io-release-${VERSION}.tgz \
  --version ${VERSION}
git add -N releases/ .final_builds/
git add -p
git ci --amend
git tag $VERSION
git push
git push --tags
cd ..
bin/make_all
```
- Browse to <https://github.com/cunnie/sslip.io/releases/new> to draft a new release
- Drag and drop `~/Downloads/sslip.io-release-${VERSION}.tgz` to the _Attach
  binaries..._ section
- Drag and drop the executables in `bin/` to the _Attach binaries..._ section.

Prepare the BOSH release
```
shasum ~/Downloads/sslip.io-release-${VERSION}.tgz
z deployments
nvim sslip.io.yml
bosh -e vsphere -d sslip.io deploy sslip.io.yml -l <(lpass show --note deployments.yml) --no-redact
dig 127-0-0-1.sslip.io +short  # output should be 127.0.0.1
dig @ns-aws.nono.io ns _ACMe-chALLengE.127-0-0-1.ssLIP.iO +short # 127-0-0-1.ssLIP.iO.
git add -p
git ci -v -m"Bump sslip.io: $OLD_VERSION → $VERSION"
git push
popd
```
Update the webserver with the HTML with new versions:
```
ssh nono.io
curl -L -o /www/sslip.io/document_root/index.html https://raw.githubusercontent.com/cunnie/sslip.io/master/k8s/document_root/index.html
exit
```
Update the Dockefile with the new release:
```
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" k8s/Dockerfile-sslip.io-dns-server
docker build k8s/ -f k8s/Dockerfile-sslip.io-dns-server -t cunnie/sslip.io-dns-server:$VERSION -t cunnie/sslip.io-dns-server:latest
docker push cunnie/sslip.io-dns-server -a
git add -p
git ci -m"Dockerfile: cunnie/sslip.io-dns-server → $VERSION"
git push
```
