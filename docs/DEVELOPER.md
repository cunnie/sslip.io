## Updating BOSH Releases

These instructions are meant primarily for me when deploying a new BOSH release;
they might not make sense unless you're on my workstation.

```bash
export OLD_VERSION=2.2.3
export VERSION=2.2.4
cd ~/workspace/sslip.io
git pull -r --autostash
# update the version number for the TXT record for version.sslip.io
sed -i '' "s/$OLD_VERSION/$VERSION/g" \
  bin/make_all \
  bosh-release/packages/sslip.io-dns-server/packaging \
  spec/check-dns_spec.rb
# update the download instructions on the website
sed -i '' "s~/$OLD_VERSION/~/$VERSION/~g" \
  k8s/document_root/index.html \
  k8s/Dockerfile-sslip.io-dns-server
# update the git hash for the TXT record for version.sslip.io for BOSH release
sed -i '' "s/VersionGitHash=[0-9a-fA-F]*/VersionGitHash=$(git rev-parse --short HEAD)/g" \
  bosh-release/packages/sslip.io-dns-server/packaging
cd bosh-release/
lpass show a # refresh LastPass token
. ~/workspace/deployments/.envrc # set BOSH auth
export BOSH_DEPLOYMENT=sslip.io-dns-server
bosh create-release --force
bosh upload-release
bosh -n -d sslip.io-dns-server deploy ~/workspace/deployments/sslip.io-dns-server.yml --recreate
bosh instances # record the IP address of the instance
IP=10.0.250.3
dig +short 127.0.0.1.example.com @$IP
echo 127.0.0.1
dig +short ns example.com @$IP
printf "ns-aws.sslip.io.\nns-azure.sslip.io.\nns-gce.sslip.io.\n"
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
dig @$IP txt ip.sslip.io +short | tr -d '"'
curl curlmyip.org; echo
dig @$IP txt version.sslip.io +short | grep $VERSION
echo "\"$VERSION\""
pushd ..
git add -p
git ci -vm"BOSH release: $VERSION: Deprecate nono.io nameservers"
popd
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
bosh upload-release
cd ..
bin/make_all
scp bin/sslip.io-dns-server-linux-arm64 ns-aws:
ssh ns-aws sudo install sslip.io-dns-server-linux-arm64 /usr/bin/sslip.io-dns-server
ssh ns-aws sudo shutdown -r now
```
- Browse to <https://github.com/cunnie/sslip.io/releases/new> to draft a new release
- Drag and drop `~/Downloads/sslip.io-release-${VERSION}.tgz` to the _Attach
  binaries..._ section
- Drag and drop the executables in `bin/` to the _Attach binaries..._ section.
```bash
fly -t nono trigger-job -j dockerfiles/build-and-push-sslip.io-dns-server
```
Prepare the BOSH release
```bash
shasum ~/Downloads/sslip.io-release-${VERSION}.tgz
lpass show a # refresh LastPass token so we don't get stuck next step
z deployments
git pull -r
nvim sslip.io.yml
bosh -e vsphere -d sslip.io deploy sslip.io.yml -l <(lpass show --note deployments.yml) --no-redact
dig @ns-azure 127-0-0-1.sslip.io +short  # output should be 127.0.0.1
dig @ns-azure.nono.io txt version.sslip.io +short
git add -p
git ci -v -m"Bump sslip.io BOSH release: $OLD_VERSION → $VERSION"
git push
popd
```
Update the webserver with the HTML with new versions:
```bash
ssh nono.io
curl -L -o /www/sslip.io/document_root/index.html https://raw.githubusercontent.com/cunnie/sslip.io/master/k8s/document_root/index.html
exit
```
Update GCP/GKE with the new executable:
```bash
kubectl rollout restart deployment/sslip.io
kubectl rollout restart deployment/sslip.io-nginx
```
