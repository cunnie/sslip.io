## Updating BOSH Releases

These instructions are meant primarily for me when deploying a new BOSH release;
the might not make sense unless you're on my workstation.

```
export OLD_VERSION=1.2.0
export VERSION=1.2.1
cd ~/go/src/github.com/cunnie/sslip.io
git pull -r
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
dig +short 127.0.0.1.example.com @$IP  # 127.0.0.1
dig +short ns example.com @$IP         # ns-aws, ns-azure, ns-gce
dig +short mx example.com @$IP         # 1 x themselves
dig +short mx sslip.io @$IP            # 2 x protonmail
dig +short txt sslip.io @$IP           # 2 x protonmail
dig +short txt 127.0.0.1.sslip.io @$IP # no records
bosh upload-blobs
bosh create-release \
  --final \
  --tarball ~/Downloads/sslip.io-release-${VERSION}.tgz \
  --version ${VERSION} --force
git add -N releases/ .final_builds/
git add -p
git ci -v  # BOSH release: 1.2.1: TXT records
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
dig +short 127-0-0-1.sslip.io # output should be 127.0.0.1
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
