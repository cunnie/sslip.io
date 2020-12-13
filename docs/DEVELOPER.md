## Updating BOSH Releases

```
export OLD_VERSION=1.1.2
export VERSION=1.2.0
cd ~/workspace/sslip.io
git pull -r
lpass show a # refresh LastPass token
. ~/workspace/deployments/.envrc # set BOSH auth
export BOSH_DEPLOYMENT=sslip.io-dns-server
bosh create-release --force
bosh upload-release
bosh -n -d sslip.io-dns-server deploy ~/workspace/deployments/sslip.io-dns-server.yml --recreate
bosh instances # record the IP address of the instance
IP=10.0.250.22
dig +short 127.0.0.1.example.com @$IP # 127.0.0.1
dig +short ns example.com @$IP        # ns-aws, ns-azure, ns-gce
dig +short mx example.com @$IP        # 1 x themselves
dig +short mx sslip.io @$IP           # 2 x protonmail
bosh upload-blobs
bosh create-release \
  --final \
  --tarball ~/Downloads/pdns-release-${VERSION}.tgz \
  --version ${VERSION} --force
git add -N releases/ .final_builds/
git add -p
git ci -v  # BOSH release: 1.2.0: bugfixes
git tag $VERSION
git push
git push --tags
```
