## BOSH Release

This is a BOSH Release of the Golang-based custom sslip.io DNS server. It's not meant to be used by anyone other than myself.

In the BOSH manifest, use this in the `releases:` section:
```yaml
- name: sslip.io
  sha1: 0f23bff9d1136d3d5e3b033d013759fe3aa85613
  url: https://github.com/cunnie/sslip.io/releases/download/1.1.1/sslip.io-release-1.1.1.tgz
  version: 1.1.1
```
And, in the `instance_groups:` section:
```yaml
  jobs:
  - name: sslip.io-dns-server
    release: sslip.io
```
Here's a sample BOSH [manifest](https://github.com/cunnie/deployments/blob/ee993025de99cb245b0042c32b672633c4316fcf/sslip.io-dns-server.yml).

After deploying, test the server. Let's assume the deployed VM's IP is 10.0.250.23:
```
dig +short 127.0.0.1.sslip.io @10.0.250.23
127.0.0.1
```
