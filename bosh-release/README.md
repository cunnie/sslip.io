## BOSH Release

This is a BOSH Release of the Golang-based custom sslip.io DNS server. It's not meant to be used by anyone other than myself.

In the BOSH manifest, use this in the `releases:` section:
```yaml
- name: sslip.io
  sha1: 4247d6f491339ba5e1010625aa3e3ced1e8281e3
  url: https://github.com/cunnie/sslip.io/releases/download/1.0.0/sslip.io-release-1.0.0.tgz
  version: 1.0.0
```
And, in the `instance_groups:` section:
```yaml
  jobs:
  - name: sslip.io-dns-server
    release: sslip.io
```
Here's a sample BOSH [manifest](https://github.com/cunnie/deployments/blob/42e985ceda1f619f32d421e5dbd7df78507fb1d3/sslip.io-dns-server.yml).

After deploying, test the server. Let's assume the deployed VM's IP is 10.0.250.23:
```
dig +short 127.0.0.1.sslip.io @10.0.250.23
127.0.0.1
```
