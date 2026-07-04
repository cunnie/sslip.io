# blocked

To redeploy:

```
tofu taint vultr_instance.blocked
tofu apply
```

After deploying, if the webserver isn't up, you'll need to do the following:

```bash
sudo certbot certonly --standalone --non-interactive --agree-tos --email cunnie@majestic-labs.ai -d blocked.nip.io -d 64.176.22.9.nip.io -d 64-176-22-9.nip.io
sudo systemctl restart nginx
```

`terraform.tfstate` is not checked in because it has the root password and the
unauthenticated URL to access the KVM.