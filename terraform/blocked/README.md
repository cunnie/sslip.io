# blocked

To redeploy:

```
tofu taint vultr_instance.blocked
tofu apply
```

After deploying, if the webserver isn't up, you'll need to do the following:

```bash
sudo cp /dev/null /etc/motd
sudo certbot certonly --standalone --non-interactive --agree-tos --email brian.cunnie@gmail.com -d blocked.nip.io -d 64.176.22.9.nip.io -d 64-176-22-9.nip.io
sudo systemctl restart nginx
sudo usermod -aG nginx $USER
```

`terraform.tfstate` is not checked in because it has the root password and the
unauthenticated URL to access the KVM.