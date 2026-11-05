# blocked

To redeploy:

```bash
export TF_VAR_vultr_api_key=X7UQ2Nxxxx
tofu taint vultr_instance.blocked
tofu apply
```

After deploying:

```bash
scp $PWD/terraform.tfstate nuada:$PWD/terraform.tfstate
ssh-keygen -R blocked
ssh blocked
sudo cp /dev/null /etc/motd
sudo usermod -aG nginx $USER
```

`terraform.tfstate` is not checked in because it has the root password and the
unauthenticated URL to access the KVM.
