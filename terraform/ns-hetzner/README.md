# Hetzner Hillsboro Nameserver

## Initial Setup

```bash
export TF_VAR_hcloud_token=YOUR_TOKEN_HERE

tofu init
tofu apply -auto-approve
```

Terraform won't delete the Floating IPs

```bash
tofu destroy
```
