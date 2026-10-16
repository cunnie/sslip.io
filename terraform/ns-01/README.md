# Hetzner Hillsboro Nameserver

## Initial Setup

```bash
export TF_VAR_hcloud_token=UoaN29xxxxx
tofu init
tofu apply -auto-approve
```

Terraform won't delete the Floating IPs (lifecycle protection), so rest easy.

The Hetzner firewall seems to drop packets randomly, so I got rid of it. I
should implement a Fedora-native firewall, but not today.
