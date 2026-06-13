# DigitalOcean Singapore Nameserver

## Initial Setup

```bash
# Set your DigitalOcean token
export TF_VAR_do_token=dop_v1_8dba0xxxxx

# Initialize and apply
tofu init
tofu apply -auto-approve
```

You'll probably get an "`Error Assigning reserved IPv6`" error when you `tofu apply`; go to the Digital Ocean web console and manually assign the IPv6 to the droplet.

**Deploy takes 20–50 minutes**. You'll have problems ssh'ing in before then. Don't panic; be patient.

**Reboot takes _at least_ 100 seconds**.

After every deploy, check both IPv4 & IPv6 addresses from a different machine:

```bash
dig +short 127.0.0.1.nip.io @167.172.4.236
dig +short 127.0.0.1.nip.io @2400:6180:0:d2:0:2:e3e7:0
```

**Pro-tip**: log in to the console and make sure there's only one droplet and that both reserved IPs are assigned to that one droplet.

The Digital Ocean Terraform is a dumpster fire:

- I've seen as many as three droplets at once; there should only ever be one
- I've had to manually assign & unassign the reserved IPs from the instances; Terraform doesn't always assign/unassign properly
- On the positive side, Terraform won't ever delete the reserved IPs, which is good because they're hard to change (requires code change and registrar change)
- They don't have a Fedora 44 image, only a Fedora 43, so you have to update by hand

```bash
sudo dnf upgrade --refresh
sudo reboot
sudo dnf system-upgrade download --releasever=44
sudo dnf system-upgrade reboot
```

## To Delete

```bash
tofu destroy -target=digitalocean_droplet.nameserver -auto-approve
```
