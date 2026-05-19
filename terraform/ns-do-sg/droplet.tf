resource "digitalocean_droplet" "nameserver" {
  name       = "ns-do-sg.sslip.io"
  region     = "sgp1"
  size       = "s-2vcpu-4gb"
  image      = "fedora-43-x64"
  monitoring = true
  ipv6       = true
  vpc_uuid   = "6d136c2d-bfff-428b-bfa0-30e2927948f0"
}

resource "digitalocean_reserved_ip" "nameserver_ip" {
  region = "sgp1"
}

resource "digitalocean_reserved_ip_assignment" "nameserver_assign" {
  ip_address = digitalocean_reserved_ip.nameserver_ip.ip_address
  droplet_id = digitalocean_droplet.nameserver.id
}
