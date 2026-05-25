# "The image for this droplet does not use root passwords, please use an SSH key."
resource "digitalocean_ssh_key" "cunnie" {
  name       = "cunnie-ed25519"
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKoPHfGEM2RMBpcW2ZzKUmTNbweJbzfz6Y/EZ+WXJDVz"
}

resource "digitalocean_reserved_ip" "nameserver_ip" {
  region = "sgp1"
  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_reserved_ipv6" "nameserver_ipv6" {
  region_slug = "sgp1"
  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_droplet" "nameserver" {
  name       = "ns-do-sg.sslip.io"
  region     = "sgp1"
  size       = "s-2vcpu-4gb"
  image      = "fedora-43-x64"
  monitoring = true
  ipv6       = true
  ssh_keys   = [digitalocean_ssh_key.cunnie.fingerprint]
  user_data  = file("${path.module}/cloud-init.yaml")

  # Ensure reserved IP is created before droplet
  depends_on = [digitalocean_reserved_ip.nameserver_ip]
}

resource "digitalocean_reserved_ip_assignment" "nameserver_assign" {
  ip_address = digitalocean_reserved_ip.nameserver_ip.ip_address
  droplet_id = digitalocean_droplet.nameserver.id
}

resource "digitalocean_reserved_ipv6_assignment" "nameserver_ipv6_assign" {
  ip = digitalocean_reserved_ipv6.nameserver_ipv6.ip
  droplet_id = digitalocean_droplet.nameserver.id
}

resource "digitalocean_firewall" "nameserver" {
  name = "ns-do-sg-firewall"

  droplet_ids = [digitalocean_droplet.nameserver.id]

  # Inbound ICMP (IPv4 and IPv6)
  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Inbound SSH (TCP 22)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["73.189.219.4/32", "99.123.0.161/32", "::/0"] # Me, Sha, all of IPv6
  }

  # Inbound DNS (TCP 53)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "53"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Inbound DNS (UDP 53)
  inbound_rule {
    protocol         = "udp"
    port_range       = "53"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Inbound HTTP (TCP 80)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Inbound HTTPS (TCP 443)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow all outbound traffic
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
