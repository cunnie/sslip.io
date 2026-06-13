data "hcloud_ssh_key" "cunnie" {
  name = "cunnie@nono.io"
}

resource "hcloud_floating_ip" "nameserver_ipv4" {
  type          = "ipv4"
  home_location = "hil"
  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_floating_ip" "nameserver_ipv6" {
  type          = "ipv6"
  home_location = "hil"
  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_server" "nameserver" {
  name        = "ns-01"
  server_type = "cpx31"
  image       = "fedora-44"
  location    = "hil"
  ssh_keys    = [data.hcloud_ssh_key.cunnie.id]
  user_data = templatefile("${path.module}/cloud-init.yaml", {
    ipv4_address = hcloud_floating_ip.nameserver_ipv4.ip_address
    ipv6_address = split("/", hcloud_floating_ip.nameserver_ipv6.ip_address)[0]
  })
}

resource "hcloud_floating_ip_assignment" "nameserver_ipv4" {
  floating_ip_id = hcloud_floating_ip.nameserver_ipv4.id
  server_id      = hcloud_server.nameserver.id
}

resource "hcloud_floating_ip_assignment" "nameserver_ipv6" {
  floating_ip_id = hcloud_floating_ip.nameserver_ipv6.id
  server_id      = hcloud_server.nameserver.id
}

resource "hcloud_firewall" "nameserver" {
  name = "ns-01-firewall"

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["73.231.94.127/32", "2601:645:8103:e3a0::/60", "99.123.0.161/32", "2600:1700:486:a840::/60"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "53"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "53"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_firewall_attachment" "nameserver" {
  firewall_id = hcloud_firewall.nameserver.id
  server_ids  = [hcloud_server.nameserver.id]
}
