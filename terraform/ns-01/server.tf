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

resource "hcloud_rdns" "nameserver_ipv4" {
  floating_ip_id = hcloud_floating_ip.nameserver_ipv4.id
  ip_address     = hcloud_floating_ip.nameserver_ipv4.ip_address
  dns_ptr        = "ns-01.nip.io"
}

resource "hcloud_rdns" "nameserver_ipv6" {
  floating_ip_id = hcloud_floating_ip.nameserver_ipv6.id
  # the floating IPv6 is a /64; set the PTR of the address the nameserver listens on
  ip_address = split("/", hcloud_floating_ip.nameserver_ipv6.ip_address)[0]
  dns_ptr    = "ns-01.nip.io"
}
