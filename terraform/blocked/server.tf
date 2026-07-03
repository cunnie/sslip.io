data "vultr_ssh_key" "nono" {
  filter {
    name   = "name"
    values = ["nono"]
  }
}

data "vultr_os" "fedora44" {
  filter {
    name   = "name"
    values = ["Fedora 44 x64"]
  }
}

resource "vultr_reserved_ip" "blocked_ipv4" {
  region  = "scl"
  ip_type = "v4"
  label   = "blocked-ipv4"
  lifecycle {
    prevent_destroy = true
  }
}

resource "vultr_reserved_ip" "blocked_ipv6" {
  region      = "scl"
  ip_type     = "v6"
  label       = "blocked-ipv6"
  instance_id = vultr_instance.blocked.id
  lifecycle {
    prevent_destroy = true
  }
}

resource "vultr_firewall_group" "blocked" {
  description = "blocked.nip.io firewall group"
}

resource "vultr_firewall_rule" "icmp_v4" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "icmp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
}

resource "vultr_firewall_rule" "icmp_v6" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "icmp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
}

resource "vultr_firewall_rule" "ssh_v4_home" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "73.231.94.127"
  subnet_size       = 32
  port              = "22"
}

resource "vultr_firewall_rule" "ssh_v6_home" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "2601:645:8103:e3a0::"
  subnet_size       = 60
  port              = "22"
}

resource "vultr_firewall_rule" "ssh_v4_work" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "99.123.0.161"
  subnet_size       = 32
  port              = "22"
}

resource "vultr_firewall_rule" "ssh_v6_work" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "2600:1700:486:a840::"
  subnet_size       = 60
  port              = "22"
}

resource "vultr_firewall_rule" "dns_tcp_v4" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "53"
}

resource "vultr_firewall_rule" "dns_tcp_v6" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "53"
}

resource "vultr_firewall_rule" "udp_v4" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "udp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "1:65535"
}

resource "vultr_firewall_rule" "udp_v6" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "udp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "1:65535"
}

resource "vultr_firewall_rule" "http_v4" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "80"
}

resource "vultr_firewall_rule" "http_v6" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "80"
}

resource "vultr_firewall_rule" "https_v4" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
}

resource "vultr_firewall_rule" "https_v6" {
  firewall_group_id = vultr_firewall_group.blocked.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = "443"
}

resource "vultr_instance" "blocked" {
  hostname          = "blocked.nip.io"
  label             = "blocked"
  region            = "scl"
  plan              = "vc2-1c-2gb"
  os_id             = data.vultr_os.fedora44.id
  enable_ipv6       = true
  firewall_group_id = vultr_firewall_group.blocked.id
  ssh_key_ids       = [data.vultr_ssh_key.nono.id]
  reserved_ip_id    = vultr_reserved_ip.blocked_ipv4.id
  user_data = templatefile("${path.module}/cloud-init.yaml", {
    ipv6_address = var.blocked_ipv6_subnet
    ipv6_prefix  = var.blocked_ipv6_prefix
  })
  lifecycle {
    ignore_changes = [user_data]
  }
}
