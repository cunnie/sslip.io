resource "ovh_ip_firewall" "nameserver" {
  ip             = "51.75.53.19/32"
  ip_on_firewall = "51.75.53.19"
  enabled        = true
}

resource "ovh_ip_firewall_rule" "icmp" {
  ip             = ovh_ip_firewall.nameserver.ip
  ip_on_firewall = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence       = 0
  action         = "permit"
  protocol       = "icmp"
}

resource "ovh_ip_firewall_rule" "ssh_cunnie" {
  ip               = ovh_ip_firewall.nameserver.ip
  ip_on_firewall   = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence         = 1
  action           = "permit"
  protocol         = "tcp"
  source           = "73.231.94.127/32"
  destination_port = 22
}

resource "ovh_ip_firewall_rule" "ssh_sha" {
  ip               = ovh_ip_firewall.nameserver.ip
  ip_on_firewall   = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence         = 2
  action           = "permit"
  protocol         = "tcp"
  source           = "99.123.0.161/32"
  destination_port = 22
}

resource "ovh_ip_firewall_rule" "dns_tcp" {
  ip               = ovh_ip_firewall.nameserver.ip
  ip_on_firewall   = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence         = 3
  action           = "permit"
  protocol         = "tcp"
  destination_port = 53
}

resource "ovh_ip_firewall_rule" "all_udp" {
  ip             = ovh_ip_firewall.nameserver.ip
  ip_on_firewall = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence       = 4
  action         = "permit"
  protocol       = "udp"
}

resource "ovh_ip_firewall_rule" "http" {
  ip               = ovh_ip_firewall.nameserver.ip
  ip_on_firewall   = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence         = 5
  action           = "permit"
  protocol         = "tcp"
  destination_port = 80
}

resource "ovh_ip_firewall_rule" "https" {
  ip               = ovh_ip_firewall.nameserver.ip
  ip_on_firewall   = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence         = 6
  action           = "permit"
  protocol         = "tcp"
  destination_port = 443
}

resource "ovh_ip_firewall_rule" "established" {
  ip             = ovh_ip_firewall.nameserver.ip
  ip_on_firewall = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence       = 7
  action         = "permit"
  protocol       = "tcp"
  tcp_option     = "established"
}

resource "ovh_ip_firewall_rule" "deny_all" {
  ip             = ovh_ip_firewall.nameserver.ip
  ip_on_firewall = ovh_ip_firewall.nameserver.ip_on_firewall
  sequence       = 19
  action         = "deny"
  protocol       = "ipv4"
}
