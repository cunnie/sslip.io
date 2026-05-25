output "reserved_ipv4" {
  description = "Reserved IPv4 address for nameserver"
  value       = digitalocean_reserved_ip.nameserver_ip.ip_address
}

output "reserved_ipv6" {
  description = "Reserved IPv6 address for nameserver"
  value       = digitalocean_reserved_ipv6.nameserver_ipv6.ip
}

output "droplet_id" {
  description = "Droplet ID"
  value       = digitalocean_droplet.nameserver.id
}
