output "floating_ipv4" {
  description = "Floating IPv4 address for nameserver"
  value       = hcloud_floating_ip.nameserver_ipv4.ip_address
}

output "floating_ipv6" {
  description = "Floating IPv6 address for nameserver"
  value       = hcloud_floating_ip.nameserver_ipv6.ip_address
}

output "server_id" {
  description = "Server ID"
  value       = hcloud_server.nameserver.id
}
