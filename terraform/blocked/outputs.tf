output "reserved_ipv4" {
  description = "Reserved IPv4 address for blocked.nip.io"
  value       = vultr_reserved_ip.blocked_ipv4.subnet
}

output "reserved_ipv6" {
  description = "Reserved IPv6 address for blocked.nip.io"
  value       = vultr_reserved_ip.blocked_ipv6.subnet
}

output "instance_id" {
  description = "Instance ID"
  value       = vultr_instance.blocked.id
}
