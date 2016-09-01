#!/usr/bin/env ruby

domain=ENV['DOMAIN']

def check_domain(domain)
  raise "'DOMAIN' environment variable not set!" if domain.nil?
  raise "'DOMAIN' environment variable is empty string!" if domain == ""
end

def get_whois_nameservers(domain)
  whois_output = `whois #{domain}`
  whois_lines = whois_output.split(/\n+/)
  nameserver_lines = whois_lines.select { |line| line =~ /^NS/ }
  nameservers = nameserver_lines.map { |line| line.split.last }
  raise "#{domain}'s whois entry has no name servers" unless nameservers.length > 0
  nameservers
end

check_domain(domain)
puts "[PASS] #{domain} basic check ('DOMAIN' variable set & not empty)"

whois_nameservers = get_whois_nameservers(domain)
puts "[PASS] #{domain} has whois entry with nameservers"
