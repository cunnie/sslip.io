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

num_failures=0 # assume successful exit

check_domain(domain)
puts "[PASS] #{domain} basic check ('DOMAIN' variable set & not empty)"

whois_nameservers = get_whois_nameservers(domain)
#whois_nameservers = [ 'ns-aws.nono.com', 'ns-he.nono.com' ] # testing
puts "[PASS] #{domain} has whois entry with nameservers #{whois_nameservers.join(", ")}"

whois_nameservers.each do |whois_nameserver|
  dig = `dig +short ns sslip.io @#{whois_nameserver}`
	dig_nameservers = dig.split(/\n+/)
  if ( whois_nameservers.sort == dig_nameservers.sort )
    puts "[PASS] #{whois_nameserver}'s NS records match whois"
  else
    puts "[FAIL] #{whois_nameserver}'s NS records do NOT match whois: #{dig_nameservers.join(", ")}"
    num_failures=(( num_failures + 1 ))
  end
  #p "#{whois_nameserver}: #{nameservers}"
end

exit(num_failures)
