#!/usr/bin/env ruby
#
# DOMAIN=sslip.io rspec --format documentation --color spec
#
# Admittedly it's overkill to use rspec to run a set of assertions
# against a DNS server -- a simple shell script would have been
# shorter and more understandable. We are using rspec merely to
# practice using rspec.
def get_whois_nameservers(domain)
  whois_output = `whois #{domain}`
  soa = nil
  whois_lines = whois_output.split(/\n+/)
  nameserver_lines = whois_lines.select { |line| line =~ /^Name Server:/ }
  nameservers = nameserver_lines.map { |line| line.split.last.downcase }.uniq
  # whois records don't have trail '.'; NS records do; add trailing '.'
  nameservers.map { |ns| ns << '.' }
  nameservers
end

domain = ENV['DOMAIN'] || 'example.com'
whois_nameservers = get_whois_nameservers(domain)

describe domain do
  soa = nil

  context "when evaluating $DOMAIN (\"#{domain}\") environment variable" do
    let (:domain) { ENV['DOMAIN'] }
    it 'is set' do
      expect(domain).not_to be_nil
    end
    it 'is not an empty string' do
      expect(domain).not_to eq('')
    end
  end

  it "should have at least 2 nameservers" do
    expect(whois_nameservers.size).to be > 1
  end

  whois_nameservers.each do |whois_nameserver|
    it "nameserver #{whois_nameserver}'s NS records match whois's #{whois_nameservers}, " +
      "`dig +short ns #{domain} @#{whois_nameserver}`" do
      dig_nameservers = `dig +short ns #{domain} @#{whois_nameserver}`.split(/\n+/)
      expect(dig_nameservers.sort).to eq(whois_nameservers.sort)
    end

    it "nameserver #{whois_nameserver}'s SOA record match" do
      dig_soa = `dig +short soa #{domain} @#{whois_nameserver}`
      soa = soa || dig_soa
      expect(dig_soa).to eq(soa)
    end

    it "nameserver #{whois_nameserver}'s has an A record" do
      expect(`dig +short a #{domain} @#{whois_nameserver}`.chomp).not_to eq('')
      expect($?.success?).to be true
    end

    it "nameserver #{whois_nameserver}'s has an AAAA record" do
      expect(`dig +short a #{domain} @#{whois_nameserver}`.chomp).not_to eq('')
      expect($?.success?).to be true
    end

    a = [ rand(256), rand(256), rand(256), rand(256) ]
    it "resolves #{a.join(".")}.#{domain} to #{a.join(".")}" do
      expect(`dig +short #{a.join(".") + "." + domain} @#{whois_nameserver}`.chomp).to  eq(a.join("."))
    end

    a = [ rand(256), rand(256), rand(256), rand(256) ]
    it "resolves #{a.join("-")}.#{domain} to #{a.join(".")}" do
      expect(`dig +short #{a.join("-") + "." + domain} @#{whois_nameserver}`.chomp).to  eq(a.join("."))
    end

    a = [ rand(256), rand(256), rand(256), rand(256) ]
    b = [ ('a'..'z').to_a, ('0'..'9').to_a ].flatten.shuffle[0,8].join
    it "resolves #{b}.#{a.join("-")}.#{domain} to #{a.join(".")}" do
      expect(`dig +short #{b}.#{a.join("-") + "." + domain} @#{whois_nameserver}`.chomp).to  eq(a.join("."))
    end

    a = [ rand(256), rand(256), rand(256), rand(256) ]
    b = [ ('a'..'z').to_a, ('0'..'9').to_a ].flatten.shuffle[0,8].join
    it "resolves #{a.join("-")}.#{b} to #{a.join(".")}" do
      expect(`dig +short #{a.join("-") + "." + b} @#{whois_nameserver}`.chomp).to  eq(a.join("."))
    end

    # don't begin the hostname with a double-dash -- `dig` mistakes it for an argument
    it "resolves api.--.#{domain}' to eq ::)}" do
      expect(`dig +short AAAA api.--.#{domain} @#{whois_nameserver}`.chomp).to eq("::")
    end

    it "resolves localhost.--1.#{domain}' to eq ::1)}" do
      expect(`dig +short AAAA localhost.api.--1.#{domain} @#{whois_nameserver}`.chomp).to eq("::1")
    end

    it "resolves 2001-4860-4860--8888.#{domain}' to eq 2001:4860:4860::8888)}" do
      expect(`dig +short AAAA 2001-4860-4860--8888.#{domain} @#{whois_nameserver}`.chomp).to eq("2001:4860:4860::8888")
    end

    it "resolves 2601-646-100-69f0--24.#{domain}' to eq 2601:646:100:69f0::24)}" do
      expect(`dig +short AAAA 2601-646-100-69f0--24.#{domain} @#{whois_nameserver}`.chomp).to eq("2601:646:100:69f0::24")
    end
  end
  # check the website
  it "is able to reach https://#{domain} and get a valid response (2xx)" do
    `curl -If https://#{domain} 2> /dev/null`
    expect($?.success?).to be true
  end
end
