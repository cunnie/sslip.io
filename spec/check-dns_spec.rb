# Admittedly it's overkill to use rspec to run a set of assertions
# against a DNS server -- a simple shell script would have been
# shorter and more understandable. We are using rspec merely to
# practice using rspec.
def get_whois_nameservers(domain)
  whois_output = `whois #{domain}`
  soa = nil
  whois_lines = whois_output.split(/\n+/)
  nameserver_lines = whois_lines.select { |line| line =~ /^NS/ }
  nameservers = nameserver_lines.map { |line| line.split.last }
  # whois records don't have trail '.'; NS records do; add trailing '.'
  nameservers.map { |ns| ns << '.' }
  nameservers
end

domain = ENV['DOMAIN'] || 'example.com'
whois_nameservers = get_whois_nameservers(domain)

describe domain do
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
    it "nameserver #{whois_nameserver}'s NS records match whois's #{whois_nameservers}" do
      dig_nameservers = `dig +short ns sslip.io @#{whois_nameserver}`.split(/\n+/)
      expect(dig_nameservers.sort).to eq(whois_nameservers.sort)
    end

    it "nameserver #{whois_nameserver}'s SOA record match" do
      dig_soa = `dig +short soa sslip.io @#{whois_nameserver}`
      soa = soa || dig_soa
      expect(dig_soa).to eq(soa)
    end

    a = [ rand(256), rand(256), rand(256), rand(256) ]
    it "resolves #{a.join(".")}.sslip.io to #{a.join(".")}" do
      expect(`dig +short #{a.join(".") + "." + domain} @#{whois_nameserver}`.chomp).to  eq(a.join("."))
    end

    a = [ rand(256), rand(256), rand(256), rand(256) ]
    it "resolves #{a.join("-")}.sslip.io to #{a.join(".")}" do
      expect(`dig +short #{a.join("-") + "." + domain} @#{whois_nameserver}`.chomp).to  eq(a.join("."))
    end
  end
end
