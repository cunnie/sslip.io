# Admittedly it's overkill to use rspec to run a set of assertions
# against a DNS server -- a simple shell script would have been
# shorter and more understandable. We are using rspec merely to
# practice using rspec.
def get_whois_nameservers(domain)
  whois_output = `whois #{domain}`
  whois_lines = whois_output.split(/\n+/)
  nameserver_lines = whois_lines.select { |line| line =~ /^NS/ }
  nameservers = nameserver_lines.map { |line| line.split.last }
  nameservers
end

describe 'xip.io-style domain' do
  domain = ENV['DOMAIN'] || 'example.com'
  whois_nameservers = get_whois_nameservers(domain)


  context "when evaluating $DOMAIN (\"#{domain}\") environment variable" do
    let (:domain) { ENV['DOMAIN'] }
    it 'is set' do
      expect(domain).not_to be_nil
    end
    it 'is not an empty string' do
      expect(domain).not_to eq('')
    end
  end

  whois_nameservers.each do |whois_nameserver|
    context "Nameserver #{whois_nameserver}" do
    end
  end
end
