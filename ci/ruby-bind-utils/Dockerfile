FROM fedora

MAINTAINER Brian Cunnie <brian.cunnie@gmail.com>

# need ruby to run dns-check.rb & bind-utils for dig & nslookup
RUN dnf update -y; \
  dnf install -y bind-utils ruby rubygems which whois; \
  gem install rspec
