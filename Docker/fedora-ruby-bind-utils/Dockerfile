# cunnie/fedora-ruby-bind-utils
FROM fedora

LABEL org.opencontainers.image.authors="Brian Cunnie <brian.cunnie@gmail.com>"

# need ruby to run dns-check.rb & bind-utils for dig & nslookup
RUN dnf update -y; \
  dnf install -y bind-utils iproute iputils net-tools ruby rubygems tcpdump which whois; \
  gem install rspec
