#!/bin/bash
set -eux

hostnamectl set-hostname ns-ovh.sslip.io

dnf -y update

dnf -y install \
  '@development-tools' \
  bind-utils \
  btop \
  bzip2 \
  curl \
  file \
  git-lfs \
  golang \
  htop \
  iputils \
  jq \
  neovim \
  net-tools \
  netcat \
  python3 \
  python3-devel \
  python3-pip \
  python3-virtualenv \
  ripgrep \
  rsync \
  socat \
  sudo \
  tar \
  tcpdump \
  tmux \
  tree \
  unzip \
  zstd

useradd -m -s /bin/bash -G wheel -c 'Brian Cunnie' cunnie
echo 'cunnie ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/cunnie
install -d -m 700 -o cunnie -g cunnie /home/cunnie/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKoPHfGEM2RMBpcW2ZzKUmTNbweJbzfz6Y/EZ+WXJDVz' \
  > /home/cunnie/.ssh/authorized_keys
chmod 600 /home/cunnie/.ssh/authorized_keys
chown cunnie:cunnie /home/cunnie/.ssh/authorized_keys

cat > /etc/systemd/system/sslip.io-dns.service <<'EOF'
[Unit]
Description=sslip.io DNS server
Documentation=https://sslip.io/
After=network-online.target
Requires=network-online.target

[Service]
ExecStart=/usr/bin/sslip.io-dns-server -nameservers=ns-00.nip.io.,ns-01.nip.io.,ns-ovh.sslip.io. -addresses=nip.io=78.46.204.247,sslip.io=78.46.204.247,nip.io=2a01:4f8:c17:b8f::2,sslip.io=2a01:4f8:c17:b8f::2,ns.nip.io=167.172.4.236,ns.nip.io=2400:6180:0:d2:0:2:e3e7:0,ns.nip.io=5.78.28.211,ns.nip.io=2a01:4ff:1f2:10d::,ns.nip.io=51.75.53.19,ns.nip.io=2001:41d0:602:2313::1,ns.sslip.io=167.172.4.236,ns.sslip.io=2400:6180:0:d2:0:2:e3e7:0,ns.sslip.io=5.78.28.211,ns.sslip.io=2a01:4ff:1f2:10d::,ns.sslip.io=51.75.53.19,ns.sslip.io=2001:41d0:602:2313::1,blocked.nip.io=64.176.22.9,blocked.nip.io=2001:19f0:c800:2315::,ns-00.nip.io=167.172.4.236,ns-00.nip.io=2400:6180:0:d2:0:2:e3e7:0,ns-01.nip.io=5.78.28.211,ns-01.nip.io=2a01:4ff:1f2:10d::,ns-ovh.sslip.io=51.75.53.19,ns-ovh.sslip.io=2001:41d0:602:2313::1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/sslip.io-dns.service

curl -L -o /usr/bin/sslip.io-dns-server \
  https://github.com/cunnie/sslip.io/releases/download/5.1.5/sslip.io-dns-server-linux-amd64
chmod +x /usr/bin/sslip.io-dns-server

systemctl daemon-reload
systemctl enable sslip.io-dns.service
rm -fr ~fedora
userdel fedora

reboot
