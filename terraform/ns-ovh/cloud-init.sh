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

[Service]
ExecStart=/usr/bin/sslip.io-dns-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/sslip.io-dns.service

curl -L -o /usr/bin/sslip.io-dns-server \
  https://github.com/cunnie/sslip.io/releases/download/5.1.4/sslip.io-dns-server-linux-amd64
chmod +x /usr/bin/sslip.io-dns-server

systemctl daemon-reload
systemctl enable sslip.io-dns.service
systemctl disable systemd-binfmt.service

reboot
