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
ExecStart=/usr/bin/sslip.io-dns-server \
  -ns=.=ns-00.nip.io. \
  -ns=.=ns-01.nip.io. \
  -ns=.=ns-ovh.sslip.io. \
  -a=nip.io=78.46.204.247 \
  -aaaa=nip.io=2a01:4f8:c17:b8f::2 \
  -a=sslip.io=78.46.204.247 \
  -aaaa=sslip.io=2a01:4f8:c17:b8f::2 \
  -a=ns.nip.io=167.172.4.236 \
  -a=ns.nip.io=5.78.28.211 \
  -a=ns.nip.io=51.75.53.19 \
  -aaaa=ns.nip.io=2400:6180:0:d2:0:2:e3e7:0 \
  -aaaa=ns.nip.io=2a01:4ff:1f2:10d:: \
  -aaaa=ns.nip.io=2001:41d0:602:2313::1 \
  -a=ns.sslip.io=167.172.4.236 \
  -a=ns.sslip.io=5.78.28.211 \
  -a=ns.sslip.io=51.75.53.19 \
  -aaaa=ns.sslip.io=2400:6180:0:d2:0:2:e3e7:0 \
  -aaaa=ns.sslip.io=2a01:4ff:1f2:10d:: \
  -aaaa=ns.sslip.io=2001:41d0:602:2313::1 \
  -a=blocked.nip.io=64.176.22.9 \
  -aaaa=blocked.nip.io=2001:19f0:c800:2315:: \
  -a=ns-00.nip.io=167.172.4.236 \
  -aaaa=ns-00.nip.io=2400:6180:0:d2:0:2:e3e7:0 \
  -a=ns-01.nip.io=5.78.28.211 \
  -aaaa=ns-01.nip.io=2a01:4ff:1f2:10d:: \
  -a=ns-ovh.sslip.io=51.75.53.19 \
  -aaaa=ns-ovh.sslip.io=2001:41d0:602:2313::1 \
  -mx=nip.io=10,mail.protonmail.ch. \
  -mx=nip.io=20,mailsec.protonmail.ch. \
  -mx=sslip.io=10,mail.protonmail.ch. \
  -mx=sslip.io=20,mailsec.protonmail.ch. \
  "-txt=nip.io=protonmail-verification=19b0837cc4d9daa1f49980071da231b00e90b313" \
  "-txt=nip.io=v=spf1 include:_spf.protonmail.ch mx -all" \
  "-txt=sslip.io=protonmail-verification=ce0ca3f5010aa7a2cf8bcc693778338ffde73e26" \
  "-txt=sslip.io=v=spf1 include:_spf.protonmail.ch mx -all" \
  "-txt=_dmarc.nip.io=v=DMARC1; p=reject" \
  "-txt=_dmarc.sslip.io=v=DMARC1; p=reject" \
  -cname=protonmail._domainkey.nip.io=protonmail.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch. \
  -cname=protonmail2._domainkey.nip.io=protonmail2.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch. \
  -cname=protonmail3._domainkey.nip.io=protonmail3.domainkey.di5fzneyjbxuzcqcrbw2f63m34itvf6lmjde2s4maty3hdt6664dq.domains.proton.ch. \
  -cname=protonmail._domainkey.sslip.io=protonmail.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch. \
  -cname=protonmail2._domainkey.sslip.io=protonmail2.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch. \
  -cname=protonmail3._domainkey.sslip.io=protonmail3.domainkey.dw4gykv5i2brtkjglrf34wf6kbxpa5hgtmg2xqopinhgxn5axo73a.domains.proton.ch.
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/sslip.io-dns.service

curl -L -o /usr/bin/sslip.io-dns-server \
  https://github.com/cunnie/sslip.io/releases/download/6.1.0/sslip.io-dns-server-linux-amd64
chmod +x /usr/bin/sslip.io-dns-server

systemctl daemon-reload
systemctl enable sslip.io-dns.service
rm -fr ~fedora
userdel fedora

reboot
