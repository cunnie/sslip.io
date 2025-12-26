# cunnie/fedora-golang

# To build

# docker buildx build --pull --platform=linux/amd64,linux/arm64 -t cunnie/fedora-golang . # OR
# docker build -t cunnie/fedora-golang .
# docker push cunnie/fedora-golang

FROM fedora

LABEL org.opencontainers.image.authors="Brian Cunnie <brian.cunnie@gmail.com>"

# need ruby to run dns-check.rb & bind-utils for dig & nslookup
RUN dnf update -y; \
  dnf install -y @development-tools; \
  dnf install -y \
  autojump-zsh \
  bind-utils \
  btrfs-progs \
  cmake \
  direnv \
  etcd \
  fd-find \
  gcc-g++ \
  golang \
  htop \
  iproute \
  iputils \
  jq \
  mysql-devel \
  neovim \
  net-tools \
  nmap-ncat \
  npm \
  openssl-devel \
  python \
  redhat-rpm-config \
  ripgrep \
  ruby \
  ruby-devel \
  rubygems \
  socat \
  strace \
  tcpdump \
  tmux \
  wget \
  zlib-devel \
  zsh \
  zsh-syntax-highlighting \
  ;

RUN dnf install -y dnf-plugins-core; \
  dnf-3 config-manager --add-repo https://rpm.releases.hashicorp.com/fedora/hashicorp.repo; \
  dnf -y install vault; \
  setcap -r /usr/bin/vault

RUN CGO_ENABLED=0 GOBIN=/usr/local/bin go install github.com/onsi/ginkgo/v2/ginkgo@latest

RUN  echo "" | SHELL=/usr/bin/zsh /usr/bin/zsh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"; \
  echo 'export EDITOR=nvim' >> ~/.zshrc; \
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc

RUN echo '[ -s /etc/profile.d/autojump.sh ] && . /etc/profile.d/autojump.sh' >> ~/.zshrc; \
  echo 'alias z=j' >> ~/.zshrc

CMD [ "/usr/bin/zsh" ]
