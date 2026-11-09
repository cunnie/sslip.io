# cunnie/fedora-golang

# To build

# docker buildx build --pull --platform=linux/amd64,linux/arm64 -t cunnie/fedora-golang . # OR
# docker build -t cunnie/fedora-golang .
# container build -t cunnie/fedora-golang .
# docker push cunnie/fedora-golang

FROM fedora:45

LABEL org.opencontainers.image.authors="Brian Cunnie <brian.cunnie@gmail.com>"

# need bind-utils for dig & nslookup
RUN dnf update -y; \
  dnf install -y @development-tools; \
  dnf install -y \
  autojump-zsh \
  bind-utils \
  fd-find \
  gcc-g++ \
  golang \
  htop \
  iproute \
  iputils \
  jq \
  neovim \
  net-tools \
  nmap-ncat \
  python \
  redhat-rpm-config \
  ripgrep \
  socat \
  strace \
  tcpdump \
  tmux \
  wget \
  zsh \
  zsh-autosuggestions \
  zsh-syntax-highlighting \
  ;

RUN CGO_ENABLED=0 GOBIN=/usr/local/bin go install github.com/onsi/ginkgo/v2/ginkgo@latest

RUN echo 'export EDITOR=nvim' >> ~/.zshrc; \
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc

RUN echo '[ -s /etc/profile.d/autojump.sh ] && . /etc/profile.d/autojump.sh' >> ~/.zshrc; \
  echo 'alias z=j' >> ~/.zshrc; \
  echo '[ -s /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ] && . /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh' >> ~/.zshrc; \
  echo '[ -s /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && . /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh' >> ~/.zshrc

CMD [ "/usr/bin/zsh" ]
