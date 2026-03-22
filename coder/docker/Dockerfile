FROM ubuntu:22.04

ARG GO_VERSION=1.22.5

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/usr/local/go/bin:/usr/local/bin:$PATH

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y -qq \
      build-essential git curl ca-certificates gnupg \
      clang llvm \
      linux-tools-common linux-tools-generic \
      linux-headers-generic \
      sudo jq vim tmux zsh unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Neovim (stable) ───────────────────────────────────────────────────────────
RUN curl -fsSL https://github.com/neovim/neovim/releases/download/stable/nvim-linux-x86_64.tar.gz \
    -o /tmp/nvim.tar.gz && \
    tar xzf /tmp/nvim.tar.gz -C /opt/ && \
    ln -sf /opt/nvim-linux-x86_64/bin/nvim /usr/local/bin/nvim && \
    rm /tmp/nvim.tar.gz

# ── Go ────────────────────────────────────────────────────────────────────────
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz

# ── Node.js 20 ────────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y -qq nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Claude Code CLI ───────────────────────────────────────────────────────────
RUN npm install -g @anthropic-ai/claude-code

# ── Gemini CLI ────────────────────────────────────────────────────────────────
RUN npm install -g @google/gemini-cli

# ── Workspace user ────────────────────────────────────────────────────────────
ARG USER=coder
RUN useradd --groups sudo --shell /bin/zsh ${USER} \
    && echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER} \
    && chmod 0440 /etc/sudoers.d/${USER}

RUN mkdir -p /home/${USER} && chown -R ${USER}:${USER} /home/${USER}

# ── Dotfiles (oh-my-zsh, p10k, neovim config, etc.) ──────────────────────────
RUN git clone https://github.com/amrit110/dotfiles /tmp/dotfiles && \
    git -C /tmp/dotfiles checkout coder && \
    sed -i 's/POWERLEVEL9K_MODE=.*/POWERLEVEL9K_MODE=ascii/' /tmp/dotfiles/.p10k.zsh && \
    cd /tmp/dotfiles && \
    HOME=/home/${USER} DEBIAN_FRONTEND=noninteractive bash setup.sh || \
    echo "Warning: setup.sh had non-fatal errors, continuing build"

# Safety-net: copy p10k config if setup.sh exited before doing so
RUN cp -n /tmp/dotfiles/.p10k.zsh /home/${USER}/.p10k.zsh 2>/dev/null || true

# Fix ownership, then snapshot to /opt/home-seed for fast runtime seeding
RUN chown -R ${USER}:${USER} /home/${USER} && \
    mkdir -p /opt/home-seed && cp -a /home/${USER}/. /opt/home-seed/

WORKDIR /home/${USER}
# Run as root so the container entrypoint can chown the mounted home volume,
# then su to ${USER} — same pattern as eval-agents template.
