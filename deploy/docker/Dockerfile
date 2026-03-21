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
      sudo jq vim tmux \
    && rm -rf /var/lib/apt/lists/*

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
RUN useradd --groups sudo --shell /bin/bash ${USER} \
    && echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER} \
    && chmod 0440 /etc/sudoers.d/${USER}

RUN mkdir -p /home/${USER} && chown -R ${USER}:${USER} /home/${USER}

# Snapshot to /opt/home-seed for fast runtime seeding (same pattern as eval-agents)
RUN mkdir -p /opt/home-seed && cp -a /home/${USER}/. /opt/home-seed/

WORKDIR /home/${USER}
# Run as root so the container entrypoint can chown the mounted home volume,
# then su to ${USER} — same pattern as eval-agents template.
