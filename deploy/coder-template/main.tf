terraform {
  required_providers {
    coder = {
      source = "coder/coder"
    }
    google = {
      source = "hashicorp/google"
    }
  }
}

provider "coder" {}

provider "google" {
  zone    = var.zone
  project = var.project
}

data "coder_provisioner" "me" {}
data "coder_workspace" "me" {}
data "coder_workspace_owner" "me" {}
data "coder_external_auth" "github" {
  id = var.github_app_id
}

locals {
  username  = "coder"
  repo_name = "vigil"
}

# ── Coder agent ───────────────────────────────────────────────────────────────

resource "coder_agent" "main" {
  auth = "google-instance-identity"
  arch = "amd64"
  os   = "linux"

  display_apps {
    vscode = false
  }

  startup_script = <<-EOT
    #!/bin/bash
    set -e

    # Seed home directory from image on first boot
    if [ ! -f "/home/${local.username}/.home_seeded" ]; then
      echo "Seeding home directory from image..."
      cp -a /opt/home-seed/. "/home/${local.username}/"
      touch "/home/${local.username}/.home_seeded"
    fi

    # Clone or update the vigil repo (for profiles and demo scripts)
    cd "/home/${local.username}"
    if [ -d "${local.repo_name}/.git" ]; then
      echo "Updating ${local.repo_name}..."
      cd ${local.repo_name}
      git pull --ff-only || echo "Warning: git pull failed, continuing"
    else
      echo "Cloning ${local.repo_name}..."
      git clone ${var.vigil_repo} ${local.repo_name}
      cd ${local.repo_name}
      git checkout ${var.vigil_branch}
    fi

    # Install vigil from pre-built GitHub release
    echo "Installing vigil from latest release..."
    sudo bash install.sh

    # Overlay repo profiles (may be newer than release)
    sudo mkdir -p /usr/lib/vigil
    sudo cp -r profiles /usr/lib/vigil/profiles
    echo "vigil installed"

    # Configure shell to always start in repo
    if ! grep -q "auto-cd vigil" "/home/${local.username}/.bashrc" 2>/dev/null; then
      cat >> "/home/${local.username}/.bashrc" <<'BASHRC'

# auto-cd vigil
cd ~/vigil 2>/dev/null || true
echo ""
echo "  vigil demo workspace — run: sudo ./demo/run_demo.sh"
echo ""
BASHRC
    fi

    echo "Startup complete"
  EOT

  env = {
    GIT_AUTHOR_NAME     = coalesce(data.coder_workspace_owner.me.full_name, data.coder_workspace_owner.me.name)
    GIT_AUTHOR_EMAIL    = data.coder_workspace_owner.me.email
    GIT_COMMITTER_NAME  = coalesce(data.coder_workspace_owner.me.full_name, data.coder_workspace_owner.me.name)
    GIT_COMMITTER_EMAIL = data.coder_workspace_owner.me.email
  }

  metadata {
    display_name = "CPU Usage"
    key          = "0_cpu_usage"
    script       = "coder stat cpu"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "RAM Usage"
    key          = "1_ram_usage"
    script       = "coder stat mem"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "LSM stack"
    key          = "2_lsm"
    script       = "cat /sys/kernel/security/lsm 2>/dev/null || echo unknown"
    interval     = 60
    timeout      = 2
  }
}

module "github-upload-public-key" {
  count            = data.coder_workspace.me.start_count
  source           = "registry.coder.com/coder/github-upload-public-key/coder"
  version          = "1.0.15"
  agent_id         = coder_agent.main.id
  external_auth_id = data.coder_external_auth.github.id
}

module "vscode-web" {
  count          = tobool(var.codeserver) ? data.coder_workspace.me.start_count : 0
  source         = "registry.coder.com/coder/vscode-web/coder"
  version        = "1.3.0"
  agent_id       = coder_agent.main.id
  extensions     = ["ms-vscode.cpptools", "golang.go"]
  install_prefix = "/tmp/.vscode-web"
  folder         = "/home/${local.username}/${local.repo_name}"
  accept_license = true
  subdomain      = false
  order          = 1
}

# ── Persistent data disk ──────────────────────────────────────────────────────

resource "google_compute_disk" "pd" {
  project = var.project
  name    = "coder-${data.coder_workspace.me.id}-data"
  type    = "pd-ssd"
  zone    = var.zone
  size    = var.disk_size_gb
}

# ── GCP VM — Ubuntu 22.04 with Docker ────────────────────────────────────────
# We use a plain Ubuntu VM (not Container-Optimized OS) because vigil's BPF LSM
# hooks require lsm=bpf in the kernel boot parameters, which COS does not support.
# Docker is installed by the startup script; the workspace runs as a privileged
# container so it can load eBPF programs into the host kernel.

resource "google_compute_instance" "dev" {
  zone         = var.zone
  count        = data.coder_workspace.me.start_count
  name         = "coder-${lower(data.coder_workspace_owner.me.name)}-${lower(data.coder_workspace.me.name)}"
  machine_type = var.machine_type

  network_interface {
    network = "default"
    access_config {}
  }

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 30
      type  = "pd-ssd"
    }
  }

  attached_disk {
    source      = google_compute_disk.pd.self_link
    device_name = "data-disk-0"
    mode        = "READ_WRITE"
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  metadata = {
    "startup-script" = <<-STARTUP
      #!/bin/bash
      set -euo pipefail
      exec >> /var/log/vigil-startup.log 2>&1

      SETUP_DONE=/var/lib/vigil-system-ready

      if [ ! -f "$SETUP_DONE" ]; then
        echo "[startup] first boot: installing system dependencies..."

        # Format and mount persistent data disk
        DISK=/dev/disk/by-id/google-data-disk-0
        if ! blkid "$DISK" &>/dev/null; then
          mkfs.ext4 -F "$DISK"
        fi
        mkdir -p /home/coder
        mount "$DISK" /home/coder

        # Install Docker
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
          | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
          https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
          > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io

        # Authenticate Docker with GAR and pull workspace image
        gcloud auth configure-docker ${var.gar_region}-docker.pkg.dev --quiet
        docker pull ${var.container_image}

        # Configure lsm=bpf if not already active
        if ! grep -q "lsm=bpf" /proc/cmdline; then
          echo "[startup] configuring lsm=bpf..."
          if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
            sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=bpf"/' /etc/default/grub
          else
            echo 'GRUB_CMDLINE_LINUX="lsm=bpf"' >> /etc/default/grub
          fi
          update-grub
          touch "$SETUP_DONE"
          echo "[startup] rebooting to activate lsm=bpf..."
          reboot
          exit 0
        fi

        touch "$SETUP_DONE"
      fi

      # Re-mount data disk on subsequent boots
      if ! mountpoint -q /home/coder; then
        mount /dev/disk/by-id/google-data-disk-0 /home/coder
      fi

      echo "[startup] lsm: $(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
      echo "[startup] starting Coder agent container..."

      # Write init script to a file to avoid shell quoting issues with inline -c embedding
      cat > /tmp/coder-init.sh << 'CODER_INIT_EOF'
      ${coder_agent.main.init_script}
      CODER_INIT_EOF
      chmod +x /tmp/coder-init.sh

      docker run --rm \
        --privileged \
        --network host \
        --name coder-workspace \
        -v /home/coder:/home/coder \
        -v /sys:/sys:ro \
        -v /tmp/coder-init.sh:/tmp/coder-init.sh:ro \
        ${var.container_image} \
        sh -c "chown -R coder:coder /home/coder && su - coder -s /bin/bash /tmp/coder-init.sh"
    STARTUP
  }

  allow_stopping_for_update = true

  labels = {
    coder_workspace_id = data.coder_workspace.me.id
  }
}

resource "coder_agent_instance" "dev" {
  count       = data.coder_workspace.me.start_count
  agent_id    = coder_agent.main.id
  instance_id = google_compute_instance.dev[0].instance_id
}

resource "coder_metadata" "workspace_info" {
  count       = data.coder_workspace.me.start_count
  resource_id = google_compute_instance.dev[0].id

  item {
    key   = "image"
    value = var.container_image
  }

  item {
    key   = "note"
    value = "First start reboots once to activate lsm=bpf"
  }
}
