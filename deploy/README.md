# vigil — Coder workspace template

Provisions a Ubuntu 22.04 GCP VM that runs the vigil workspace Docker image, with Claude Code and Gemini CLI pre-installed. The Coder agent startup script clones the vigil repo, builds the eBPF programs, and installs profiles on each workspace start.

## Why Ubuntu (not Container-Optimized OS)?

vigil's BPF LSM hooks (`lsm/file_open`, `lsm/bprm_check`, `lsm/socket_connect`) require `lsm=bpf` in the host kernel boot parameters. Container-Optimized OS does not support custom GRUB parameters. A plain Ubuntu 22.04 VM is used instead; the workspace container runs `--privileged` so it can load eBPF programs into the host kernel.

The first workspace start triggers a one-time reboot to activate `lsm=bpf`. Subsequent starts skip the reboot.

## Build and push the workspace image

```bash
# From the repo root
gcloud builds submit \
  --config deploy/docker/cloudbuild.yaml \
  --substitutions _PROJECT=coderd \
  .
```

The image is pushed to `us-central1-docker.pkg.dev/coderd/vigil/workspace:latest`.

## Deploy the Coder template

```bash
cd deploy/coder-template
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set project, container_image, service_account_email
terraform init
coder templates push vigil-demo --directory .
```

## Demo

Once the workspace is running, open a terminal:

```bash
# Run all three jailbreak scenarios under the claude-code profile
sudo ./demo/run_demo.sh --profile claude-code

# Or the gemini-cli profile
sudo ./demo/run_demo.sh --profile gemini-cli
```

Scenarios:
- **Credential theft** — `open(/etc/shadow)`, `~/.ssh/id_rsa`, `~/.aws/credentials` → BLOCK
- **Shell escape** — `execve(/bin/bash)`, `execve(/usr/bin/python3)` → BLOCK
- **Network exfiltration** — TCP to attacker IPs → logged, blocked after `BlockIP`

## Running real agents under vigil

```bash
# Terminal 1: start vigil
sudo vigil watch --profile profiles/claude-code.yaml

# Terminal 2: run Claude Code normally — vigil streams every file/network event
claude
```

## Profiles

| Profile | Description |
|---|---|
| `ollama` | Ollama LLM inference server |
| `claude-code` | Claude Code AI coding agent |
| `gemini-cli` | Gemini CLI AI coding agent |
