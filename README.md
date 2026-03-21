<div align="center">
  <img src="assets/logo.svg" width="345" alt="vigil logo"/>
</div>

# vigil

eBPF-based runtime security for AI inference workloads.

Vigil attaches to AI serving processes (Ollama, vLLM, llama.cpp) and enforces a behavioral profile at the kernel level, blocking unexpected file access, network connections, and subprocess spawning before they complete. No code changes required in the target process.

## How it works

```
AI process (Ollama, vLLM, ...)
        │ syscalls
        ▼
Linux Kernel: eBPF LSM hooks (file_open, socket_connect, bprm_check)
        │ ring buffer events
        ▼
vigil daemon: evaluates against profile → ALLOW / BLOCK
        │ JSON
        ▼
Audit log / SIEM
```

- **Kernel layer** (`bpf/`): tracepoints observe syscalls; LSM hooks enforce policy inline
- **Profiles** (`profiles/`): YAML files defining allowed paths, networks, and commands per framework
- **Detector** (`internal/detector`): evaluates kernel events against the loaded profile
- **Audit** (`internal/audit`): one JSON line per decision, stdout or file

## Requirements

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y`
- Boot param: `lsm=bpf` (add to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`)
- `clang`, `llvm`, `bpftool`, `linux-headers`
- Root privileges to load eBPF programs
- Go 1.22+

## Quick start

```bash
# Build eBPF programs and binary
make

# Watch Ollama with the built-in profile
sudo ./vigil watch --framework ollama

# Use a custom profile
sudo ./vigil watch --profile /path/to/custom.yaml

# List available profiles
./vigil profile list
```

## Output

```json
{"ts":"2026-01-01T00:00:00Z","pid":1234,"comm":"ollama","event":"file_open","path":"/etc/passwd","action":"BLOCK","reason":"matches denied path pattern"}
{"ts":"2026-01-01T00:00:01Z","pid":1234,"comm":"ollama","event":"net_connect","dest_ip":"8.8.8.8","dest_port":443,"action":"BLOCK","reason":"default policy: deny, destination network not in allowlist"}
```

## Testing

```bash
# Unit tests (works on macOS and Linux, no eBPF required)
make test-unit

# Integration / e2e test (Linux + root, requires BPF LSM enabled)
make test-integration
```

## Architecture

See [`docs/architecture.html`](docs/architecture.html) for the full diagram.

## Profiles

| Profile | Status |
|---|---|
| `ollama` | Available |
| `claude-code` | Available |
| `gemini-cli` | Available |
| `vllm` | Coming soon |
| `llamacpp` | Coming soon |

## Demo

See [`deploy/`](deploy/) for a Coder workspace template that provisions a Ubuntu VM with vigil, Claude Code, and Gemini CLI, and runs live jailbreak blocking scenarios.
