<div align="center">
  <img src="assets/logo.svg" width="345" alt="vigil logo"/>
</div>

# vigil

eBPF-based runtime security for AI inference workloads.

Vigil attaches to AI agent processes (Claude Code, Gemini CLI, Ollama) and enforces a behavioral profile at the kernel level, blocking unexpected file access, network connections, and subprocess spawning before they complete. No code changes required in the target process.

## How it works

```
AI process (claude, gemini, ollama, ...)
        │ syscalls
        ▼
Linux Kernel: eBPF LSM hooks (file_open, socket_connect, bprm_check)
        │ ring buffer events
        ▼
vigil daemon: evaluates against profile → ALLOW / BLOCK
        │ JSON + real-time UI
        ▼
Audit log / SIEM
```

- **Kernel layer** (`bpf/`): tracepoints observe syscalls; LSM hooks enforce policy inline
- **Process lineage** (`bpf/probe.c`): tracks agent process trees by PID — follows forks and execs so child processes (`node`, `sh`, `git`) are attributed to the correct agent
- **Profiles** (`profiles/`): YAML files defining allowed paths, networks, and commands per framework
- **Detector** (`internal/detector`): evaluates kernel events against the loaded profile
- **Audit** (`internal/audit`): one JSON line per decision, stdout or file
- **Web UI** (`internal/ui`): real-time event feed with BLOCK/ALLOW badges, served over SSE

## Requirements

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y`
- Boot param: `lsm=bpf` (add to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`)
- `clang`, `llvm`, `bpftool`, `linux-headers`
- Root privileges to load eBPF programs
- Go 1.22+

## Quick start

```bash
# Install from latest release (Linux amd64/arm64)
curl -fsSL https://github.com/VectorInstitute/vigil/releases/latest/download/install.sh | sudo bash

# Watch an AI agent with the built-in profile
sudo vigil watch --framework gemini-cli

# With real-time web UI at http://localhost:7394
sudo vigil watch --framework claude-code --ui

# Use a custom profile
sudo vigil watch --profile /path/to/custom.yaml

# List available profiles
vigil profile list
```

## Output

```json
{"ts":"2026-01-01T00:00:00Z","pid":1234,"comm":"gemini","event":"file_open","path":"/etc/passwd","action":"BLOCK","reason":"matches denied path pattern"}
{"ts":"2026-01-01T00:00:01Z","pid":1234,"comm":"node","event":"net_connect","dest_ip":"1.2.3.4","dest_port":443,"action":"ALLOW","reason":"default policy: allow — destination network not in allowlist"}
```

## Process lineage tracking

AI agents spawn many child processes (`node`, `sh`, `python3`, `git`, ...) that share comm names with unrelated system processes. Without lineage tracking, vigil would either miss agent children or produce noise from VS Code, SSH daemons, and cron jobs with the same comm.

Vigil solves this with BPF process lineage tracking:

1. `entry_comm` in the profile names the agent's root process (e.g. `gemini`)
2. A `sched_process_exec` tracepoint detects when that process starts and adds its PID to `watched_pids`
3. A `sched_process_fork` tracepoint propagates membership to all descendants
4. A `sched_process_exit` tracepoint removes PIDs when processes exit (prevents PID reuse false positives)
5. Observation tracepoints only emit events for PIDs in `watched_pids`

Result: vigil sees exactly the agent's process tree — nothing more.

```yaml
# profiles/gemini-cli.yaml
entry_comm: gemini   # root process to track
```

## Profiles

| Profile | Entry process | Status |
|---|---|---|
| `ollama` | `ollama` | Available |
| `claude-code` | `claude` | Available |
| `gemini-cli` | `gemini` | Available |
| `vllm` | `vllm` | Coming soon |
| `llamacpp` | `server` | Coming soon |

## Testing

```bash
# Unit tests (works on macOS and Linux, no eBPF required)
make test-unit

# Integration / e2e test (Linux + root, requires BPF LSM enabled)
make test-integration
```

## Demo

See [`coder/`](coder/) for a Coder workspace template that provisions a Ubuntu VM with vigil, Claude Code, and Gemini CLI, and runs live jailbreak blocking scenarios.
