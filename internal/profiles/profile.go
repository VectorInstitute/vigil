package profiles

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
)

// Verdict is the result of a profile rule evaluation.
type Verdict int

const (
	VerdictAllow   Verdict = iota // explicitly permitted by a rule
	VerdictDeny                   // explicitly denied by a rule
	VerdictDefault                // no rule matched; caller applies default policy
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictDeny:
		return "DENY"
	default:
		return "DEFAULT"
	}
}

// Profile defines the expected behavioral envelope for an AI inference process.
type Profile struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`

	// DefaultPolicy is applied when no rule matches ("allow" or "deny").
	DefaultPolicy string `yaml:"default_policy"`

	// EntryComm is the kernel comm of the agent's root process (e.g. "gemini",
	// "claude"). When set, vigil uses BPF process lineage tracking: only the
	// entry process and all its descendants emit events. This eliminates false
	// positives from unrelated processes sharing the same comm (e.g. VS Code's
	// "node" vs gemini-cli's "node"). Requires kernel 5.7+.
	EntryComm string `yaml:"entry_comm"`

	// WatchedComms restricts event collection to the listed process names
	// (kernel comm, max 15 chars). Used when entry_comm is not set.
	// If both are empty, all processes are watched.
	WatchedComms []string `yaml:"watched_comms"`

	DeniedPaths     []string `yaml:"denied_paths"`
	AllowedPaths    []string `yaml:"allowed_paths"`
	AllowedNetworks []string `yaml:"allowed_networks"`
	AllowedCommands []string `yaml:"allowed_commands"`

	// compiled
	allowedNets []*net.IPNet
}

// compile parses CIDRs into net.IPNet for fast matching.
func (p *Profile) compile() error {
	p.allowedNets = nil
	for _, cidr := range p.AllowedNetworks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q in profile %q: %w", cidr, p.Name, err)
		}
		p.allowedNets = append(p.allowedNets, ipNet)
	}
	return nil
}

// WatchComm reports whether events from a process named comm should be
// processed by the Go detector.
//
// When EntryComm is set, BPF lineage tracking has already filtered the ring
// buffer to only contain events from the agent's process tree. The Go layer
// must not re-filter by comm name, so WatchComm always returns true.
//
// When EntryComm is empty, WatchedComms applies: if the list is non-empty,
// only listed names pass; an empty list watches all processes.
func (p *Profile) WatchComm(comm string) bool {
	if p.EntryComm != "" {
		return true // BPF lineage tracking active; trust the ring buffer
	}
	if len(p.WatchedComms) == 0 {
		return true
	}
	for _, c := range p.WatchedComms {
		if c == comm {
			return true
		}
	}
	return false
}

// DefaultDeny reports whether the default policy is to deny unmatched actions.
func (p *Profile) DefaultDeny() bool {
	return p.DefaultPolicy != "allow"
}

// MatchPath returns the verdict for a file open at the given path.
// Denied patterns are checked before allowed patterns.
func (p *Profile) MatchPath(path string) Verdict {
	for _, pattern := range p.DeniedPaths {
		if globMatch(pattern, path) {
			return VerdictDeny
		}
	}
	for _, pattern := range p.AllowedPaths {
		if globMatch(pattern, path) {
			return VerdictAllow
		}
	}
	return VerdictDefault
}

// MatchIP returns the verdict for an outbound connection to ip.
func (p *Profile) MatchIP(ip net.IP) Verdict {
	for _, network := range p.allowedNets {
		if network.Contains(ip) {
			return VerdictAllow
		}
	}
	return VerdictDefault
}

// MatchCommand returns the verdict for spawning the process at cmdPath.
// Matching is done on the basename so both "ollama" and "/usr/bin/ollama" work.
func (p *Profile) MatchCommand(cmdPath string) Verdict {
	base := filepath.Base(cmdPath)
	for _, allowed := range p.AllowedCommands {
		if base == allowed {
			return VerdictAllow
		}
	}
	return VerdictDefault
}

// globMatch wraps doublestar.Match with a safe fallback.
func globMatch(pattern, s string) bool {
	matched, err := doublestar.Match(pattern, s)
	if err != nil {
		return false
	}
	return matched
}
