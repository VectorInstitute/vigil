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
