package profiles_test

import (
	"net"
	"testing"

	"github.com/VectorInstitute/vigil/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadOllama(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := profiles.LoadFile("../../profiles/ollama.yaml")
	require.NoError(t, err)
	return p
}

// ── Profile loading ─────────────────────────────────────────────────────────

func TestLoad_ValidFile(t *testing.T) {
	p := loadOllama(t)
	assert.Equal(t, "ollama", p.Name)
	assert.NotEmpty(t, p.DeniedPaths)
	assert.NotEmpty(t, p.AllowedPaths)
	assert.NotEmpty(t, p.AllowedNetworks)
	assert.NotEmpty(t, p.AllowedCommands)
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := profiles.LoadFile("nonexistent.yaml")
	assert.Error(t, err)
}

func TestLoad_InvalidCIDR(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
name: bad
allowed_networks:
  - not-a-cidr
`))
	assert.Error(t, err)
}

// ── File path matching ───────────────────────────────────────────────────────

func TestMatchPath_DeniedExact(t *testing.T) {
	p := loadOllama(t)
	cases := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
	}
	for _, path := range cases {
		assert.Equal(t, profiles.VerdictDeny, p.MatchPath(path), "expected DENY for %s", path)
	}
}

func TestMatchPath_DeniedGlob(t *testing.T) {
	p := loadOllama(t)
	cases := []string{
		"/root/.ssh/id_rsa",
		"/home/alice/.ssh/authorized_keys",
		"/home/bob/.ssh/id_ed25519",
		"/etc/sudoers.d/nopasswd",
		"/proc/1234/mem",
	}
	for _, path := range cases {
		assert.Equal(t, profiles.VerdictDeny, p.MatchPath(path), "expected DENY for %s", path)
	}
}

func TestMatchPath_AllowedOllamaModel(t *testing.T) {
	p := loadOllama(t)
	cases := []string{
		"/home/alice/.ollama/models/sha256-abc123",
		"/root/.ollama/models/llama3/config.json",
		"/tmp/ollama_blobs",
	}
	for _, path := range cases {
		assert.Equal(t, profiles.VerdictAllow, p.MatchPath(path), "expected ALLOW for %s", path)
	}
}

func TestMatchPath_DefaultDeny_UnknownPath(t *testing.T) {
	p := loadOllama(t)
	// A path not in any rule should fall back to default policy (deny)
	v := p.MatchPath("/opt/someapp/data/file.bin")
	assert.Equal(t, profiles.VerdictDefault, v)
	assert.True(t, p.DefaultDeny())
}

// ── Network matching ─────────────────────────────────────────────────────────

func TestMatchIP_LocahostAllowed(t *testing.T) {
	p := loadOllama(t)
	cases := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("127.0.0.2"),
		net.ParseIP("::1"),
	}
	for _, ip := range cases {
		assert.Equal(t, profiles.VerdictAllow, p.MatchIP(ip), "expected ALLOW for %s", ip)
	}
}

func TestMatchIP_ExternalDenied(t *testing.T) {
	p := loadOllama(t)
	cases := []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("192.168.1.100"),
		net.ParseIP("10.0.0.1"),
	}
	for _, ip := range cases {
		assert.Equal(t, profiles.VerdictDefault, p.MatchIP(ip), "expected DEFAULT(→deny) for %s", ip)
	}
}

// ── Command matching ─────────────────────────────────────────────────────────

func TestMatchCommand_AllowedRunners(t *testing.T) {
	p := loadOllama(t)
	cases := []string{"ollama", "llama-runner", "ollama-runner"}
	for _, cmd := range cases {
		assert.Equal(t, profiles.VerdictAllow, p.MatchCommand(cmd), "expected ALLOW for %s", cmd)
	}
}

func TestMatchCommand_FullPathStrippedToBasename(t *testing.T) {
	p := loadOllama(t)
	assert.Equal(t, profiles.VerdictAllow, p.MatchCommand("/usr/local/bin/ollama"))
}

func TestMatchCommand_ShellDenied(t *testing.T) {
	p := loadOllama(t)
	cases := []string{"bash", "sh", "python3", "curl", "wget", "nc"}
	for _, cmd := range cases {
		assert.Equal(t, profiles.VerdictDefault, p.MatchCommand(cmd), "expected DEFAULT(→deny) for %s", cmd)
	}
}
