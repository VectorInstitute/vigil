package detector

import (
	"github.com/VectorInstitute/vigil/internal/events"
	"github.com/VectorInstitute/vigil/internal/profiles"
)

// Action is the enforcement decision for a kernel event.
type Action int

const (
	Allow Action = iota
	Block
	Skip // event is from a non-watched process — discard silently
)

func (a Action) String() string {
	switch a {
	case Allow:
		return "ALLOW"
	case Block:
		return "BLOCK"
	default:
		return "SKIP"
	}
}

// Decision pairs an event with its enforcement action and human-readable reason.
type Decision struct {
	Event  events.Event
	Action Action
	Reason string
}

// Detector evaluates kernel events against a behavioral profile.
type Detector struct {
	profile *profiles.Profile
}

// New returns a Detector backed by the given profile.
func New(p *profiles.Profile) *Detector {
	return &Detector{profile: p}
}

// Evaluate returns the enforcement decision for a single kernel event.
// Returns Skip if the event's process is not in the profile's watched_comms list.
func (d *Detector) Evaluate(e events.Event) Decision {
	if !d.profile.WatchComm(e.Comm) {
		return Decision{Event: e, Action: Skip, Reason: "not a watched process"}
	}
	switch e.Type {
	case events.FileOpen, events.Exec:
		return d.evaluatePath(e)
	case events.NetConnect:
		return d.evaluateNetwork(e)
	case events.SSLData:
		return Decision{Event: e, Action: Allow, Reason: "ssl capture — observation only"}
	default:
		return Decision{Event: e, Action: Allow, Reason: "unknown event type — pass through"}
	}
}

func (d *Detector) evaluatePath(e events.Event) Decision {
	switch d.profile.MatchPath(e.Path) {
	case profiles.VerdictDeny:
		return Decision{Event: e, Action: Block, Reason: "matches denied path pattern"}
	case profiles.VerdictAllow:
		return Decision{Event: e, Action: Allow, Reason: "matches allowed path pattern"}
	default:
		return d.defaultDecision(e, "path matches no rule")
	}
}

func (d *Detector) evaluateNetwork(e events.Event) Decision {
	switch d.profile.MatchIP(e.DestIP) {
	case profiles.VerdictAllow:
		return Decision{Event: e, Action: Allow, Reason: "destination is in allowed network"}
	default:
		return d.defaultDecision(e, "destination network not in allowlist")
	}
}

func (d *Detector) defaultDecision(e events.Event, context string) Decision {
	if d.profile.DefaultDeny() {
		return Decision{Event: e, Action: Block, Reason: "default policy: deny — " + context}
	}
	return Decision{Event: e, Action: Allow, Reason: "default policy: allow — " + context}
}
