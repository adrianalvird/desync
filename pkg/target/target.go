// pkg/target/target.go

package target

import (
	"fmt"
	"net/url"
	"strings"

	"desync/pkg/config"
)

// Role indicates how a URL is used in detection.
type Role int

const (
	RoleBaseline Role = iota
	RoleVictim
)

// URLTarget is a fully parsed target with its role.
type URLTarget struct {
	URL    *url.URL
	Status string
	Role   Role
}

// HostGroup contains all targets for one host (host:port).
type HostGroup struct {
	Host     string
	Targets  []*URLTarget
	Baseline *URLTarget // could be nil if none set, but we ensure fallback
}

// DefaultBaselineTags are status values that identify good baseline URLs.
var DefaultBaselineTags = map[string]bool{
	"root":   true,
	"200":    true,
	"static": true,
}

// GroupByHost creates HostGroups and assigns roles using given baseline tags.
// If baselineTags is nil, uses DefaultBaselineTags.
func GroupByHost(entries []config.TargetEntry, baselineTags map[string]bool) ([]HostGroup, error) {
	if baselineTags == nil {
		baselineTags = DefaultBaselineTags
	}
	groups := make(map[string]*HostGroup)

	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if err != nil {
			continue
		}
		host := u.Host
		if u.Port() == "" {
			switch u.Scheme {
			case "https":
				host += ":443"
			case "http":
				host += ":80"
			}
		}
		if _, exists := groups[host]; !exists {
			groups[host] = &HostGroup{Host: host}
		}
		ut := &URLTarget{
			URL:    u,
			Status: e.Status,
			Role:   RoleVictim, // default victim
		}
		// Assign baseline role if tag matches and none set yet for this host.
		if baselineTags[e.Status] && groups[host].Baseline == nil {
			ut.Role = RoleBaseline
			groups[host].Baseline = ut
		}
		groups[host].Targets = append(groups[host].Targets, ut)
	}

	var result []HostGroup
	for _, g := range groups {
		if g.Baseline == nil {
			// Fallback: pick first entry with a baseline tag, else first entry overall.
			for _, t := range g.Targets {
				if baselineTags[t.Status] {
					t.Role = RoleBaseline
					g.Baseline = t
					break
				}
			}
			if g.Baseline == nil && len(g.Targets) > 0 {
				g.Targets[0].Role = RoleBaseline
				g.Baseline = g.Targets[0]
			}
		}
		if g.Baseline == nil {
			return nil, fmt.Errorf("no URL for host %s", g.Host)
		}
		result = append(result, *g)
	}
	return result, nil
}

// VictimURLs returns all URLs with victim role (excluding baseline).
func (hg *HostGroup) VictimURLs() []*URLTarget {
	var victims []*URLTarget
	for _, t := range hg.Targets {
		if t.Role == RoleVictim {
			victims = append(victims, t)
		}
	}
	return victims
}

// String representation for debugging.
func (hg *HostGroup) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Host: %s\n", hg.Host))
	if hg.Baseline != nil {
		sb.WriteString(fmt.Sprintf("  Baseline: %s (%s)\n", hg.Baseline.URL.String(), hg.Baseline.Status))
	}
	for _, t := range hg.Targets {
		if t.Role == RoleVictim {
			sb.WriteString(fmt.Sprintf("  Victim: %s (%s)\n", t.URL.String(), t.Status))
		}
	}
	return sb.String()
}