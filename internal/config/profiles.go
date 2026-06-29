package config

import (
	"embed"
	"fmt"
	"sort"

	"github.com/BurntSushi/toml"
)

//go:embed presets/*.toml
var profileFS embed.FS

// Profile describes an embedded runtime preset.
type Profile struct {
	Name    string
	Summary string
}

var profileSummaries = map[string]string{
	"claude-code": "default-deny Claude Code draft: project filesystem root, Claude/npm/PyPI/GitHub egress, secret-token blocks, required Linux fences",
	"codex":       "default-deny Codex draft: project filesystem root, OpenAI/npm/PyPI/GitHub egress, secret-token blocks, required Linux fences",
}

// Profiles returns the embedded runtime profiles in stable name order.
func Profiles() []Profile {
	names := make([]string, 0, len(profileSummaries))
	for name := range profileSummaries {
		names = append(names, name)
	}
	sort.Strings(names)

	profiles := make([]Profile, 0, len(names))
	for _, name := range names {
		profiles = append(profiles, Profile{Name: name, Summary: profileSummaries[name]})
	}
	return profiles
}

// LoadProfile loads an embedded runtime profile by name.
func LoadProfile(name string) (*Config, error) {
	if name == "" {
		return nil, fmt.Errorf("profile name is required")
	}
	if _, ok := profileSummaries[name]; !ok {
		return nil, fmt.Errorf("unknown profile %q", name)
	}

	data, err := profileFS.ReadFile("presets/" + name + ".toml")
	if err != nil {
		return nil, fmt.Errorf("embedded profile %q is unavailable: %w", name, err)
	}

	cfg := DefaultConfig()
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("embedded profile %q is invalid: %w", name, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("embedded profile %q has unknown config keys: %v", name, undecoded)
	}
	if errs := Validate(&cfg); len(errs) > 0 {
		for _, e := range errs {
			if e.Severity == "error" {
				return nil, fmt.Errorf("embedded profile %q is invalid: %s", name, e.Error())
			}
		}
	}
	cfg.ProfileName = name
	return &cfg, nil
}
