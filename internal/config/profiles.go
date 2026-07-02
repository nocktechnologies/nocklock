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
	"aider":       "default-deny aider draft: project filesystem root, OpenAI/Anthropic/npm/PyPI/GitHub egress, own provider keys only, required Linux fences",
	"claude-code": "default-deny Claude Code draft: project filesystem root, Claude/npm/PyPI/GitHub egress, secret-token blocks, required Linux fences",
	"codex":       "default-deny Codex draft: project filesystem root, OpenAI/npm/PyPI/GitHub egress, secret-token blocks, required Linux fences",
	"gemini-cli":  "default-deny Gemini CLI API-key draft: project filesystem root, Gemini API/npm/GitHub egress, Gemini key only, required Linux fences",
	"opencode":    "default-deny OpenCode Zen draft: project filesystem root, OpenCode/npm/GitHub egress, OpenCode key only, required Linux fences",
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
	data, err := ProfileTOML(name)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	md, err := toml.Decode(data, &cfg)
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

// ProfileTOML returns the embedded TOML for a runtime profile after confirming
// the profile name is known.
func ProfileTOML(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("profile name is required")
	}
	if _, ok := profileSummaries[name]; !ok {
		return "", fmt.Errorf("unknown profile %q", name)
	}

	data, err := profileFS.ReadFile("presets/" + name + ".toml")
	if err != nil {
		return "", fmt.Errorf("embedded profile %q is unavailable: %w", name, err)
	}
	return string(data), nil
}
