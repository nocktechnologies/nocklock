package cli

import (
	"context"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
)

func projectDotEnvDoctorCheck(cfg *config.Config) doctorCheck {
	check := doctorCheck{Group: "Secrets", Name: "project-dotenv", Severity: doctorInfo, Status: "not-configured", Message: "No filesystem root is configured for .env inspection."}
	if cfg.Filesystem.Root == "" {
		return check
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	root, err := fsfence.ExpandTilde(cfg.Filesystem.Root)
	report := secrets.ScanReport{Complete: false}
	if err == nil {
		report = secrets.ScanDotEnv(ctx, root)
	}
	check.Status = "clear"
	check.Message = "No secret-shaped values found in .env and .env.* files at filesystem.root and one directory level below, excluding dependency/build directories. Deeper files were not checked; project .env files remain readable."
	if len(report.Findings) > 0 {
		check.Severity, check.Status = doctorWarning, "readable-secret"
		check.Message = "Project .env files contain secret-shaped values and remain readable by the wrapped agent. Values are not reported."
		check.Fix = "remove credentials from the project root or replace them with scoped development credentials"
	} else if !report.Complete {
		check.Status = "not-checked"
		check.Message = "Project .env check: not checked (inspection could not finish within the bounded root-and-one-level scope). Project .env files remain readable; this is not a full-project secret scan."
		check.Fix = "inspect project .env files separately; resolve scan size, permissions, symlink, or concurrent-change limits to retry the shallow check"
	}
	return check
}
