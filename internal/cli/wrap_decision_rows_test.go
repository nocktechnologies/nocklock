package cli

import (
	"strings"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// hasDecisionRow reports whether any network-category event's Detail contains
// all of needles. It is shared by the Linux netns egress-audit acceptance test
// and the macOS proxy-only DNS-escape test, which both assert that a wrapped
// session signed a specific allow/deny decision into .nock/events.db. Kept free
// of a build tag so both platforms compile it.
func hasDecisionRow(rows []logging.Event, needles ...string) bool {
	for _, e := range rows {
		if e.Category != "network" {
			continue
		}
		match := true
		for _, n := range needles {
			if !strings.Contains(e.Detail, n) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// detailList renders the Detail of each event as a bulleted list for failure
// messages, or "(none)" when there are no rows.
func detailList(rows []logging.Event) string {
	var b strings.Builder
	for _, e := range rows {
		b.WriteString("\n  - ")
		b.WriteString(e.Detail)
	}
	if b.Len() == 0 {
		return "(none)"
	}
	return b.String()
}
