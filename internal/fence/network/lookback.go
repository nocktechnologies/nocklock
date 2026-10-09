package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// lookbackMaxDenialRows bounds the signed denial rows written per rule, so a
// flood of requests cannot grow the audit log without limit. It mirrors
// DefaultMaxDenialEvents in internal/fence/fs/denylog.go.
const lookbackMaxDenialRows = 500

// Trigger markers cited in a denial row when no committed trigger row id is
// available to cite.
const (
	triggerUncommitted = "uncommitted"
	triggerUnreadable  = "unreadable"
)

// evaluateLookback reports whether any rule denies egress given the newest
// trigger row (nil when there is none). It returns the first tripped rule in
// config order. A trigger dated in the future counts as inside the window, so a
// skewed clock cannot expire a rule early on that side.
func evaluateLookback(rules []config.LookbackRule, trigger *logging.Event, now time.Time) (deny bool, ruleName string, triggerID int64) {
	if trigger == nil {
		return false, "", 0
	}
	age := now.Sub(trigger.Timestamp)
	for _, r := range rules {
		if w := r.WithinDuration(); w == 0 || age < 0 || age <= w {
			return true, r.Name, trigger.ID
		}
	}
	return false, "", 0
}

// lookbackGuard holds the state behind the proxy's look-back rules. mu is held
// across evaluate-and-register on the request path and across
// commit-and-close-all in LookbackTrip, so a request is either registered
// before the commit begins, and close-all closes it, or evaluated after the
// commit, and the query denies it.
type lookbackGuard struct {
	rules []config.LookbackRule
	query func() (*logging.Event, error)

	mu sync.Mutex
	// stickyTrigger is the denial label once a trip leaves the history unable
	// to vouch for the trigger; empty until then.
	stickyTrigger string
	live          map[*lookbackConn]struct{}

	capMu sync.Mutex
	rows  map[string]int

	unreadableOnce sync.Once
}

// pauseLookback is a test seam: nil in production.
func (p *ProxyServer) pauseLookback(stage string) {
	if p.lookbackPause != nil {
		p.lookbackPause(stage)
	}
}

// lookbackConn is one registered in-flight request or tunnel.
type lookbackConn struct {
	desc  string // "method=CONNECT host=h"
	close func()
}

// lookbackDenial says why a request was refused: the rule and the trigger
// row id (or a triggerUncommitted / triggerUnreadable marker).
type lookbackDenial struct {
	rule    string
	trigger string
}

// EnableLookback turns on the configured look-back rules. It must be called
// before the proxy starts serving. With no rules it does nothing, so a proxy
// without rules pays no cost and never touches the history.
func (p *ProxyServer) EnableLookback(rules []config.LookbackRule) {
	if len(rules) == 0 {
		return
	}
	p.lookback = &lookbackGuard{
		rules: rules,
		live:  map[*lookbackConn]struct{}{},
		rows:  map[string]int{},
		query: func() (*logging.Event, error) {
			if p.logger == nil {
				return nil, fmt.Errorf("no event logger attached")
			}
			return p.logger.LatestBlockedEvent(p.sessionID, logging.EventFileBlocked)
		},
	}
}

// admitLookback evaluates the rules and, when the request may proceed,
// registers closeFn so a later trip can close it. The returned release must be
// deferred for the life of the tunnel or request. Callers log a denial with
// logLookbackBlocked after this returns, since the mutex must be released
// first.
func (p *ProxyServer) admitLookback(desc string, closeFn func()) (release func(), denial *lookbackDenial) {
	g := p.lookback
	g.mu.Lock()
	defer g.mu.Unlock()

	if d := g.evaluateLocked(); d != nil {
		return nil, d
	}
	p.pauseLookback("after-evaluate")
	c := &lookbackConn{desc: desc, close: closeFn}
	g.live[c] = struct{}{}
	return func() {
		g.mu.Lock()
		delete(g.live, c)
		g.mu.Unlock()
	}, nil
}

func (g *lookbackGuard) evaluateLocked() *lookbackDenial {
	if g.stickyTrigger != "" {
		return &lookbackDenial{rule: g.rules[0].Name, trigger: g.stickyTrigger}
	}
	trigger, err := g.query()
	if err != nil {
		g.unreadableOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "NockLock: look-back rules cannot read the event history (%v); denying egress while it is unreadable\n", err)
		})
		return &lookbackDenial{rule: g.rules[0].Name, trigger: triggerUnreadable}
	}
	if deny, rule, id := evaluateLookback(g.rules, trigger, time.Now()); deny {
		return &lookbackDenial{rule: rule, trigger: strconv.FormatInt(id, 10)}
	}
	return nil
}

// closeAllLocked closes every registered connection and returns what it
// closed. The caller holds g.mu.
func (g *lookbackGuard) closeAllLocked() []string {
	closed := make([]string, 0, len(g.live))
	for c := range g.live {
		c.close()
		closed = append(closed, c.desc)
		delete(g.live, c)
	}
	return closed
}

// LookbackTrip records a trigger and cuts off what is already open. commit
// writes the trigger row and runs under the same mutex as request
// evaluation, so a request cannot slip between the commit and the close.
// Callers acknowledge the report only after LookbackTrip returns. If commit
// fails, close-all still runs and egress stays denied for the session. It does
// nothing when no rules are configured.
func (p *ProxyServer) LookbackTrip(commit func() error) {
	g := p.lookback
	if g == nil {
		return
	}
	g.mu.Lock()
	trigger := triggerUncommitted
	if err := commit(); err != nil {
		g.stickyTrigger = triggerUncommitted
		fmt.Fprintf(os.Stderr, "NockLock: look-back trigger could not be committed (%v); denying egress for the rest of the session\n", err)
	} else if ev, qerr := g.query(); qerr != nil {
		trigger = triggerUnreadable
	} else if ev == nil {
		// A committed trigger that reads back empty would otherwise allow the
		// next request, so deny for the rest of the session.
		trigger = triggerUnreadable
		g.stickyTrigger = triggerUnreadable
		fmt.Fprintln(os.Stderr, "NockLock: look-back trigger was committed but reads back empty; denying egress for the rest of the session")
	} else {
		trigger = strconv.FormatInt(ev.ID, 10)
	}
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	closed := g.closeAllLocked()
	g.mu.Unlock()

	for _, desc := range closed {
		p.recordLookbackBlock(desc, g.rules[0].Name, trigger)
	}
}

// lookbackDesc names a request in denial rows.
func lookbackDesc(method, host string) string {
	return "method=" + method + " host=" + host
}

// logLookbackBlocked records a denied request.
func (p *ProxyServer) logLookbackBlocked(method, host string, d *lookbackDenial) {
	p.recordLookbackBlock(lookbackDesc(method, host), d.rule, d.trigger)
}

// recordLookbackBlock writes a signed network_blocked row whose Detail names
// the rule and the trigger row, under a per-rule cap: the first
// lookbackMaxDenialRows rows, then one summary row.
func (p *ProxyServer) recordLookbackBlock(desc, rule, trigger string) {
	if p.logger == nil {
		return
	}
	g := p.lookback
	g.capMu.Lock()
	n := g.rows[rule]
	g.rows[rule] = n + 1
	g.capMu.Unlock()

	detail := fmt.Sprintf("%s rule=lookback:%s trigger=%s", desc, rule, trigger)
	switch {
	case n < lookbackMaxDenialRows:
	case n == lookbackMaxDenialRows:
		detail = fmt.Sprintf("rule=lookback:%s trigger=%s summary=denial row cap of %d reached; further denials for this rule are not logged individually", rule, trigger, lookbackMaxDenialRows)
	default:
		return
	}
	_ = p.logger.LogImmediate(logging.Event{
		Timestamp: time.Now(),
		EventType: logging.EventNetworkBlocked,
		Category:  "network",
		Detail:    detail,
		Blocked:   true,
		SessionID: p.sessionID,
	})
}

// clientConnKey carries the accepted client connection into the request
// context so a trip can close it.
type clientConnKey struct{}

func withClientConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, clientConnKey{}, c)
}

const lookbackDeniedResponse = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
