package server

import (
	"context"
	"sync"
	"time"
)

const (
	// serviceMonitorInterval is how often the monitor polls systemd.
	serviceMonitorInterval = 60 * time.Second
	// serviceDownConfirmChecks is the number of consecutive unhealthy polls
	// before a service is reported down. Two polls (~2 minutes) debounces a
	// routine restart's deactivating/activating window so it doesn't flap.
	serviceDownConfirmChecks = 2
)

// serviceMonitor tracks the health of managed services and emits service.down /
// service.up notifications on transition.
type serviceMonitor struct {
	mu    sync.Mutex
	state map[string]serviceMonitorState
}

type serviceMonitorState struct {
	downStreak    int
	confirmedDown bool
}

func newServiceMonitor() *serviceMonitor {
	return &serviceMonitor{state: make(map[string]serviceMonitorState)}
}

// isHealthyService reports whether a systemd is-active status means "up".
// Transitional states (activating/reloading/deactivating) count as up so a
// restart doesn't flap; only a definitive inactive/failed is down. An empty
// output becomes "unknown" (see serviceState), which is treated as up: we can't
// tell, so we don't page anyone.
func isHealthyService(status string) bool {
	switch status {
	case "inactive", "failed":
		return false
	default:
		return true
	}
}

// StartServiceMonitor runs the service-health monitor until ctx is cancelled.
func (s *Server) StartServiceMonitor(ctx context.Context) {
	mon := newServiceMonitor()
	ticker := time.NewTicker(serviceMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mon.poll(ctx, s)
		}
	}
}

func (m *serviceMonitor) poll(ctx context.Context, s *Server) {
	var downs, ups []string
	for _, name := range managedServices {
		healthy := isHealthyService(serviceState(ctx, name))

		m.mu.Lock()
		st := m.state[name]
		if healthy {
			if st.confirmedDown {
				ups = append(ups, name)
			}
			st.downStreak = 0
			st.confirmedDown = false
		} else {
			st.downStreak++
			if st.downStreak >= serviceDownConfirmChecks && !st.confirmedDown {
				downs = append(downs, name)
				st.confirmedDown = true
			}
		}
		m.state[name] = st
		m.mu.Unlock()
	}

	// Dispatch outside the lock; webhooks can take up to the client timeout.
	for _, name := range downs {
		go s.DispatchNotifications(context.Background(), "service.down", map[string]string{"service": name})
	}
	for _, name := range ups {
		go s.DispatchNotifications(context.Background(), "service.up", map[string]string{"service": name})
	}
}
