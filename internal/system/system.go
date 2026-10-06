// Package system reads live host metrics — CPU, memory, disk, load, uptime and
// identity — from the local machine for the dashboard's system-information
// panel. It is Linux-only at runtime (the panel runs on the mail server); the
// non-Linux build is a stub so the Windows developer checkout still compiles.
package system

import (
	"sync"
	"time"
)

// cpuCounters is one reading of /proc/stat's aggregate cpu line.
type cpuCounters struct{ total, idle uint64 }

// Info is one snapshot of the host's identity and resource usage.
type Info struct {
	Hostname string
	IP       string
	OS       string
	Kernel   string
	CPUModel string
	CPUCores int

	UptimeSec float64
	Processes int
	Load1     float64
	Load5     float64
	Load15    float64

	MemTotal  int64
	MemUsed   int64
	MemCached int64
	SwapTotal int64
	SwapUsed  int64

	DiskTotal int64
	DiskUsed  int64
	DiskFree  int64

	CPUUsedPct  float64
	MemUsedPct  float64
	DiskUsedPct float64
}

// Sample is one point on the dashboard's sparklines.
type Sample struct {
	Time        time.Time
	CPU         float64
	MemUsedPct  float64
	DiskUsedPct float64
	Load1       float64
}

// historyLen is how many samples the sparklines keep (15s * 60 = 15 minutes).
const historyLen = 60

// Sampler polls host metrics on a timer and keeps a short history for the
// dashboard's sparklines.
type Sampler struct {
	mu      sync.Mutex
	info    Info
	history []Sample
	prev    cpuCounters

	stop chan struct{}
	once sync.Once
}

func NewSampler() *Sampler {
	return &Sampler{stop: make(chan struct{})}
}

// Start begins sampling. It is idempotent and safe to call once at startup.
func (s *Sampler) Start() {
	s.once.Do(func() { go s.loop() })
}

// Stop halts sampling. Production never calls it; tests do.
func (s *Sampler) Stop() { close(s.stop) }

func (s *Sampler) loop() {
	s.collect()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.collect()
		}
	}
}

func (s *Sampler) collect() {
	info, counters := collectInfo(s.prev)
	s.mu.Lock()
	s.prev = counters
	s.info = info
	s.history = append(s.history, Sample{
		Time:        time.Now(),
		CPU:         info.CPUUsedPct,
		MemUsedPct:  info.MemUsedPct,
		DiskUsedPct: info.DiskUsedPct,
		Load1:       info.Load1,
	})
	if len(s.history) > historyLen {
		s.history = s.history[len(s.history)-historyLen:]
	}
	s.mu.Unlock()
}

// Latest returns the most recent snapshot.
func (s *Sampler) Latest() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// History returns the recent samples, oldest first.
func (s *Sampler) History() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Sample, len(s.history))
	copy(out, s.history)
	return out
}

func pct(part, whole int64) float64 {
	if whole == 0 {
		return 0
	}
	return clamp(100*float64(part)/float64(whole), 0, 100)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
