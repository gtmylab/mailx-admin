package importer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// JobStatus is the lifecycle of one import job.
type JobStatus string

const (
	StatusQueued  JobStatus = "queued"
	StatusRunning JobStatus = "running"
	StatusDone    JobStatus = "done"
	StatusError   JobStatus = "error"
	StatusStopped JobStatus = "stopped"
)

// logCap bounds the per-job log buffer kept for the UI.
const logCap = 50

// Job is one import request and its live state.
type Job struct {
	ID     string
	Label  string // destination mailbox email, for display
	Source Source
	Dest   string // destination maildir path
	UID    int
	GID    int

	Status   JobStatus
	Error    string
	Folder   string // current folder
	Messages int    // cumulative written
	Total    int    // cumulative expected (0 = unknown)
	Result   *Result
	Log      []string

	Created  time.Time
	Started  *time.Time
	Finished *time.Time
}

// Queue runs import jobs one at a time, in the order they were added. It is
// safe for concurrent use; jobs live in memory for the lifetime of the process,
// so an import keeps running after the operator navigates away.
type Queue struct {
	mu     sync.Mutex
	jobs   map[string]*Job
	order  []string
	cancel map[string]context.CancelFunc
	wake   chan struct{}
	done   chan struct{}

	// run performs one import; overridable in tests.
	run func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error)
}

// NewQueue returns a running Queue. Close it when done.
func NewQueue() *Queue {
	q := &Queue{
		jobs:   map[string]*Job{},
		cancel: map[string]context.CancelFunc{},
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		run:    Import,
	}
	go q.worker()
	return q
}

// Close stops the worker. No further jobs are processed.
func (q *Queue) Close() {
	select {
	case <-q.done:
	default:
		close(q.done)
	}
}

// Add queues a job and returns its id.
func (q *Queue) Add(src Source, dest string, uid, gid int, label string) string {
	id := newID()
	now := time.Now()
	q.mu.Lock()
	q.jobs[id] = &Job{
		ID: id, Label: label, Source: src, Dest: dest, UID: uid, GID: gid,
		Status: StatusQueued, Created: now,
	}
	q.order = append(q.order, id)
	q.mu.Unlock()
	q.signal()
	return id
}

// List returns a snapshot of all jobs in insertion order.
func (q *Queue) List() []Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Job, 0, len(q.order))
	for _, id := range q.order {
		if j, ok := q.jobs[id]; ok {
			out = append(out, cloneJob(j))
		}
	}
	return out
}

// Get returns a snapshot of one job.
func (q *Queue) Get(id string) (Job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return Job{}, false
	}
	return cloneJob(j), true
}

// Stop cancels a running job, or marks a still-queued job stopped.
func (q *Queue) Stop(id string) bool {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return false
	}
	if j.Status == StatusQueued {
		now := time.Now()
		j.Status = StatusStopped
		j.Finished = &now
		j.Log = appendLog(j.Log, "Stopped before it started.")
		q.mu.Unlock()
		return true
	}
	cancel := q.cancel[id]
	q.mu.Unlock()
	if cancel != nil {
		cancel()
		return true
	}
	return false
}

// Retry re-queues a finished (done/error/stopped) job.
func (q *Queue) Retry(id string) bool {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok || j.Status == StatusRunning || j.Status == StatusQueued {
		q.mu.Unlock()
		return false
	}
	j.Status = StatusQueued
	j.Error = ""
	j.Folder = ""
	j.Messages = 0
	j.Total = 0
	j.Result = nil
	j.Log = nil
	j.Started = nil
	j.Finished = nil
	q.mu.Unlock()
	q.signal()
	return true
}

// Remove deletes a non-running job.
func (q *Queue) Remove(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok || j.Status == StatusRunning {
		return false
	}
	delete(q.jobs, id)
	delete(q.cancel, id)
	for i, x := range q.order {
		if x == id {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
	return true
}

// worker runs queued jobs sequentially until Close.
func (q *Queue) worker() {
	for {
		id := q.nextQueued()
		if id == "" {
			select {
			case <-q.wake:
				continue
			case <-q.done:
				return
			}
		}
		q.runJob(id)
	}
}

func (q *Queue) nextQueued() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, id := range q.order {
		if j, ok := q.jobs[id]; ok && j.Status == StatusQueued {
			return id
		}
	}
	return ""
}

func (q *Queue) runJob(id string) {
	ctx, cancel := context.WithCancel(context.Background())

	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok || j.Status != StatusQueued {
		// It was stopped or removed while waiting in the queue.
		delete(q.cancel, id)
		q.mu.Unlock()
		cancel()
		return
	}
	q.cancel[id] = cancel
	now := time.Now()
	j.Status = StatusRunning
	j.Started = &now
	src := j.Source
	dest := j.Dest
	uid, gid := j.UID, j.GID
	q.mu.Unlock()

	res, err := q.run(ctx, src, dest, uid, gid, func(p Progress) {
		q.update(id, func(j *Job) {
			if p.Log != "" {
				j.Log = appendLog(j.Log, p.Log)
			}
			if p.Folder != "" {
				j.Folder = p.Folder
			}
			j.Messages = p.Messages
			if p.Total > 0 {
				j.Total = p.Total
			}
		})
	})

	finished := time.Now()
	q.update(id, func(j *Job) {
		j.Finished = &finished
		switch {
		case err != nil && ctx.Err() != nil:
			j.Status = StatusStopped
			j.Log = appendLog(j.Log, "Stopped.")
		case err != nil:
			j.Status = StatusError
			j.Error = err.Error()
			j.Log = appendLog(j.Log, "Error: "+err.Error())
		default:
			j.Status = StatusDone
			j.Result = res
			total := 0
			if res != nil {
				total = res.Total()
			}
			j.Log = appendLog(j.Log, fmt.Sprintf("Import complete: %d messages.", total))
		}
	})

	q.mu.Lock()
	delete(q.cancel, id)
	q.mu.Unlock()
}

func (q *Queue) update(id string, fn func(*Job)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j, ok := q.jobs[id]; ok {
		fn(j)
	}
}

func (q *Queue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func appendLog(log []string, line string) []string {
	log = append(log, line)
	if len(log) > logCap {
		log = log[len(log)-logCap:]
	}
	return log
}

// cloneJob deep-copies the slices/pointers so callers get a snapshot, never a
// view into the worker's live state.
func cloneJob(j *Job) Job {
	out := *j
	out.Log = append([]string(nil), j.Log...)
	if j.Result != nil {
		r := *j.Result
		if j.Result.Folders != nil {
			r.Folders = make(map[string]int, len(j.Result.Folders))
			for k, v := range j.Result.Folders {
				r.Folders[k] = v
			}
		}
		out.Result = &r
	}
	if j.Started != nil {
		t := *j.Started
		out.Started = &t
	}
	if j.Finished != nil {
		t := *j.Finished
		out.Finished = &t
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
