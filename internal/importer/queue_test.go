package importer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestQueue builds a Queue whose run function is controlled by f.
func newTestQueue(f func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error)) *Queue {
	q := NewQueue()
	q.run = f
	return q
}

func waitStatus(t *testing.T, q *Queue, id string, want JobStatus) Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		j, ok := q.Get(id)
		if ok && j.Status == want {
			return j
		}
		time.Sleep(2 * time.Millisecond)
	}
	j, _ := q.Get(id)
	t.Fatalf("job %s did not reach %s (got %s, err=%q)", id, want, j.Status, j.Error)
	return j
}

func TestQueueRunsJobsSequentially(t *testing.T) {
	var mu sync.Mutex
	var ran []string
	q := newTestQueue(func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
		mu.Lock()
		ran = append(ran, dst)
		mu.Unlock()
		report(Progress{Log: "working", Messages: 1, Total: 1})
		return &Result{Folders: map[string]int{"": 1}}, nil
	})
	defer q.Close()

	id1 := q.Add(Source{MboxPath: "/a"}, "/dst1", 1, 1, "a@example.com")
	id2 := q.Add(Source{MboxPath: "/b"}, "/dst2", 1, 1, "b@example.com")

	waitStatus(t, q, id2, StatusDone)

	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 2 || ran[0] != "/dst1" || ran[1] != "/dst2" {
		t.Fatalf("jobs ran in wrong order: %v", ran)
	}
	if j, _ := q.Get(id1); j.Status != StatusDone {
		t.Fatalf("first job not done: %+v", j)
	}
}

func TestQueueCapturesProgress(t *testing.T) {
	q := newTestQueue(func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
		report(Progress{Log: "one", Folder: "INBOX", Messages: 1, Total: 2})
		report(Progress{Folder: "Sent", Messages: 2})
		return &Result{Folders: map[string]int{"INBOX": 1, "Sent": 1}}, nil
	})
	defer q.Close()

	id := q.Add(Source{MboxPath: "/a"}, "/dst", 1, 1, "a@example.com")
	waitStatus(t, q, id, StatusDone)

	j, _ := q.Get(id)
	if j.Folder != "Sent" || j.Messages != 2 || j.Total != 2 {
		t.Fatalf("progress not captured: folder=%q messages=%d total=%d", j.Folder, j.Messages, j.Total)
	}
	if j.Result == nil || j.Result.Total() != 2 {
		t.Fatalf("result not captured: %+v", j.Result)
	}
	found := false
	for _, l := range j.Log {
		if l == "one" {
			found = true
		}
	}
	if !found {
		t.Fatalf("log line not captured: %v", j.Log)
	}
}

func TestQueueStopRunning(t *testing.T) {
	started := make(chan struct{})
	q := newTestQueue(func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	defer q.Close()

	id := q.Add(Source{MboxPath: "/a"}, "/dst", 1, 1, "a@example.com")
	<-started
	if !q.Stop(id) {
		t.Fatal("Stop returned false for a running job")
	}
	waitStatus(t, q, id, StatusStopped)
}

func TestQueueStopQueued(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	q := newTestQueue(func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
		close(started)
		<-release
		return &Result{Folders: map[string]int{"": 1}}, nil
	})
	defer q.Close()

	id1 := q.Add(Source{MboxPath: "/a"}, "/dst1", 1, 1, "a@example.com")
	id2 := q.Add(Source{MboxPath: "/b"}, "/dst2", 1, 1, "b@example.com")

	<-started // first job is running, second is queued behind it
	if !q.Stop(id2) {
		t.Fatal("Stop returned false for a queued job")
	}
	j, _ := q.Get(id2)
	if j.Status != StatusStopped {
		t.Fatalf("queued job should be stopped, got %s", j.Status)
	}

	close(release)
	waitStatus(t, q, id1, StatusDone)
}

func TestQueueRetry(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	q := newTestQueue(func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
		if fail.Load() {
			return nil, fmt.Errorf("boom")
		}
		return &Result{Folders: map[string]int{"": 1}}, nil
	})
	defer q.Close()

	id := q.Add(Source{MboxPath: "/a"}, "/dst", 1, 1, "a@example.com")
	waitStatus(t, q, id, StatusError)

	fail.Store(false)
	if !q.Retry(id) {
		t.Fatal("Retry returned false for a failed job")
	}
	waitStatus(t, q, id, StatusDone)
}

func TestQueueRemove(t *testing.T) {
	q := newTestQueue(func(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
		return &Result{Folders: map[string]int{"": 1}}, nil
	})
	defer q.Close()

	id := q.Add(Source{MboxPath: "/a"}, "/dst", 1, 1, "a@example.com")
	waitStatus(t, q, id, StatusDone)
	if !q.Remove(id) {
		t.Fatal("Remove returned false for a done job")
	}
	if len(q.List()) != 0 {
		t.Fatal("expected empty queue after Remove")
	}
}
