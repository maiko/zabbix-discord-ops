package correlation

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingCorrelationSurvivesRestartAndCompletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "correlations")
	startedAt := time.Unix(1_800_000_000, 0)
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, existed, err := store.Begin("101", "prod", "1002", startedAt)
	if err != nil || existed {
		t.Fatalf("begin failed: existed=%v err=%v", existed, err)
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, existed, err = reloaded.Begin("101", "prod", "1002", startedAt.Add(time.Hour))
	if err != nil || !existed || pending.MessageID != "" || !pending.StartedAt.Equal(startedAt) {
		t.Fatalf("pending correlation was not restored: %#v existed=%v err=%v", pending, existed, err)
	}
	complete, err := reloaded.Complete(pending, "2001", startedAt.Add(time.Minute))
	if err != nil || complete.MessageID != "2001" {
		t.Fatalf("complete failed: %#v err=%v", complete, err)
	}

	finalStore, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	final, existed, err := finalStore.Begin("101", "prod", "1002", startedAt)
	if err != nil || !existed || final.MessageID != "2001" {
		t.Fatalf("completed correlation was not restored: %#v existed=%v err=%v", final, existed, err)
	}
}

func TestCountStaleCompletedPreservesEveryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "correlations")
	now := time.Unix(1_800_000_000, 0)
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	expired, _, err := store.Begin("101", "prod", "1002", now.Add(-100*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Complete(expired, "2001", now.Add(-100*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin("102", "prod", "1002", now.Add(-100*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	current, _, err := store.Begin("103", "prod", "1002", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Complete(current, "2003", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	stale, err := store.CountStaleCompleted(now, 90*24*time.Hour)
	if err != nil || stale != 1 {
		t.Fatalf("unexpected stale count: count=%d err=%v", stale, err)
	}
	expired, existed, err := store.Begin("101", "prod", "1002", now)
	if err != nil || !existed || expired.MessageID != "2001" {
		t.Fatalf("stale completed record changed: %#v existed=%v err=%v", expired, existed, err)
	}
	pending, existed, err := store.Begin("102", "prod", "1002", now)
	if err != nil || !existed || pending.MessageID != "" {
		t.Fatalf("old pending record changed: %#v existed=%v err=%v", pending, existed, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 3 {
		t.Fatalf("report-only inspection changed state: entries=%d err=%v", len(entries), err)
	}
}

func TestStoreRejectsSymlinkDirectory(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "correlations")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link); err == nil {
		t.Fatal("expected symlink state directory rejection")
	}
}
