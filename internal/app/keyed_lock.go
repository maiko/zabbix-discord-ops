package app

import (
	"context"
	"sync"
)

type keyedLockEntry struct {
	token chan struct{}
	refs  int
}

type keyedLocker struct {
	mu      sync.Mutex
	entries map[string]*keyedLockEntry
}

func newKeyedLocker() *keyedLocker {
	return &keyedLocker{entries: make(map[string]*keyedLockEntry)}
}

func (l *keyedLocker) Acquire(
	ctx context.Context,
	key string,
) (func(), error) {
	l.mu.Lock()
	entry, ok := l.entries[key]
	if !ok {
		entry = &keyedLockEntry{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		l.entries[key] = entry
	}
	entry.refs++
	l.mu.Unlock()

	select {
	case <-entry.token:
		if err := ctx.Err(); err != nil {
			entry.token <- struct{}{}
			l.releaseReference(key, entry)
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				entry.token <- struct{}{}
				l.releaseReference(key, entry)
			})
		}, nil
	case <-ctx.Done():
		l.releaseReference(key, entry)
		return nil, ctx.Err()
	}
}

func (l *keyedLocker) releaseReference(
	key string,
	entry *keyedLockEntry,
) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.refs--
	if entry.refs == 0 && l.entries[key] == entry {
		delete(l.entries, key)
	}
}
