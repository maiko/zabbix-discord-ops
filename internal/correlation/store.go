package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	legacyRecordVersion = 1
	recordVersion       = 2
)

type Record struct {
	Version         int                  `json:"version"`
	EventID         string               `json:"event_id"`
	Route           string               `json:"route"`
	ChannelID       string               `json:"channel_id"`
	MessageID       string               `json:"message_id,omitempty"`
	MirrorStartedAt map[string]time.Time `json:"mirror_started_at,omitempty"`
	MirrorMessages  map[string]string    `json:"mirror_messages,omitempty"`
	StartedAt       time.Time            `json:"started_at"`
	CompletedAt     *time.Time           `json:"completed_at,omitempty"`
}

type Store struct {
	path string
}

func New(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("correlation state path must be absolute")
	}
	if err := ensurePrivateDirectory(path); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func (s *Store) Begin(
	eventID, route, channelID string,
	startedAt time.Time,
) (Record, bool, error) {
	path := s.recordPath(eventID, route)
	record, err := readRecord(path)
	if err == nil {
		if record.EventID != eventID ||
			record.Route != route ||
			record.ChannelID != channelID {
			return Record{}, true, errors.New("stored correlation identity does not match route")
		}
		return record, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Record{}, false, err
	}
	record = Record{
		Version:   recordVersion,
		EventID:   eventID,
		Route:     route,
		ChannelID: channelID,
		StartedAt: startedAt.UTC(),
	}
	if err := writeRecord(path, record); err != nil {
		return Record{}, false, err
	}
	return record, false, nil
}

func (s *Store) Complete(
	record Record,
	messageID string,
	completedAt time.Time,
) (Record, error) {
	path := s.recordPath(record.EventID, record.Route)
	current, err := readRecord(path)
	if err != nil {
		return Record{}, err
	}
	if current.EventID != record.EventID ||
		current.Route != record.Route ||
		current.ChannelID != record.ChannelID {
		return Record{}, errors.New("correlation changed before completion")
	}
	if current.MessageID != "" {
		if current.MessageID != messageID {
			return Record{}, errors.New("correlation already points to another Discord message")
		}
		return current, nil
	}
	completed := completedAt.UTC()
	current.MessageID = messageID
	current.CompletedAt = &completed
	if err := writeRecord(path, current); err != nil {
		return Record{}, err
	}
	return current, nil
}

func (s *Store) CompleteMirror(
	record Record,
	channelID, messageID string,
) (Record, error) {
	path := s.recordPath(record.EventID, record.Route)
	current, err := readRecord(path)
	if err != nil {
		return Record{}, err
	}
	if current.EventID != record.EventID ||
		current.Route != record.Route ||
		current.ChannelID != record.ChannelID ||
		current.MessageID == "" {
		return Record{}, errors.New("correlation changed before mirror completion")
	}
	if channelID == "" || channelID == current.ChannelID || messageID == "" {
		return Record{}, errors.New("invalid mirror correlation identity")
	}
	if current.MirrorStartedAt[channelID].IsZero() {
		return Record{}, errors.New("mirror correlation was not started")
	}
	if current.MirrorMessages == nil {
		current.MirrorMessages = map[string]string{}
	}
	if existing := current.MirrorMessages[channelID]; existing != "" {
		if existing != messageID {
			return Record{}, errors.New("mirror correlation already points to another Discord message")
		}
		return current, nil
	}
	current.Version = recordVersion
	current.MirrorMessages[channelID] = messageID
	if err := writeRecord(path, current); err != nil {
		return Record{}, err
	}
	return current, nil
}

func (s *Store) BeginMirror(
	record Record,
	channelID string,
	startedAt time.Time,
) (Record, bool, error) {
	path := s.recordPath(record.EventID, record.Route)
	current, err := readRecord(path)
	if err != nil {
		return Record{}, false, err
	}
	if current.EventID != record.EventID ||
		current.Route != record.Route ||
		current.ChannelID != record.ChannelID ||
		current.MessageID == "" {
		return Record{}, false, errors.New("correlation changed before mirror start")
	}
	if channelID == "" || channelID == current.ChannelID || startedAt.IsZero() {
		return Record{}, false, errors.New("invalid mirror correlation identity")
	}
	if existing := current.MirrorStartedAt[channelID]; !existing.IsZero() {
		return current, true, nil
	}
	if current.MirrorStartedAt == nil {
		current.MirrorStartedAt = map[string]time.Time{}
	}
	current.Version = recordVersion
	current.MirrorStartedAt[channelID] = startedAt.UTC()
	if err := writeRecord(path, current); err != nil {
		return Record{}, false, err
	}
	return current, false, nil
}

func (s *Store) Lookup(eventID, route string) (Record, bool, error) {
	record, err := readRecord(s.recordPath(eventID, route))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	return record, err == nil, err
}

func (s *Store) CountStaleCompleted(
	now time.Time,
	reviewAfter time.Duration,
) (int, error) {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return 0, fmt.Errorf("read correlation state directory: %w", err)
	}
	cutoff := now.UTC().Add(-reviewAfter)
	stale := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.path, entry.Name())
		record, err := readRecord(path)
		if err != nil {
			return stale, err
		}
		if path != s.recordPath(record.EventID, record.Route) {
			return stale, errors.New("correlation record filename does not match its identity")
		}
		if record.CompletedAt == nil || !record.CompletedAt.Before(cutoff) {
			continue
		}
		stale++
	}
	return stale, nil
}

func (s *Store) recordPath(eventID, route string) string {
	digest := sha256.Sum256([]byte(route + "\x00" + eventID))
	return filepath.Join(s.path, hex.EncodeToString(digest[:])+".json")
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create correlation state directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect correlation state directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("correlation state path must be a private non-symlink directory")
	}
	return nil
}

func readRecord(path string) (Record, error) {
	var record Record
	before, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !before.Mode().IsRegular() ||
		before.Mode().Perm()&0o077 != 0 ||
		before.Size() > 64<<10 {
		return record, errors.New("correlation record must be a small regular non-symlink file with mode 0600 or stricter")
	}
	file, err := os.Open(path)
	if err != nil {
		return record, fmt.Errorf("open correlation record: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return record, fmt.Errorf("inspect opened correlation record: %w", err)
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return record, errors.New("correlation record changed while it was opened")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode correlation record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return record, errors.New("decode correlation record: trailing JSON content")
	}
	if (record.Version != legacyRecordVersion && record.Version != recordVersion) ||
		record.EventID == "" ||
		record.Route == "" ||
		record.ChannelID == "" ||
		record.StartedAt.IsZero() ||
		(record.MessageID == "") != (record.CompletedAt == nil) {
		return record, errors.New("invalid correlation record")
	}
	if record.Version == legacyRecordVersion &&
		(len(record.MirrorStartedAt) != 0 || len(record.MirrorMessages) != 0) {
		return record, errors.New("legacy correlation record contains mirror messages")
	}
	for channelID, startedAt := range record.MirrorStartedAt {
		if channelID == "" || channelID == record.ChannelID || startedAt.IsZero() {
			return record, errors.New("invalid mirror correlation record")
		}
	}
	for channelID, messageID := range record.MirrorMessages {
		if record.MirrorStartedAt[channelID].IsZero() || messageID == "" {
			return record, errors.New("invalid mirror correlation record")
		}
	}
	return record, nil
}

func writeRecord(path string, record Record) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".correlation-*")
	if err != nil {
		return fmt.Errorf("create correlation record: %w", err)
	}
	temporaryPath := file.Name()

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf(
			"protect correlation temporary file %q: %w",
			temporaryPath,
			err,
		)
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		_ = file.Close()
		return fmt.Errorf(
			"encode correlation temporary file %q: %w",
			temporaryPath,
			err,
		)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf(
			"sync correlation temporary file %q: %w",
			temporaryPath,
			err,
		)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close correlation temporary file %q: %w",
			temporaryPath,
			err,
		)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf(
			"replace correlation record; retained temporary file %q: %w",
			temporaryPath,
			err,
		)
	}
	parent, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open correlation state directory: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync correlation state directory: %w", err)
	}
	return nil
}
