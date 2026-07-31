package operation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Status string

const (
	Pending    Status = "pending"
	Executing  Status = "executing"
	Reconciled Status = "reconciled"
	Completed  Status = "completed"
)

type Record struct {
	Version       int            `json:"version"`
	InteractionID string         `json:"interaction_id"`
	Action        string         `json:"action"`
	Route         string         `json:"route"`
	ObjectID      string         `json:"object_id"`
	Status        Status         `json:"status"`
	StartedAt     time.Time      `json:"started_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Result        string         `json:"result,omitempty"`
	FinalSnapshot map[string]any `json:"final_snapshot,omitempty"`
}

type Store struct {
	path string
}

func New(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("operation state path must be absolute")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create operation state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect operation state directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("operation state path must be a private non-symlink directory")
	}
	return &Store{path: path}, nil
}

func (s *Store) Begin(record Record) (Record, bool, error) {
	if record.InteractionID == "" || record.Action == "" ||
		record.Route == "" || record.ObjectID == "" {
		return Record{}, false, errors.New("operation identity is incomplete")
	}
	path := s.recordPath(record.InteractionID)
	existing, err := read(path)
	if err == nil {
		if existing.InteractionID != record.InteractionID ||
			existing.Action != record.Action ||
			existing.Route != record.Route ||
			existing.ObjectID != record.ObjectID {
			return Record{}, true, errors.New("operation identity mismatch")
		}
		return existing, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Record{}, false, err
	}
	now := record.StartedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.Version = 1
	record.Status = Pending
	record.StartedAt = now
	record.UpdatedAt = now
	if err := write(path, record); err != nil {
		return Record{}, false, err
	}
	return record, false, nil
}

func (s *Store) Get(interactionID string) (Record, bool, error) {
	record, err := read(s.recordPath(interactionID))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	return record, err == nil, err
}

func (s *Store) Update(
	record Record,
	status Status,
	result string,
	snapshot map[string]any,
	now time.Time,
) (Record, error) {
	if status != Executing && status != Reconciled && status != Completed {
		return Record{}, errors.New("invalid operation transition")
	}
	current, err := read(s.recordPath(record.InteractionID))
	if err != nil {
		return Record{}, err
	}
	if current.InteractionID != record.InteractionID ||
		current.Action != record.Action ||
		current.Route != record.Route ||
		current.ObjectID != record.ObjectID {
		return Record{}, errors.New("operation changed before update")
	}
	if current.Status == Completed {
		return current, nil
	}
	current.Status = status
	current.Result = result
	current.FinalSnapshot = snapshot
	current.UpdatedAt = now.UTC()
	if err := write(s.recordPath(record.InteractionID), current); err != nil {
		return Record{}, err
	}
	return current, nil
}

func (s *Store) OldestPending(now time.Time) (time.Duration, int, error) {
	records, err := s.List()
	if err != nil {
		return 0, 0, err
	}
	var oldest time.Duration
	count := 0
	for _, record := range records {
		if record.Status == Completed {
			continue
		}
		count++
		age := now.UTC().Sub(record.UpdatedAt)
		if age > oldest {
			oldest = age
		}
	}
	return oldest, count, nil
}

func (s *Store) List() ([]Record, error) {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return nil, err
	}
	result := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, readErr := read(filepath.Join(s.path, entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		if filepath.Join(s.path, entry.Name()) !=
			s.recordPath(record.InteractionID) {
			return nil, errors.New(
				"operation record filename does not match its identity",
			)
		}
		result = append(result, record)
	}
	return result, nil
}

func (s *Store) recordPath(interactionID string) string {
	digest := sha256.Sum256([]byte("maintenance\x00" + interactionID))
	return filepath.Join(s.path, hex.EncodeToString(digest[:])+".json")
}

func read(path string) (Record, error) {
	var record Record
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() > 64<<10 {
		return record, errors.New("operation record is not a protected regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return record, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() ||
		opened.Mode().Perm()&0o077 != 0 {
		return record, errors.New("operation record changed while it was opened")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return record, errors.New("operation record has trailing content")
	}
	if record.Version != 1 || record.InteractionID == "" ||
		record.Action == "" || record.Route == "" || record.ObjectID == "" ||
		record.StartedAt.IsZero() || record.UpdatedAt.IsZero() {
		return record, errors.New("invalid operation record")
	}
	return record, nil
}

func write(path string, record Record) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".operation-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = os.Remove(temporary)
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(record); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
