package maintenancecard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Record struct {
	Version        int               `json:"version"`
	MaintenanceID  string            `json:"maintenance_id"`
	Route          string            `json:"route"`
	ChannelID      string            `json:"channel_id"`
	MessageID      string            `json:"message_id,omitempty"`
	MirrorMessages map[string]string `json:"mirror_messages,omitempty"`
	State          string            `json:"state"`
	LastSeenAt     time.Time         `json:"last_seen_at"`
	FinalSnapshot  map[string]any    `json:"final_snapshot,omitempty"`
}

type Store struct {
	path string
}

func New(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("maintenance card state path must be absolute")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("maintenance card state path must be private")
	}
	return &Store{path: path}, nil
}

func (s *Store) Get(maintenanceID, route string) (Record, bool, error) {
	record, err := read(s.recordPath(maintenanceID, route))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	return record, err == nil, err
}

func (s *Store) Put(record Record) error {
	if record.MaintenanceID == "" || record.Route == "" ||
		record.ChannelID == "" || record.State == "" || record.LastSeenAt.IsZero() {
		return errors.New("maintenance card record is incomplete")
	}
	record.Version = 1
	return write(s.recordPath(record.MaintenanceID, record.Route), record)
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
			s.recordPath(record.MaintenanceID, record.Route) {
			return nil, errors.New(
				"maintenance card filename does not match its identity",
			)
		}
		result = append(result, record)
	}
	return result, nil
}

func (s *Store) recordPath(maintenanceID, route string) string {
	digest := sha256.Sum256([]byte(route + "\x00" + maintenanceID))
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
		return record, errors.New("maintenance card record is not protected")
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
		return record, errors.New(
			"maintenance card record changed while it was opened",
		)
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return record, errors.New("maintenance card record has trailing content")
	}
	if record.Version != 1 || record.MaintenanceID == "" ||
		record.Route == "" || record.ChannelID == "" ||
		record.State == "" || record.LastSeenAt.IsZero() {
		return record, errors.New("invalid maintenance card record")
	}
	return record, nil
}

func write(path string, record Record) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".maintenance-card-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
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
