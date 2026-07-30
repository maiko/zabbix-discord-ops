package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunRejectsSymlinkTokenFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("discord-token-long-enough"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := run(
		"1001",
		"1002",
		link,
		"https://discord.com/api/v10",
	)
	if err == nil {
		t.Fatal("expected symlink token rejection")
	}
}
