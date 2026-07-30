package discord

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifierAcceptsOnceAndRejectsReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"type":1}`)
	signature := ed25519.Sign(privateKey, append([]byte(timestamp), body...))

	if err := verifier.Verify(timestamp, hex.EncodeToString(signature), body, now); err != nil {
		t.Fatalf("first verification failed: %v", err)
	}
	if err := verifier.Verify(timestamp, strings.ToUpper(hex.EncodeToString(signature)), body, now); err != ErrReplay {
		t.Fatalf("expected replay error, got %v", err)
	}
}

func TestVerifierRejectsStaleAndTamperedPayloads(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewVerifier(publicKey)
	now := time.Unix(1_800_000_000, 0)
	oldTimestamp := strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10)
	body := []byte(`{"type":1}`)
	signature := ed25519.Sign(privateKey, append([]byte(oldTimestamp), body...))
	if err := verifier.Verify(oldTimestamp, hex.EncodeToString(signature), body, now); err != ErrBadSignature {
		t.Fatalf("expected stale signature rejection, got %v", err)
	}

	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature = ed25519.Sign(privateKey, append([]byte(timestamp), body...))
	if err := verifier.Verify(timestamp, hex.EncodeToString(signature), []byte(`{"type":2}`), now); err != ErrBadSignature {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestComponentSignerRoundTripAndExpiry(t *testing.T) {
	signer, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	want := ComponentToken{
		Action:  "ack",
		EventID: "12345",
		Route:   "prod",
		Expires: now.Add(time.Minute).Unix(),
	}
	value, err := signer.Sign(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signer.Verify(value, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if _, err := signer.Verify(value, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected expired component rejection")
	}
	if _, err := signer.Verify(value+"x", now); err == nil {
		t.Fatal("expected tampered component rejection")
	}
}

func TestComponentSignerFitsDiscordLimitAtMaximumInput(t *testing.T) {
	signer, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := signer.Sign(ComponentToken{
		Action:  "severity-submit",
		EventID: "18446744073709551615",
		Route:   "tenant-prod-route-123456",
		Expires: time.Unix(1_800_000_000, 0).Add(30 * 24 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(value) > 100 {
		t.Fatalf("custom ID has %d characters", len(value))
	}
}
