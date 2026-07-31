package discord

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrBadSignature = errors.New("invalid Discord signature")
	ErrReplay       = errors.New("replayed Discord interaction")
)

type Verifier struct {
	publicKey ed25519.PublicKey
	maxSkew   time.Duration
	mu        sync.Mutex
	seen      map[string]time.Time
}

func NewVerifier(publicKey []byte) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("Discord public key has invalid length")
	}
	return &Verifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		maxSkew:   5 * time.Minute,
		seen:      make(map[string]time.Time),
	}, nil
}

func (v *Verifier) Verify(timestamp, signatureHex string, body []byte, now time.Time) error {
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrBadSignature
	}
	signedAt := time.Unix(seconds, 0)
	if delta := now.Sub(signedAt); delta >= v.maxSkew || delta <= -v.maxSkew {
		return ErrBadSignature
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	message := append([]byte(timestamp), body...)
	if !ed25519.Verify(v.publicKey, message, signature) {
		return ErrBadSignature
	}

	key := timestamp + ":" + hex.EncodeToString(signature)
	expiresAt := signedAt.Add(v.maxSkew)
	v.mu.Lock()
	defer v.mu.Unlock()
	for candidate, expires := range v.seen {
		if !now.Before(expires) {
			delete(v.seen, candidate)
		}
	}
	if expires, ok := v.seen[key]; ok && now.Before(expires) {
		return ErrReplay
	}
	v.seen[key] = expiresAt
	return nil
}

type ComponentToken struct {
	Action        string `json:"a"`
	EventID       string `json:"e"`
	Route         string `json:"r"`
	SubjectUserID string `json:"u,omitempty"`
	Expires       int64  `json:"x"`
}

type Signer struct {
	key []byte
}

var componentActionCodes = map[string]string{
	"ack":                        "a",
	"unsuppress":                 "u",
	"comment":                    "c",
	"comment-submit":             "C",
	"suppress":                   "s",
	"suppress-submit":            "S",
	"severity":                   "v",
	"severity-submit":            "V",
	"close":                      "x",
	"close-confirm":              "X",
	"maintenance-cancel-confirm": "M",
}

func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, errors.New("component signing key is too short")
	}
	return &Signer{key: append([]byte(nil), key...)}, nil
}

func (s *Signer) Sign(component ComponentToken) (string, error) {
	actionCode, ok := componentActionCodes[component.Action]
	if !ok || !isDecimal(component.EventID) || !isRouteName(component.Route) || component.Expires <= 0 {
		return "", errors.New("invalid component payload")
	}
	if component.Action == "maintenance-cancel-confirm" {
		if !isDecimal(component.SubjectUserID) {
			return "", errors.New("maintenance component requires a Discord user")
		}
		eventID, eventErr := strconv.ParseUint(component.EventID, 10, 64)
		userID, userErr := strconv.ParseUint(component.SubjectUserID, 10, 64)
		if eventErr != nil || userErr != nil {
			return "", errors.New("maintenance component has an invalid numeric ID")
		}
		payload := strings.Join([]string{
			"2",
			actionCode,
			strconv.FormatUint(eventID, 36),
			component.Route,
			strconv.FormatUint(userID, 36),
			strconv.FormatInt(component.Expires, 36),
		}, ".")
		return s.signedValue(payload)
	}
	payload := strings.Join([]string{
		"1",
		actionCode,
		component.EventID,
		component.Route,
		strconv.FormatInt(component.Expires, 36),
	}, ".")
	return s.signedValue(payload)
}

func (s *Signer) signedValue(payload string) (string, error) {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	value := payload + "." + signature
	if len(value) > 100 {
		return "", errors.New("signed component ID exceeds Discord's limit")
	}
	return value, nil
}

func (s *Signer) Verify(value string, now time.Time) (ComponentToken, error) {
	var component ComponentToken
	parts := strings.Split(value, ".")
	if len(parts) == 7 && parts[0] == "2" {
		return s.verifyMaintenance(parts, now)
	}
	if len(parts) != 6 || parts[0] != "1" {
		return component, errors.New("malformed component ID")
	}
	payload := strings.Join(parts[:5], ".")
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	expected := mac.Sum(nil)[:16]
	actual, err := base64.RawURLEncoding.DecodeString(parts[5])
	if err != nil || !hmac.Equal(expected, actual) {
		return component, errors.New("invalid component signature")
	}
	action := ""
	for name, code := range componentActionCodes {
		if code == parts[1] {
			action = name
			break
		}
	}
	expires, err := strconv.ParseInt(parts[4], 36, 64)
	if action == "" || err != nil || !isDecimal(parts[2]) || !isRouteName(parts[3]) {
		return component, errors.New("invalid component payload")
	}
	component = ComponentToken{
		Action:  action,
		EventID: parts[2],
		Route:   parts[3],
		Expires: expires,
	}
	if now.Unix() > component.Expires {
		return component, fmt.Errorf("component expired at %d", component.Expires)
	}
	return component, nil
}

func (s *Signer) verifyMaintenance(
	parts []string,
	now time.Time,
) (ComponentToken, error) {
	var component ComponentToken
	payload := strings.Join(parts[:6], ".")
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	expected := mac.Sum(nil)[:16]
	actual, err := base64.RawURLEncoding.DecodeString(parts[6])
	if err != nil || !hmac.Equal(expected, actual) {
		return component, errors.New("invalid component signature")
	}
	if parts[1] != componentActionCodes["maintenance-cancel-confirm"] ||
		!isRouteName(parts[3]) {
		return component, errors.New("invalid maintenance component payload")
	}
	eventID, eventErr := strconv.ParseUint(parts[2], 36, 64)
	userID, userErr := strconv.ParseUint(parts[4], 36, 64)
	expires, expiresErr := strconv.ParseInt(parts[5], 36, 64)
	if eventErr != nil || userErr != nil || expiresErr != nil ||
		eventID == 0 || userID == 0 {
		return component, errors.New("invalid maintenance component payload")
	}
	component = ComponentToken{
		Action:        "maintenance-cancel-confirm",
		EventID:       strconv.FormatUint(eventID, 10),
		Route:         parts[3],
		SubjectUserID: strconv.FormatUint(userID, 10),
		Expires:       expires,
	}
	if now.Unix() > component.Expires {
		return component, fmt.Errorf("component expired at %d", component.Expires)
	}
	return component, nil
}

func isDecimal(value string) bool {
	if value == "" || len(value) > 20 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isRouteName(value string) bool {
	if value == "" || len(value) > 24 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' &&
			character != '_' {
			return false
		}
	}
	return true
}
