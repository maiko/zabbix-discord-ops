package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	routeNamePattern = regexp.MustCompile(`^[a-z0-9_-]{1,24}$`)
	snowflakePattern = regexp.MustCompile(`^[0-9]{1,20}$`)
)

type Route struct {
	GuildID             string            `json:"guild_id"`
	ChannelID           string            `json:"channel_id"`
	RequiredTags        map[string]string `json:"required_tags"`
	RequiredHostGroupID []string          `json:"required_host_group_ids"`
	AllowedRoleIDs      []string          `json:"allowed_role_ids"`
	AllowedUserIDs      []string          `json:"allowed_user_ids"`
}

type Config struct {
	Listen               string           `json:"listen"`
	DisplayName          string           `json:"display_name"`
	PublicBaseURL        string           `json:"public_base_url"`
	ZabbixURL            string           `json:"zabbix_url"`
	StatePath            string           `json:"state_path"`
	StateReviewAfterDays int              `json:"state_review_after_days"`
	RoutingTag           string           `json:"routing_tag"`
	DiscordAPIURL        string           `json:"discord_api_url"`
	DiscordBotUserID     string           `json:"discord_bot_user_id"`
	RequestMaxBytes      int64            `json:"request_max_bytes"`
	Routes               map[string]Route `json:"routes"`
}

type Secrets struct {
	DiscordBotToken     string
	DiscordPublicKey    []byte
	ZabbixAPIToken      string
	IngestToken         string
	ComponentSigningKey []byte
}

func Load(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return cfg, errors.New("decode config: trailing JSON content")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9088"
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Zabbix Ops"
	}
	if cfg.RoutingTag == "" {
		cfg.RoutingTag = "notification_route"
	}
	if cfg.DiscordAPIURL == "" {
		cfg.DiscordAPIURL = "https://discord.com/api/v10"
	}
	if cfg.RequestMaxBytes == 0 {
		cfg.RequestMaxBytes = 1 << 20
	}
	if cfg.StateReviewAfterDays == 0 {
		cfg.StateReviewAfterDays = 90
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen must be host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen address must be an IP loopback address")
	}
	for name, rawURL := range map[string]string{
		"public_base_url": c.PublicBaseURL,
		"zabbix_url":      c.ZabbixURL,
		"discord_api_url": c.DiscordAPIURL,
	} {
		parsed, err := url.Parse(rawURL)
		if err != nil ||
			parsed.Scheme != "https" ||
			parsed.Host == "" ||
			parsed.User != nil ||
			parsed.Fragment != "" {
			return fmt.Errorf("%s must be an absolute HTTPS URL", name)
		}
	}
	if c.RoutingTag == "" || len(c.Routes) == 0 {
		return errors.New("routing_tag and at least one route are required")
	}
	if !filepath.IsAbs(c.StatePath) {
		return errors.New("state_path must be an absolute path")
	}
	if c.StateReviewAfterDays < 30 || c.StateReviewAfterDays > 3650 {
		return errors.New("state_review_after_days must be between 30 and 3650")
	}
	if !snowflakePattern.MatchString(c.DiscordBotUserID) {
		return errors.New("discord_bot_user_id must be a numeric Discord user ID")
	}
	if strings.TrimSpace(c.DisplayName) == "" || len([]rune(c.DisplayName)) > 80 {
		return errors.New("display_name is required and must not exceed 80 characters")
	}
	for name, route := range c.Routes {
		if !routeNamePattern.MatchString(name) {
			return fmt.Errorf("route %q must match %s", name, routeNamePattern)
		}
		if !snowflakePattern.MatchString(route.GuildID) ||
			!snowflakePattern.MatchString(route.ChannelID) {
			return fmt.Errorf("route %q requires numeric Discord guild and channel IDs", name)
		}
		if len(route.AllowedRoleIDs) == 0 && len(route.AllowedUserIDs) == 0 {
			return fmt.Errorf("route %q requires an allowed role or user", name)
		}
		for _, value := range append(
			append([]string{}, route.AllowedRoleIDs...),
			route.AllowedUserIDs...,
		) {
			if !snowflakePattern.MatchString(value) {
				return fmt.Errorf("route %q has a non-numeric Discord authorization ID", name)
			}
		}
		if len(route.RequiredTags) == 0 || len(route.RequiredHostGroupID) == 0 {
			return fmt.Errorf("route %q requires tags and host group IDs", name)
		}
		for tag, value := range route.RequiredTags {
			if strings.TrimSpace(tag) == "" || strings.TrimSpace(value) == "" {
				return fmt.Errorf("route %q has an empty required tag or value", name)
			}
		}
		for _, groupID := range route.RequiredHostGroupID {
			if !snowflakePattern.MatchString(groupID) {
				return fmt.Errorf("route %q has a non-numeric Zabbix host group ID", name)
			}
		}
	}
	if c.RequestMaxBytes < 1024 || c.RequestMaxBytes > 10<<20 {
		return errors.New("request_max_bytes must be between 1024 and 10485760")
	}
	return nil
}

func LoadSecrets() (Secrets, error) {
	credentialDir := os.Getenv("CREDENTIALS_DIRECTORY")
	if credentialDir == "" {
		credentialDir = "/run/credentials/zabbix-discord-ops.service"
	}
	read := func(envName, filename string) (string, error) {
		path := os.Getenv(envName)
		if path == "" {
			path = filepath.Join(credentialDir, filename)
		}
		value, err := ReadProtectedTextFile(path, envName, 64<<10)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("%s is empty", path)
		}
		return strings.TrimSpace(value), nil
	}

	botToken, err := read("DISCORD_BOT_TOKEN_FILE", "discord-bot-token")
	if err != nil {
		return Secrets{}, err
	}
	publicKeyHex, err := read("DISCORD_PUBLIC_KEY_FILE", "discord-public-key")
	if err != nil {
		return Secrets{}, err
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(publicKey) != 32 {
		return Secrets{}, errors.New("Discord public key must be 32-byte hex")
	}
	zabbixToken, err := read("ZABBIX_API_TOKEN_FILE", "zabbix-api-token")
	if err != nil {
		return Secrets{}, err
	}
	ingestToken, err := read("INGEST_TOKEN_FILE", "ingest-token")
	if err != nil {
		return Secrets{}, err
	}
	signingKeyText, err := read("COMPONENT_SIGNING_KEY_FILE", "component-signing-key")
	if err != nil {
		return Secrets{}, err
	}
	signingKey, err := hex.DecodeString(signingKeyText)
	if err != nil || len(signingKey) < 32 {
		return Secrets{}, errors.New("component signing key must be at least 32-byte hex")
	}
	if len(ingestToken) < 32 || len(zabbixToken) < 16 || len(botToken) < 16 {
		return Secrets{}, errors.New("one or more credentials are implausibly short")
	}
	return Secrets{
		DiscordBotToken:     botToken,
		DiscordPublicKey:    publicKey,
		ZabbixAPIToken:      zabbixToken,
		IngestToken:         ingestToken,
		ComponentSigningKey: signingKey,
	}, nil
}

func ReadProtectedTextFile(
	path, label string,
	maxBytes int64,
) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%s: inspect protected file: %w", label, err)
	}
	if !before.Mode().IsRegular() ||
		before.Mode().Perm()&0o077 != 0 ||
		before.Size() > maxBytes {
		return "", fmt.Errorf(
			"%s must be a small regular non-symlink file with mode 0600 or stricter",
			path,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: open protected file: %w", label, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("%s: inspect opened protected file: %w", label, err)
	}
	if !os.SameFile(before, opened) ||
		!opened.Mode().IsRegular() ||
		opened.Mode().Perm()&0o077 != 0 ||
		opened.Size() > maxBytes {
		return "", fmt.Errorf("%s changed while it was opened", label)
	}
	value, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s: read protected file: %w", label, err)
	}
	after, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("%s: recheck protected file: %w", label, err)
	}
	if len(value) > int(maxBytes) ||
		!os.SameFile(opened, after) ||
		!after.Mode().IsRegular() ||
		after.Mode().Perm()&0o077 != 0 ||
		opened.Size() != after.Size() ||
		!opened.ModTime().Equal(after.ModTime()) {
		return "", fmt.Errorf("%s changed while it was read", label)
	}
	return string(value), nil
}
