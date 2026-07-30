package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRequiresLoopbackAndExplicitAuthorization(t *testing.T) {
	cfg := Config{
		Listen:               "0.0.0.0:9088",
		DisplayName:          "Zabbix Ops",
		PublicBaseURL:        "https://zabbix.example.test",
		ZabbixURL:            "https://zabbix.example.test/api_jsonrpc.php",
		StatePath:            "/var/lib/zabbix-discord-ops/correlations",
		StateReviewAfterDays: 90,
		DiscordBotUserID:     "5",
		DiscordAPIURL:        "https://discord.com/api/v10",
		RoutingTag:           "notification_route",
		RequestMaxBytes:      1 << 20,
		Routes: map[string]Route{
			"prod": {
				GuildID:   "1",
				ChannelID: "2",
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-loopback listen rejection")
	}
	cfg.Listen = "127.0.0.1:9088"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing route authorization rejection")
	}
	cfg.Routes["prod"] = Route{
		GuildID:             "1",
		ChannelID:           "2",
		AllowedRoleIDs:      []string{"3"},
		RequiredTags:        map[string]string{"tenant": "example"},
		RequiredHostGroupID: []string{"4"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	route := cfg.Routes["prod"]
	route.MirrorChannelIDs = []string{"2"}
	cfg.Routes["prod"] = route
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate primary and mirror channel rejection")
	}
}

func TestReadProtectedTextFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "credential")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedTextFile(link, "test credential", 1024); err == nil {
		t.Fatal("expected symlink credential rejection")
	}
}
