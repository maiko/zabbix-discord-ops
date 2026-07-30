package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maiko/zabbix-discord-ops/internal/config"
)

type command struct {
	Name                     string   `json:"name"`
	Description              string   `json:"description"`
	DMEnabled                bool     `json:"dm_permission"`
	DefaultMemberPermissions string   `json:"default_member_permissions,omitempty"`
	Options                  []option `json:"options"`
}

type option struct {
	Type        int    `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func main() {
	applicationID := flag.String("application-id", "", "Discord application ID")
	guildID := flag.String("guild-id", "", "optional guild ID for immediate guild registration")
	tokenFile := flag.String("token-file", "", "path to the Discord bot token file")
	apiURL := flag.String("discord-api-url", "https://discord.com/api/v10", "Discord API base URL")
	flag.Parse()

	if err := run(*applicationID, *guildID, *tokenFile, *apiURL); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(applicationID, guildID, tokenFile, apiURL string) error {
	if !isSnowflake(applicationID) {
		return errors.New("application-id must be a Discord snowflake")
	}
	if guildID != "" && !isSnowflake(guildID) {
		return errors.New("guild-id must be a Discord snowflake")
	}
	parsedAPIURL, err := url.Parse(apiURL)
	if err != nil ||
		parsedAPIURL.Scheme != "https" ||
		parsedAPIURL.Host == "" ||
		parsedAPIURL.User != nil ||
		parsedAPIURL.RawQuery != "" ||
		parsedAPIURL.Fragment != "" {
		return errors.New("discord-api-url must be an absolute HTTPS URL")
	}
	if tokenFile == "" {
		return errors.New("token-file is required")
	}
	tokenText, err := config.ReadProtectedTextFile(tokenFile, "bot token", 64<<10)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(tokenText)
	if len(token) < 16 {
		return errors.New("bot token is implausibly short")
	}

	endpoint := strings.TrimRight(apiURL, "/") + "/applications/" + applicationID
	if guildID == "" {
		endpoint += "/commands"
	} else {
		endpoint += "/guilds/" + guildID + "/commands"
	}
	body, err := json.Marshal(command{
		Name:                     "zabbix",
		Description:              "Inspect tenant-authorized Zabbix state",
		DMEnabled:                false,
		DefaultMemberPermissions: "0",
		Options: []option{
			{Type: 1, Name: "status", Description: "Check Zabbix reachability and routed problem count"},
			{Type: 1, Name: "problems", Description: "List routed open problems"},
		},
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bot "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "zabbix-discord-ops-command-registration")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("Discord command registration: %w", err)
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf(
			"Discord command registration returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}
	_, _ = fmt.Fprintln(os.Stdout, "registered /zabbix command")
	return nil
}

func isSnowflake(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}
