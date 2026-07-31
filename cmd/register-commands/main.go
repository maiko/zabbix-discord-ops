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
	Name                     string            `json:"name"`
	Description              string            `json:"description"`
	DescriptionLocalizations map[string]string `json:"description_localizations,omitempty"`
	DMEnabled                bool              `json:"dm_permission"`
	DefaultMemberPermissions string            `json:"default_member_permissions,omitempty"`
	Options                  []option          `json:"options"`
}

type option struct {
	Type                     int               `json:"type"`
	Name                     string            `json:"name"`
	Description              string            `json:"description"`
	DescriptionLocalizations map[string]string `json:"description_localizations,omitempty"`
	Required                 bool              `json:"required,omitempty"`
	Autocomplete             bool              `json:"autocomplete,omitempty"`
	Choices                  []choice          `json:"choices,omitempty"`
	Options                  []option          `json:"options,omitempty"`
}

type choice struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
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
	commandSpec := command{
		Name:                     "zabbix",
		Description:              "Inspect and operate authorized Zabbix resources",
		DescriptionLocalizations: map[string]string{"fr": "Inspecter et gérer les ressources Zabbix autorisées"},
		DMEnabled:                false,
		DefaultMemberPermissions: "0",
		Options: []option{
			{Type: 1, Name: "status", Description: "Check Zabbix reachability and routed problem count"},
			{Type: 1, Name: "whoami", Description: "Show your effective Zabbix Ops authorization"},
			{Type: 1, Name: "host", Description: "Inspect an authorized host", Options: []option{
				{Type: 3, Name: "host", Description: "Host", Required: true, Autocomplete: true},
			}},
			{Type: 1, Name: "problem", Description: "Inspect an authorized open problem", Options: []option{
				{Type: 3, Name: "event", Description: "Event", Required: true, Autocomplete: true},
			}},
			{Type: 1, Name: "problems", Description: "List routed open problems", Options: []option{
				{Type: 3, Name: "host", Description: "Optional host filter", Autocomplete: true},
				{Type: 4, Name: "severity", Description: "Minimum severity", Choices: severityChoices()},
			}},
			{Type: 2, Name: "downtime", Description: "Manage Zabbix maintenance windows", Options: []option{
				{Type: 1, Name: "start", Description: "Schedule host downtime", Options: []option{
					{Type: 3, Name: "host", Description: "Host", Required: true, Autocomplete: true},
					{Type: 3, Name: "duration", Description: "Duration (for example 15m or 2h)", Required: true, Autocomplete: true},
					{Type: 3, Name: "starts_in", Description: "Delay before start (for example 30m)", Autocomplete: true},
					{Type: 3, Name: "reason", Description: "Reason, up to 300 characters"},
				}},
				{Type: 1, Name: "list", Description: "List authorized maintenance windows", Options: []option{
					{Type: 3, Name: "host", Description: "Optional host filter", Autocomplete: true},
					{Type: 3, Name: "state", Description: "Optional state filter", Choices: []choice{
						{Name: "Scheduled", Value: "scheduled"}, {Name: "Active", Value: "active"},
						{Name: "Ended", Value: "ended"},
					}},
				}},
				{Type: 1, Name: "extend", Description: "Extend a maintenance window", Options: maintenanceMutationOptions(true)},
				{Type: 1, Name: "end", Description: "End an active maintenance window", Options: maintenanceMutationOptions(false)},
				{Type: 1, Name: "cancel", Description: "Cancel a future maintenance window", Options: maintenanceMutationOptions(false)},
			}},
		},
	}
	localizeOptions(commandSpec.Options)
	body, err := json.Marshal(commandSpec)
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

func localizeOptions(options []option) {
	translations := map[string]string{
		"status":      "Vérifier Zabbix et le nombre de problèmes autorisés",
		"whoami":      "Afficher vos autorisations Zabbix Ops effectives",
		"host":        "Hôte autorisé",
		"problem":     "Inspecter un problème ouvert autorisé",
		"event":       "Événement Zabbix",
		"problems":    "Lister les problèmes ouverts autorisés",
		"severity":    "Sévérité minimale",
		"downtime":    "Gérer les fenêtres de maintenance Zabbix",
		"start":       "Planifier une indisponibilité pour un hôte",
		"duration":    "Durée, par exemple 15m ou 2h",
		"starts_in":   "Délai avant le début, par exemple 30m",
		"reason":      "Motif, 300 caractères maximum",
		"list":        "Lister les fenêtres de maintenance autorisées",
		"state":       "Filtre d’état facultatif",
		"extend":      "Prolonger une fenêtre de maintenance",
		"maintenance": "Fenêtre de maintenance",
		"end":         "Terminer une maintenance active",
		"cancel":      "Annuler une maintenance future",
	}
	for index := range options {
		if translated, ok := translations[options[index].Name]; ok {
			options[index].DescriptionLocalizations = map[string]string{
				"fr": translated,
			}
		}
		localizeOptions(options[index].Options)
	}
}

func severityChoices() []choice {
	names := []string{"Not classified", "Information", "Warning", "Average", "High", "Disaster"}
	result := make([]choice, 0, len(names))
	for value, name := range names {
		result = append(result, choice{Name: name, Value: value})
	}
	return result
}

func maintenanceMutationOptions(withDuration bool) []option {
	result := []option{{
		Type: 3, Name: "maintenance", Description: "Maintenance window",
		Required: true, Autocomplete: true,
	}}
	if withDuration {
		result = append(result, option{
			Type: 3, Name: "duration", Description: "Additional duration",
			Required: true, Autocomplete: true,
		})
	}
	return append(result, option{Type: 3, Name: "reason", Description: "Reason, up to 300 characters"})
}

func isSnowflake(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}
