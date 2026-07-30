package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maiko/zabbix-discord-ops/internal/config"
	"github.com/maiko/zabbix-discord-ops/internal/discord"
	"github.com/maiko/zabbix-discord-ops/internal/zabbix"
)

type fakeDiscord struct {
	createdChannel    string
	createdPayload    any
	createdChannels   []string
	createdPayloads   []any
	createCount       int
	editedChannel     string
	editedMessage     string
	editedChannels    []string
	editedMessages    []string
	foundMessage      discord.Message
	findMessage       bool
	findCount         int
	createStarted     chan struct{}
	createRelease     chan struct{}
	createStartOnce   sync.Once
	nonceMessages     map[string]discord.Message
	botUserID         string
	interactionEdit   chan string
	interactionDelete chan struct{}
}

func (f *fakeDiscord) CurrentUser(context.Context) (discord.User, error) {
	userID := f.botUserID
	if userID == "" {
		userID = "1006"
	}
	return discord.User{ID: userID}, nil
}

func (f *fakeDiscord) CreateMessage(
	ctx context.Context,
	channelID string,
	payload any,
) (discord.Message, error) {
	messagePayload, _ := payload.(map[string]any)
	nonce, _ := messagePayload["nonce"].(string)
	enforceNonce, _ := messagePayload["enforce_nonce"].(bool)
	if enforceNonce {
		if existing, found := f.nonceMessages[nonce]; found {
			return existing, nil
		}
	}
	f.createCount++
	f.createdChannel = channelID
	f.createdPayload = payload
	f.createdChannels = append(f.createdChannels, channelID)
	f.createdPayloads = append(f.createdPayloads, payload)
	if f.createStarted != nil {
		f.createStartOnce.Do(func() { close(f.createStarted) })
	}
	if f.createRelease != nil {
		select {
		case <-f.createRelease:
		case <-ctx.Done():
			return discord.Message{}, ctx.Err()
		}
	}
	message := discord.Message{
		ID:        strconv.Itoa(2000 + f.createCount),
		ChannelID: channelID,
		Author:    discord.User{ID: "1006"},
	}
	if enforceNonce {
		f.nonceMessages[nonce] = message
	}
	return message, nil
}

func (f *fakeDiscord) FindMessageByNonce(
	_ context.Context,
	_, _ string,
	_ time.Time,
) (discord.Message, bool, error) {
	f.findCount++
	return f.foundMessage, f.findMessage, nil
}

func (f *fakeDiscord) EditMessage(
	_ context.Context,
	channelID, messageID string,
	_ any,
) error {
	f.editedChannel = channelID
	f.editedMessage = messageID
	f.editedChannels = append(f.editedChannels, channelID)
	f.editedMessages = append(f.editedMessages, messageID)
	return nil
}

func (f *fakeDiscord) EditOriginalInteraction(
	_ context.Context,
	_, _ string,
	payload any,
) error {
	content, _ := payload.(map[string]any)["content"].(string)
	if f.interactionEdit != nil {
		f.interactionEdit <- content
	}
	return nil
}

func (f *fakeDiscord) DeleteOriginalInteraction(
	_ context.Context,
	_, _ string,
) error {
	if f.interactionDelete != nil {
		f.interactionDelete <- struct{}{}
	}
	return nil
}

type fakeZabbix struct {
	problem         zabbix.Problem
	actions         []int
	actionStarted   chan struct{}
	actionRelease   chan struct{}
	actionStartOnce sync.Once
	actionErr       error
}

func (f *fakeZabbix) Version(context.Context) (string, error) {
	return "7.4.12", nil
}

func (f *fakeZabbix) Problems(context.Context, int) ([]zabbix.Problem, error) {
	return []zabbix.Problem{f.problem}, nil
}

func (f *fakeZabbix) Problem(context.Context, string) (zabbix.Problem, error) {
	return f.problem, nil
}

func (f *fakeZabbix) Acknowledge(
	ctx context.Context,
	_ string,
	action int,
	_ string,
	_ map[string]any,
) error {
	if f.actionStarted != nil {
		f.actionStartOnce.Do(func() { close(f.actionStarted) })
	}
	if f.actionRelease != nil {
		select {
		case <-f.actionRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.actions = append(f.actions, action)
	return f.actionErr
}

func testApp(t *testing.T) (*App, ed25519.PrivateKey, *fakeDiscord, *fakeZabbix) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Listen:               "127.0.0.1:9088",
		DisplayName:          "Zabbix Ops",
		PublicBaseURL:        "https://zabbix.example.test",
		ZabbixURL:            "https://zabbix.example.test/api_jsonrpc.php",
		StatePath:            filepath.Join(t.TempDir(), "correlations"),
		StateReviewAfterDays: 90,
		DiscordAPIURL:        "https://discord.com/api/v10",
		DiscordBotUserID:     "1006",
		RoutingTag:           "notification_route",
		RequestMaxBytes:      1 << 20,
		Routes: map[string]config.Route{
			"prod": {
				GuildID:             "1001",
				ChannelID:           "1002",
				RequiredTags:        map[string]string{"tenant": "example"},
				RequiredHostGroupID: []string{"1003"},
				AllowedRoleIDs:      []string{"1004"},
			},
		},
	}
	secrets := config.Secrets{
		DiscordBotToken:     "discord-bot-token-long-enough",
		DiscordPublicKey:    publicKey,
		ZabbixAPIToken:      "zabbix-api-token-long-enough",
		IngestToken:         "0123456789abcdef0123456789abcdef",
		ComponentSigningKey: []byte("0123456789abcdef0123456789abcdef"),
	}
	application, err := New(cfg, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	application.now = func() time.Time { return now }
	application.successMessageTTL = 0
	discordClient := &fakeDiscord{
		interactionEdit:   make(chan string, 4),
		interactionDelete: make(chan struct{}, 4),
		nonceMessages:     map[string]discord.Message{},
	}
	zabbixClient := &fakeZabbix{
		problem: zabbix.Problem{
			EventID:  "101",
			ObjectID: "trigger-1",
			Name:     "Service unavailable",
			Severity: "4",
			Tags: []zabbix.Tag{
				{Tag: "notification_route", Value: "prod"},
				{Tag: "tenant", Value: "example"},
			},
			HostGroups: []zabbix.HostGroup{{GroupID: "1003", Name: "Tenants/Example"}},
		},
	}
	application.discord = discordClient
	application.zabbix = zabbixClient
	return application, privateKey, discordClient, zabbixClient
}

func TestSignedPingAndReplay(t *testing.T) {
	application, privateKey, _, _ := testApp(t)
	body := []byte(`{"type":1}`)
	timestamp := strconv.FormatInt(application.now().Unix(), 10)
	signature := hex.EncodeToString(ed25519.Sign(privateKey, append([]byte(timestamp), body...)))
	request := httptest.NewRequest(http.MethodPost, "/discord/interactions", bytes.NewReader(body))
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", signature)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"type":1`)) {
		t.Fatalf("unexpected ping response: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/discord/interactions", bytes.NewReader(body))
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", signature)
	response = httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("expected replay conflict, got %d", response.Code)
	}
}

func TestDiscordIdentityMustMatchConfiguredBot(t *testing.T) {
	application, _, discordClient, _ := testApp(t)
	if err := application.ValidateDiscordIdentity(context.Background()); err != nil {
		t.Fatalf("matching identity rejected: %v", err)
	}
	discordClient.botUserID = "9999"
	if err := application.ValidateDiscordIdentity(context.Background()); err == nil {
		t.Fatal("mismatched bot identity was accepted")
	}
}

func TestIngestCreatesCorrelatedMessage(t *testing.T) {
	application, _, discordClient, _ := testApp(t)
	event := IngestEvent{
		EventID:  "101",
		Status:   "PROBLEM",
		Severity: 4,
		Name:     "Service unavailable",
		Host:     "service.example.test",
		Clock:    application.now().Unix(),
		Tags: []zabbix.Tag{
			{Tag: "notification_route", Value: "prod"},
			{Tag: "tenant", Value: "example"},
			{Tag: "Application", Value: "Apache"},
			{Tag: "Application", Value: "Plesk"},
		},
	}
	body, _ := json.Marshal(event)
	request := httptest.NewRequest(http.MethodPost, "/v1/zabbix/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected ingest response: %d %s", response.Code, response.Body.String())
	}
	if discordClient.createdChannel != "1002" {
		t.Fatalf("message routed to %q", discordClient.createdChannel)
	}
	var result struct {
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Tags["zbx_discord_ops_message_id"] != "2001" ||
		result.Tags["zbx_discord_ops_channel_id"] != "1002" ||
		result.Tags["zbx_discord_ops_route"] != "prod" {
		t.Fatalf("unexpected correlation tags: %#v", result.Tags)
	}
	payload := discordClient.createdPayload.(map[string]any)
	if payload["nonce"] != "101" || payload["enforce_nonce"] != true {
		t.Fatalf("message creation is not idempotent: %#v", payload)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/zabbix/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response = httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || discordClient.createCount != 1 {
		t.Fatalf(
			"durable retry created another message: status=%d creates=%d",
			response.Code,
			discordClient.createCount,
		)
	}
}

func TestIngestMirrorsProblemAndRecoveryWithoutInteractiveComponents(t *testing.T) {
	application, _, discordClient, _ := testApp(t)
	route := application.cfg.Routes["prod"]
	route.MirrorChannelIDs = []string{"1007"}
	application.cfg.Routes["prod"] = route

	problem := IngestEvent{
		EventID:  "101",
		Status:   "PROBLEM",
		Severity: 4,
		Name:     "Service unavailable",
		Host:     "service.example.test",
		Clock:    application.now().Unix(),
		Tags: []zabbix.Tag{
			{Tag: "notification_route", Value: "prod"},
			{Tag: "tenant", Value: "example"},
		},
	}
	body, _ := json.Marshal(problem)
	request := httptest.NewRequest(http.MethodPost, "/v1/zabbix/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("problem ingest failed: %d %s", response.Code, response.Body.String())
	}
	if fmt.Sprint(discordClient.createdChannels) != "[1002 1007]" {
		t.Fatalf("unexpected problem destinations: %#v", discordClient.createdChannels)
	}
	primary := discordClient.createdPayloads[0].(map[string]any)
	mirror := discordClient.createdPayloads[1].(map[string]any)
	if len(primary["components"].([]any)) == 0 ||
		len(mirror["components"].([]any)) != 0 {
		t.Fatal("mirror did not remove interactive components")
	}
	if primary["nonce"] == mirror["nonce"] ||
		mirror["nonce"] != mirrorNonce(problem.EventID, "1007") {
		t.Fatalf(
			"mirror nonce is not destination-specific: primary=%v mirror=%v",
			primary["nonce"],
			mirror["nonce"],
		)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"zbx_discord_ops_message_id":"2001"`)) {
		t.Fatalf("primary correlation was not returned: %s", response.Body.String())
	}

	update := problem
	update.Status = "UPDATE"
	update.Tags = append(update.Tags,
		zabbix.Tag{Tag: "zbx_discord_ops_message_id", Value: "2001"},
		zabbix.Tag{Tag: "zbx_discord_ops_channel_id", Value: "1002"},
		zabbix.Tag{Tag: "zbx_discord_ops_route", Value: "prod"},
	)
	body, _ = json.Marshal(update)
	request = httptest.NewRequest(http.MethodPost, "/v1/zabbix/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response = httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update ingest failed: %d %s", response.Code, response.Body.String())
	}
	if fmt.Sprint(discordClient.editedChannels) != "[1002 1007]" ||
		fmt.Sprint(discordClient.editedMessages) != "[2001 2002]" {
		t.Fatalf(
			"unexpected update destinations: channels=%#v messages=%#v",
			discordClient.editedChannels,
			discordClient.editedMessages,
		)
	}

	route = application.cfg.Routes["prod"]
	route.MirrorChannelIDs = nil
	application.cfg.Routes["prod"] = route
	discordClient.editedChannels = nil
	discordClient.editedMessages = nil
	recovery := update
	recovery.Status = "RESOLVED"
	body, _ = json.Marshal(recovery)
	request = httptest.NewRequest(http.MethodPost, "/v1/zabbix/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response = httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("recovery ingest failed: %d %s", response.Code, response.Body.String())
	}
	if fmt.Sprint(discordClient.editedChannels) != "[1002]" ||
		fmt.Sprint(discordClient.editedMessages) != "[2001]" {
		t.Fatalf(
			"removed mirror received recovery: channels=%#v messages=%#v",
			discordClient.editedChannels,
			discordClient.editedMessages,
		)
	}
}

func TestIngestReconcilesDurablePendingMessage(t *testing.T) {
	application, _, discordClient, _ := testApp(t)
	event := IngestEvent{
		EventID:  "101",
		Status:   "PROBLEM",
		Severity: 4,
		Name:     "Service unavailable",
		Host:     "service.example.test",
		Tags: []zabbix.Tag{
			{Tag: "notification_route", Value: "prod"},
			{Tag: "tenant", Value: "example"},
		},
	}
	if _, _, err := application.correlations.Begin(
		event.EventID,
		"prod",
		"1002",
		application.now(),
	); err != nil {
		t.Fatal(err)
	}
	discordClient.findMessage = true
	discordClient.foundMessage = discord.Message{
		ID:        "2999",
		ChannelID: "1002",
		Author:    discord.User{ID: "1006"},
	}

	body, _ := json.Marshal(event)
	request := httptest.NewRequest(http.MethodPost, "/v1/zabbix/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		discordClient.findCount != 1 ||
		discordClient.createCount != 0 {
		t.Fatalf(
			"pending message was not reconciled: status=%d finds=%d creates=%d body=%s",
			response.Code,
			discordClient.findCount,
			discordClient.createCount,
			response.Body.String(),
		)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"2999"`)) {
		t.Fatalf("reconciled message ID missing from response: %s", response.Body.String())
	}
}

func TestIngestRejectsAmbiguousTagsInBothOrders(t *testing.T) {
	for _, values := range [][2]string{{"prod", "other"}, {"other", "prod"}} {
		t.Run(values[0]+"-then-"+values[1], func(t *testing.T) {
			application, _, discordClient, _ := testApp(t)
			event := IngestEvent{
				EventID:  "101",
				Status:   "PROBLEM",
				Severity: 4,
				Name:     "Service unavailable",
				Host:     "service.example.test",
				Tags: []zabbix.Tag{
					{Tag: "notification_route", Value: values[0]},
					{Tag: "notification_route", Value: values[1]},
					{Tag: "tenant", Value: "example"},
				},
			}
			body, _ := json.Marshal(event)
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/zabbix/events",
				bytes.NewReader(body),
			)
			request.Header.Set("Authorization", "Bearer "+application.ingestToken)
			response := httptest.NewRecorder()
			application.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusUnprocessableEntity || discordClient.createCount != 0 {
				t.Fatalf(
					"ambiguous tags were accepted: status=%d creates=%d",
					response.Code,
					discordClient.createCount,
				)
			}
		})
	}
}

func TestIngestRejectsAmbiguousCorrelationTagsInBothOrders(t *testing.T) {
	for _, values := range [][2]string{{"2001", "2002"}, {"2002", "2001"}} {
		t.Run(values[0]+"-then-"+values[1], func(t *testing.T) {
			application, _, discordClient, _ := testApp(t)
			event := IngestEvent{
				EventID:  "101",
				Status:   "RESOLVED",
				Severity: 4,
				Name:     "Service unavailable",
				Host:     "service.example.test",
				Tags: []zabbix.Tag{
					{Tag: "notification_route", Value: "prod"},
					{Tag: "tenant", Value: "example"},
					{Tag: "zbx_discord_ops_message_id", Value: values[0]},
					{Tag: "zbx_discord_ops_message_id", Value: values[1]},
					{Tag: "zbx_discord_ops_channel_id", Value: "1002"},
					{Tag: "zbx_discord_ops_route", Value: "prod"},
				},
			}
			body, _ := json.Marshal(event)
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/zabbix/events",
				bytes.NewReader(body),
			)
			request.Header.Set("Authorization", "Bearer "+application.ingestToken)
			response := httptest.NewRecorder()
			application.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusUnprocessableEntity ||
				discordClient.editedMessage != "" {
				t.Fatalf(
					"ambiguous correlation tags were accepted: status=%d edit=%q",
					response.Code,
					discordClient.editedMessage,
				)
			}
		})
	}
}

func TestInteractionRevalidatesTenantAndHostGroup(t *testing.T) {
	application, privateKey, discordClient, zabbixClient := testApp(t)
	zabbixClient.actionStarted = make(chan struct{})
	zabbixClient.actionRelease = make(chan struct{})
	customID, err := application.signer.Sign(discord.ComponentToken{
		Action:  "ack",
		EventID: "101",
		Route:   "prod",
		Expires: application.now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	interaction := discord.Interaction{
		ID:            "interaction-1",
		ApplicationID: "1006",
		Type:          interactionComponent,
		Token:         "interaction-token-1",
		GuildID:       "1001",
		ChannelID:     "1002",
		Data:          discord.InteractionData{CustomID: customID},
		Member: discord.Member{
			User:  discord.User{ID: "1005", Username: "operator"},
			Roles: []string{"1004"},
		},
	}
	body, _ := json.Marshal(interaction)
	timestamp := strconv.FormatInt(application.now().Unix(), 10)
	signature := hex.EncodeToString(ed25519.Sign(privateKey, append([]byte(timestamp), body...)))
	request := httptest.NewRequest(http.MethodPost, "/discord/interactions", bytes.NewReader(body))
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", signature)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	select {
	case <-zabbixClient.actionStarted:
	case <-time.After(time.Second):
		t.Fatal("deferred Zabbix action did not start")
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"type":5`)) {
		t.Fatalf("interaction was not deferred: %s", response.Body.String())
	}
	close(zabbixClient.actionRelease)
	result := <-discordClient.interactionEdit
	<-discordClient.interactionDelete
	if response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"type":5`)) ||
		result != "Zabbix accepted the action." ||
		len(zabbixClient.actions) != 1 {
		t.Fatalf("authorized action failed: %d %s", response.Code, response.Body.String())
	}

	zabbixClient.problem.Tags[1].Value = "other"
	interaction.ID = "interaction-2"
	interaction.Token = "interaction-token-2"
	body, _ = json.Marshal(interaction)
	timestamp = strconv.FormatInt(application.now().Add(time.Second).Unix(), 10)
	signature = hex.EncodeToString(ed25519.Sign(privateKey, append([]byte(timestamp), body...)))
	request = httptest.NewRequest(http.MethodPost, "/discord/interactions", bytes.NewReader(body))
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", signature)
	response = httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	result = <-discordClient.interactionEdit
	if result != "Action rejected. The event or tenant authorization no longer matches." {
		t.Fatalf("unexpected rejected action response: %q", result)
	}
	if len(zabbixClient.actions) != 1 {
		t.Fatal("tenant mismatch still reached Zabbix action")
	}
}

func TestDeferredMutationReportsUnknownOutcomeAndDrains(t *testing.T) {
	application, privateKey, discordClient, zabbixClient := testApp(t)
	zabbixClient.actionErr = zabbix.ErrMutationOutcomeUnknown
	customID, err := application.signer.Sign(discord.ComponentToken{
		Action:  "ack",
		EventID: "101",
		Route:   "prod",
		Expires: application.now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	interaction := discord.Interaction{
		ID:            "interaction-unknown",
		ApplicationID: "1006",
		Type:          interactionComponent,
		Token:         "interaction-token-unknown",
		GuildID:       "1001",
		ChannelID:     "1002",
		Data:          discord.InteractionData{CustomID: customID},
		Member: discord.Member{
			User:  discord.User{ID: "1005", Username: "operator"},
			Roles: []string{"1004"},
		},
	}
	body, _ := json.Marshal(interaction)
	timestamp := strconv.FormatInt(application.now().Unix(), 10)
	signature := hex.EncodeToString(
		ed25519.Sign(privateKey, append([]byte(timestamp), body...)),
	)
	request := httptest.NewRequest(
		http.MethodPost,
		"/discord/interactions",
		bytes.NewReader(body),
	)
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", signature)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)

	waitContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := application.WaitForDeferred(waitContext); err != nil {
		t.Fatalf("drain deferred interaction: %v", err)
	}
	result := <-discordClient.interactionEdit
	if response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"type":5`)) ||
		result != "Zabbix did not confirm the final result. The action may have been applied; check the live event before retrying." {
		t.Fatalf("unexpected unknown-outcome response: %d %s result=%q", response.Code, response.Body, result)
	}
}

func TestInteractionRejectsAmbiguousLiveTagsInBothOrders(t *testing.T) {
	for index, values := range [][2]string{{"example", "other"}, {"other", "example"}} {
		t.Run(values[0]+"-then-"+values[1], func(t *testing.T) {
			application, privateKey, discordClient, zabbixClient := testApp(t)
			zabbixClient.problem.Tags = []zabbix.Tag{
				{Tag: "notification_route", Value: "prod"},
				{Tag: "tenant", Value: values[0]},
				{Tag: "tenant", Value: values[1]},
			}
			customID, err := application.signer.Sign(discord.ComponentToken{
				Action:  "ack",
				EventID: "101",
				Route:   "prod",
				Expires: application.now().Add(time.Minute).Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			interaction := discord.Interaction{
				ID:            strconv.Itoa(index + 4001),
				ApplicationID: "1006",
				Type:          interactionComponent,
				Token:         "interaction-token-ambiguous",
				GuildID:       "1001",
				ChannelID:     "1002",
				Data:          discord.InteractionData{CustomID: customID},
				Member: discord.Member{
					User:  discord.User{ID: "1005", Username: "operator"},
					Roles: []string{"1004"},
				},
			}
			body, _ := json.Marshal(interaction)
			timestamp := strconv.FormatInt(application.now().Unix(), 10)
			signature := hex.EncodeToString(
				ed25519.Sign(privateKey, append([]byte(timestamp), body...)),
			)
			request := httptest.NewRequest(
				http.MethodPost,
				"/discord/interactions",
				bytes.NewReader(body),
			)
			request.Header.Set("X-Signature-Timestamp", timestamp)
			request.Header.Set("X-Signature-Ed25519", signature)
			response := httptest.NewRecorder()
			application.Handler().ServeHTTP(response, request)
			result := <-discordClient.interactionEdit
			if response.Code != http.StatusOK || len(zabbixClient.actions) != 0 {
				t.Fatalf(
					"ambiguous live tags reached Zabbix: status=%d actions=%d",
					response.Code,
					len(zabbixClient.actions),
				)
			}
			if result != "Action rejected. The event or tenant authorization no longer matches." {
				t.Fatalf("unexpected ambiguous-tag response: %q", result)
			}
		})
	}
}

func TestEventMessageRejectsExternalURL(t *testing.T) {
	application, _, _, _ := testApp(t)
	_, err := application.eventMessage(IngestEvent{
		EventID:  "101",
		Status:   "PROBLEM",
		Severity: 4,
		Name:     "Service unavailable",
		Host:     "service.example.test",
		URL:      "https://attacker.example/phishing",
	}, "prod", false)
	if err == nil {
		t.Fatal("expected an external event URL to be rejected")
	}
}

func TestSuppressedProblemMintsWorkingUnsuppressAction(t *testing.T) {
	application, privateKey, discordClient, zabbixClient := testApp(t)
	zabbixClient.problem.Suppressed = "1"
	payload, err := application.eventMessage(
		IngestEvent{
			EventID:  "101",
			Status:   "PROBLEM",
			Severity: 4,
			Name:     "Service unavailable",
			Host:     "service.example.test",
		},
		"prod",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	rows := payload["components"].([]any)
	buttons := rows[0].(map[string]any)["components"].([]any)
	customID := ""
	for _, raw := range buttons {
		candidate := raw.(map[string]any)
		if candidate["label"] == "Unsuppress" {
			customID = candidate["custom_id"].(string)
			break
		}
	}
	if customID == "" {
		t.Fatal("suppressed problem did not mint an Unsuppress component")
	}

	interaction := discord.Interaction{
		ID:            "3001",
		ApplicationID: "1006",
		Type:          interactionComponent,
		Token:         "interaction-token-3001",
		GuildID:       "1001",
		ChannelID:     "1002",
		Data:          discord.InteractionData{CustomID: customID},
		Member: discord.Member{
			User:  discord.User{ID: "1005", Username: "operator"},
			Roles: []string{"1004"},
		},
	}
	body, _ := json.Marshal(interaction)
	timestamp := strconv.FormatInt(application.now().Unix(), 10)
	signature := hex.EncodeToString(
		ed25519.Sign(privateKey, append([]byte(timestamp), body...)),
	)
	request := httptest.NewRequest(
		http.MethodPost,
		"/discord/interactions",
		bytes.NewReader(body),
	)
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", signature)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	result := <-discordClient.interactionEdit
	if response.Code != http.StatusOK {
		t.Fatalf("unsuppress interaction failed: %d %s", response.Code, response.Body.String())
	}
	if result != "Zabbix accepted the action." {
		t.Fatalf("unexpected unsuppress response: %q", result)
	}
	want := zabbix.ActionUnsuppress | zabbix.ActionMessage
	if len(zabbixClient.actions) != 1 || zabbixClient.actions[0] != want {
		t.Fatalf("got actions %#v, want %d", zabbixClient.actions, want)
	}
}

func TestIngestRejectsNonNumericEventID(t *testing.T) {
	event := IngestEvent{
		EventID:  "101/../../users/@me",
		Status:   "PROBLEM",
		Severity: 4,
		Name:     "Service unavailable",
		Host:     "service.example.test",
	}
	if err := validateIngestEvent(event); err == nil {
		t.Fatal("expected non-numeric event ID rejection")
	}
}

func TestIngestDeadlineInterruptsSlowRequestBody(t *testing.T) {
	application, _, _, _ := testApp(t)
	application.ingestTimeout = 50 * time.Millisecond
	server := httptest.NewServer(application.Handler())
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(
		connection,
		"POST /v1/zabbix/events HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: Bearer %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: 100\r\n"+
			"Connection: close\r\n\r\n{",
		parsed.Host,
		application.ingestToken,
	); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatalf("slow-body request did not receive a response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("slow-body request returned HTTP %d", response.StatusCode)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("slow-body deadline took %s", elapsed)
	}
}

func TestSecondIngestDeadlineWhileSameEventIsBlocked(t *testing.T) {
	application, _, discordClient, _ := testApp(t)
	application.ingestTimeout = 2 * time.Second
	discordClient.createStarted = make(chan struct{})
	discordClient.createRelease = make(chan struct{})
	event := IngestEvent{
		EventID:  "101",
		Status:   "PROBLEM",
		Severity: 4,
		Name:     "Service unavailable",
		Host:     "service.example.test",
		Tags: []zabbix.Tag{
			{Tag: "notification_route", Value: "prod"},
			{Tag: "tenant", Value: "example"},
		},
	}
	body, _ := json.Marshal(event)
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/zabbix/events",
			bytes.NewReader(body),
		)
		request.Header.Set("Authorization", "Bearer "+application.ingestToken)
		response := httptest.NewRecorder()
		application.Handler().ServeHTTP(response, request)
		firstDone <- response
	}()
	select {
	case <-discordClient.createStarted:
	case <-time.After(time.Second):
		t.Fatal("first ingest did not reach Discord")
	}

	application.ingestTimeout = 50 * time.Millisecond
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/zabbix/events",
		bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+application.ingestToken)
	response := httptest.NewRecorder()
	started := time.Now()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("queued ingest returned HTTP %d: %s", response.Code, response.Body.String())
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("queued ingest ignored deadline for %s", elapsed)
	}

	close(discordClient.createRelease)
	select {
	case first := <-firstDone:
		if first.Code != http.StatusOK {
			t.Fatalf("first ingest failed: %d %s", first.Code, first.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("first ingest did not finish")
	}
}
