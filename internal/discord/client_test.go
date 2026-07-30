package discord

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRejectsNonNumericPathIDs(t *testing.T) {
	client := NewClient("https://discord.example.test/api/v10", "test-token", "1006")
	if _, err := client.CreateMessage(
		context.Background(),
		"1002/../../users/@me",
		map[string]any{},
	); err == nil {
		t.Fatal("expected invalid channel ID rejection")
	}
	if err := client.EditMessage(
		context.Background(),
		"1002",
		"2001?thread_id=attacker",
		map[string]any{},
	); err == nil {
		t.Fatal("expected invalid message ID rejection")
	}
}

func TestClientHonorsInboundContextDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	client := NewClient(server.URL, "test-token", "1006")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := client.CreateMessage(ctx, "1002", map[string]any{})
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("request ignored context for %s", elapsed)
	}
}

func TestClientReadsCurrentBotIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodGet || request.URL.Path != "/users/@me" {
			t.Fatalf("unexpected identity request: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bot test-token" {
			t.Fatal("identity request omitted bot authorization")
		}
		_, _ = response.Write([]byte(`{"id":"1006","username":"zabbix-ops"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", "1006")
	user, err := client.CurrentUser(context.Background())
	if err != nil || user.ID != "1006" {
		t.Fatalf("unexpected bot identity: %#v err=%v", user, err)
	}
}

func TestClientEditsDeferredInteractionWithoutBotAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPatch ||
			request.URL.Path != "/webhooks/1006/interaction-token/messages/@original" {
			t.Fatalf("unexpected interaction edit: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("interaction webhook request included bot authorization")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"id":"2001"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", "1006")
	err := client.EditOriginalInteraction(
		context.Background(),
		"1006",
		"interaction-token",
		map[string]any{"content": "accepted"},
	)
	if err != nil {
		t.Fatalf("edit original interaction: %v", err)
	}
}

func TestClientDeletesDeferredInteractionWithoutBotAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodDelete ||
			request.URL.Path != "/webhooks/1006/interaction-token/messages/@original" {
			t.Fatalf("unexpected interaction delete: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("interaction webhook request included bot authorization")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", "1006")
	if err := client.DeleteOriginalInteraction(
		context.Background(),
		"1006",
		"interaction-token",
	); err != nil {
		t.Fatalf("delete original interaction: %v", err)
	}
}

func TestClientEditsChannelMessageWithBotAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPatch ||
			request.URL.Path != "/channels/1002/messages/2001" {
			t.Fatalf("unexpected channel edit: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bot test-token" {
			t.Fatal("channel edit omitted bot authorization")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", "1006")
	if err := client.EditMessage(
		context.Background(),
		"1002",
		"2001",
		map[string]any{"content": "updated"},
	); err != nil {
		t.Fatalf("edit channel message: %v", err)
	}
}

func TestClientReconcilesMessageByStringOrNumericNonce(t *testing.T) {
	for _, nonce := range []string{`"101"`, `101`} {
		t.Run(nonce, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(
				response http.ResponseWriter,
				request *http.Request,
			) {
				if request.Method != http.MethodGet ||
					request.URL.Path != "/channels/1002/messages" ||
					request.URL.Query().Get("limit") != "100" {
					t.Fatalf("unexpected reconciliation request: %s %s", request.Method, request.URL)
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(response, `[{
					"id":"2002",
					"channel_id":"1002",
					"nonce":%s,
					"timestamp":"2027-01-15T08:00:02Z",
					"author":{"id":"9999"}
				},{
					"id":"2001",
					"channel_id":"1002",
					"nonce":%s,
					"timestamp":"2027-01-15T08:00:01Z",
					"author":{"id":"1006"}
				}]`, nonce, nonce)
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token", "1006")
			message, found, err := client.FindMessageByNonce(
				context.Background(),
				"1002",
				"101",
				time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC),
			)
			if err != nil || !found || message.ID != "2001" {
				t.Fatalf("message was not reconciled: %#v found=%v err=%v", message, found, err)
			}
		})
	}
}

func TestClientPaginatesPendingCorrelationHistory(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			messages := make([]Message, 100)
			for index := range messages {
				messages[index] = Message{
					ID:        fmt.Sprintf("%d", 3000-index),
					ChannelID: "1002",
					Nonce:     json.RawMessage(fmt.Sprintf("%d", 9000+index)),
					Timestamp: "2027-01-15T08:00:02Z",
					Author:    User{ID: "1006"},
				}
			}
			_ = json.NewEncoder(response).Encode(messages)
			return
		}
		if request.URL.Query().Get("before") != "2901" {
			t.Fatalf("unexpected pagination cursor: %s", request.URL.RawQuery)
		}
		_, _ = response.Write([]byte(`[{
			"id":"2001",
			"channel_id":"1002",
			"nonce":"101",
			"timestamp":"2027-01-15T08:00:01Z",
			"author":{"id":"1006"}
		}]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", "1006")
	message, found, err := client.FindMessageByNonce(
		context.Background(),
		"1002",
		"101",
		time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC),
	)
	if err != nil || !found || message.ID != "2001" || requests != 2 {
		t.Fatalf(
			"paginated reconciliation failed: %#v found=%v requests=%d err=%v",
			message,
			found,
			requests,
			err,
		)
	}
}
