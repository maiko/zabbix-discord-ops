package discord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	baseURL   string
	token     string
	botUserID string
	http      *http.Client
}

type Message struct {
	ID        string          `json:"id"`
	ChannelID string          `json:"channel_id"`
	Nonce     json.RawMessage `json:"nonce"`
	Timestamp string          `json:"timestamp"`
	Author    User            `json:"author"`
}

func NewClient(baseURL, token, botUserID string) *Client {
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		token:     token,
		botUserID: botUserID,
		http: &http.Client{
			Timeout: 8 * time.Second,
		},
	}
}

func (c *Client) CreateMessage(
	ctx context.Context,
	channelID string,
	payload any,
) (Message, error) {
	var result Message
	if !isDecimal(channelID) {
		return result, errors.New("invalid Discord channel ID")
	}
	err := c.request(
		ctx,
		http.MethodPost,
		"/channels/"+channelID+"/messages",
		payload,
		&result,
	)
	return result, err
}

func (c *Client) CurrentUser(ctx context.Context) (User, error) {
	var user User
	if err := c.request(ctx, http.MethodGet, "/users/@me", nil, &user); err != nil {
		return User{}, err
	}
	if !isDecimal(user.ID) {
		return User{}, errors.New("Discord returned an invalid bot user ID")
	}
	return user, nil
}

func (c *Client) EditMessage(
	ctx context.Context,
	channelID, messageID string,
	payload any,
) error {
	if !isDecimal(channelID) || !isDecimal(messageID) {
		return errors.New("invalid Discord channel or message ID")
	}
	return c.request(
		ctx,
		http.MethodPatch,
		"/channels/"+channelID+"/messages/"+messageID,
		payload,
		nil,
	)
}

func (c *Client) EditOriginalInteraction(
	ctx context.Context,
	applicationID, interactionToken string,
	payload any,
) error {
	if !isDecimal(applicationID) || interactionToken == "" {
		return errors.New("invalid Discord application ID or interaction token")
	}
	return c.requestWithoutAuthorization(
		ctx,
		http.MethodPatch,
		"/webhooks/"+applicationID+"/"+url.PathEscape(interactionToken)+"/messages/@original",
		payload,
		nil,
	)
}

func (c *Client) DeleteOriginalInteraction(
	ctx context.Context,
	applicationID, interactionToken string,
) error {
	if !isDecimal(applicationID) || interactionToken == "" {
		return errors.New("invalid Discord application ID or interaction token")
	}
	return c.requestWithoutAuthorization(
		ctx,
		http.MethodDelete,
		"/webhooks/"+applicationID+"/"+url.PathEscape(interactionToken)+"/messages/@original",
		nil,
		nil,
	)
}

func (c *Client) FindMessageByNonce(
	ctx context.Context,
	channelID, nonce string,
	notBefore time.Time,
) (Message, bool, error) {
	var zero Message
	if !isDecimal(channelID) || !isDecimal(nonce) {
		return zero, false, errors.New("invalid Discord channel ID or nonce")
	}
	before := ""
	cutoff := notBefore.UTC().Add(-5 * time.Minute)
	for {
		path := "/channels/" + channelID + "/messages?limit=100"
		if before != "" {
			path += "&before=" + before
		}
		var messages []Message
		if err := c.request(ctx, http.MethodGet, path, nil, &messages); err != nil {
			return zero, false, err
		}
		if len(messages) == 0 {
			return zero, false, nil
		}
		for _, message := range messages {
			if !isDecimal(message.ID) || message.ChannelID != channelID {
				return zero, false, errors.New("Discord history returned an unexpected message identity")
			}
			sentAt, err := time.Parse(time.RFC3339Nano, message.Timestamp)
			if err != nil {
				return zero, false, errors.New("Discord history returned an invalid message timestamp")
			}
			if nonceMatches(message.Nonce, nonce) &&
				message.Author.ID == c.botUserID {
				return message, true, nil
			}
			if sentAt.Before(cutoff) {
				return zero, false, nil
			}
		}
		if len(messages) < 100 {
			return zero, false, nil
		}
		before = messages[len(messages)-1].ID
	}
}

func (c *Client) request(
	ctx context.Context,
	method, path string,
	payload, result any,
) error {
	return c.requestWithAuthorization(ctx, method, path, payload, result, true)
}

func (c *Client) requestWithoutAuthorization(
	ctx context.Context,
	method, path string,
	payload, result any,
) error {
	return c.requestWithAuthorization(ctx, method, path, payload, result, false)
}

func (c *Client) requestWithAuthorization(
	ctx context.Context,
	method, path string,
	payload, result any,
	authenticate bool,
) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		request, requestErr := http.NewRequestWithContext(
			ctx,
			method,
			c.baseURL+path,
			bytes.NewReader(body),
		)
		if requestErr != nil {
			return requestErr
		}
		if authenticate {
			request.Header.Set("Authorization", "Bot "+c.token)
		}
		if payload != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		request.Header.Set("User-Agent", "zabbix-discord-ops")
		response, requestErr := c.http.Do(request)
		if requestErr != nil {
			return fmt.Errorf("Discord API: %w", requestErr)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read Discord API response: %w", readErr)
		}
		if response.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			retryAfter, retryErr := retryDelay(response.Header.Get("Retry-After"), responseBody)
			if retryErr != nil {
				return retryErr
			}
			timer := time.NewTimer(retryAfter)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return fmt.Errorf("Discord API retry: %w", ctx.Err())
			case <-timer.C:
			}
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("Discord API returned HTTP %d", response.StatusCode)
		}
		if result == nil || response.StatusCode == http.StatusNoContent {
			return nil
		}
		if err := json.Unmarshal(responseBody, result); err != nil {
			return fmt.Errorf("decode Discord API response: %w", err)
		}
		return nil
	}
	return errors.New("Discord API retry exhausted")
}

func nonceMatches(raw json.RawMessage, expected string) bool {
	if len(raw) == 0 {
		return false
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text == expected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var number json.Number
	if decoder.Decode(&number) != nil {
		return false
	}
	return number.String() == expected
}

func retryDelay(header string, body []byte) (time.Duration, error) {
	seconds, err := strconv.ParseFloat(header, 64)
	if err != nil {
		var payload struct {
			RetryAfter float64 `json:"retry_after"`
		}
		if json.Unmarshal(body, &payload) != nil || payload.RetryAfter <= 0 {
			return 0, errors.New("Discord rate limit response lacks retry delay")
		}
		seconds = payload.RetryAfter
	}
	delay := time.Duration(seconds * float64(time.Second))
	if delay <= 0 || delay > 2*time.Second {
		return 0, errors.New("Discord rate limit retry delay is outside safe bounds")
	}
	return delay, nil
}
