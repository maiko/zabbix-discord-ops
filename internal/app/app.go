package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maiko/zabbix-discord-ops/internal/config"
	"github.com/maiko/zabbix-discord-ops/internal/correlation"
	"github.com/maiko/zabbix-discord-ops/internal/discord"
	"github.com/maiko/zabbix-discord-ops/internal/zabbix"
)

const (
	interactionPing      = 1
	interactionCommand   = 2
	interactionComponent = 3
	interactionModal     = 5

	responsePong            = 1
	responseMessage         = 4
	responseDeferredMessage = 5
	responseModal           = 9
	ephemeralFlag           = 64
)

type discordClient interface {
	CurrentUser(context.Context) (discord.User, error)
	CreateMessage(context.Context, string, any) (discord.Message, error)
	EditMessage(context.Context, string, string, any) error
	EditOriginalInteraction(context.Context, string, string, any) error
	DeleteOriginalInteraction(context.Context, string, string) error
	FindMessageByNonce(
		context.Context,
		string,
		string,
		time.Time,
	) (discord.Message, bool, error)
}

type zabbixClient interface {
	Version(context.Context) (string, error)
	Problems(context.Context, int) ([]zabbix.Problem, error)
	Problem(context.Context, string) (zabbix.Problem, error)
	Acknowledge(context.Context, string, int, string, map[string]any) error
}

type metrics struct {
	interactions               atomic.Uint64
	rejected                   atomic.Uint64
	ingested                   atomic.Uint64
	actions                    atomic.Uint64
	errors                     atomic.Uint64
	staleCompletedCorrelations atomic.Uint64
}

type App struct {
	cfg               config.Config
	ingestToken       string
	verifier          *discord.Verifier
	signer            *discord.Signer
	discord           discordClient
	zabbix            zabbixClient
	logger            *slog.Logger
	now               func() time.Time
	correlations      *correlation.Store
	correlationLocks  *keyedLocker
	ingestTimeout     time.Duration
	successMessageTTL time.Duration
	deferredJobs      sync.WaitGroup
	metrics           metrics
}

type IngestEvent struct {
	EventID      string       `json:"event_id"`
	Status       string       `json:"status"`
	Severity     int          `json:"severity"`
	SeverityName string       `json:"severity_name"`
	Name         string       `json:"name"`
	Host         string       `json:"host"`
	Clock        int64        `json:"clock"`
	URL          string       `json:"url"`
	Message      string       `json:"message"`
	Tags         []zabbix.Tag `json:"tags"`
}

func New(
	cfg config.Config,
	secrets config.Secrets,
	logger *slog.Logger,
) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	verifier, err := discord.NewVerifier(secrets.DiscordPublicKey)
	if err != nil {
		return nil, err
	}
	signer, err := discord.NewSigner(secrets.ComponentSigningKey)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	correlations, err := correlation.New(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("load correlation state: %w", err)
	}
	application := &App{
		cfg:         cfg,
		ingestToken: secrets.IngestToken,
		verifier:    verifier,
		signer:      signer,
		discord: discord.NewClient(
			cfg.DiscordAPIURL,
			secrets.DiscordBotToken,
			cfg.DiscordBotUserID,
		),
		zabbix:            zabbix.NewClient(cfg.ZabbixURL, secrets.ZabbixAPIToken),
		logger:            logger,
		now:               time.Now,
		correlations:      correlations,
		correlationLocks:  newKeyedLocker(),
		ingestTimeout:     8 * time.Second,
		successMessageTTL: 3 * time.Second,
	}
	if err := application.inspectCompletedCorrelations(time.Now()); err != nil {
		return nil, fmt.Errorf("inspect correlation state: %w", err)
	}
	return application, nil
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /discord/interactions", a.handleInteraction)
	mux.HandleFunc("POST /v1/zabbix/events", a.handleIngest)
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /metrics", a.handleMetrics)
	return securityHeaders(mux)
}

func (a *App) ValidateDiscordIdentity(ctx context.Context) error {
	user, err := a.discord.CurrentUser(ctx)
	if err != nil {
		return fmt.Errorf("read Discord bot identity: %w", err)
	}
	if user.ID != a.cfg.DiscordBotUserID {
		return errors.New("configured Discord bot user ID does not match the bot token")
	}
	return nil
}

func (a *App) RunMaintenance(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := a.inspectCompletedCorrelations(now); err != nil {
				a.metrics.errors.Add(1)
				a.logger.Error("inspect completed Discord correlations", "error", err)
			}
		}
	}
}

func (a *App) inspectCompletedCorrelations(now time.Time) error {
	stale, err := a.correlations.CountStaleCompleted(
		now,
		time.Duration(a.cfg.StateReviewAfterDays)*24*time.Hour,
	)
	if err != nil {
		return err
	}
	a.metrics.staleCompletedCorrelations.Store(uint64(stale))
	if stale > 0 {
		a.logger.Warn(
			"stale completed Discord correlations require operator review",
			"count", stale,
			"review_after_days", a.cfg.StateReviewAfterDays,
		)
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'none'")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(response, request)
	})
}

func (a *App) handleInteraction(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, a.cfg.RequestMaxBytes))
	if err != nil {
		a.metrics.rejected.Add(1)
		http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := a.verifier.Verify(
		request.Header.Get("X-Signature-Timestamp"),
		request.Header.Get("X-Signature-Ed25519"),
		body,
		a.now(),
	); err != nil {
		a.metrics.rejected.Add(1)
		status := http.StatusUnauthorized
		if errors.Is(err, discord.ErrReplay) {
			status = http.StatusConflict
		}
		http.Error(response, "invalid interaction", status)
		return
	}
	var interaction discord.Interaction
	if err := json.Unmarshal(body, &interaction); err != nil {
		a.metrics.rejected.Add(1)
		http.Error(response, "invalid JSON", http.StatusBadRequest)
		return
	}
	a.metrics.interactions.Add(1)

	if a.requiresDeferredResponse(interaction) {
		a.deferredJobs.Add(1)
		writeJSON(response, http.StatusOK, deferredEphemeral())
		go func() {
			defer a.deferredJobs.Done()
			a.completeDeferredInteraction(interaction)
		}()
		return
	}

	var payload any
	operationContext, cancel := context.WithTimeout(request.Context(), 2500*time.Millisecond)
	defer cancel()
	switch interaction.Type {
	case interactionPing:
		payload = map[string]any{"type": responsePong}
	case interactionCommand:
		payload, err = a.command(operationContext, interaction)
	case interactionComponent:
		payload, err = a.component(operationContext, interaction)
	case interactionModal:
		payload, err = a.modal(operationContext, interaction)
	default:
		err = errors.New("unsupported interaction type")
	}
	if err != nil {
		a.metrics.errors.Add(1)
		a.logger.Warn("interaction rejected",
			"interaction_id", interaction.ID,
			"guild_id", interaction.GuildID,
			"user_id", interaction.Member.User.ID,
			"error", err,
		)
		payload = ephemeral("Action rejected. The event or tenant authorization no longer matches.")
	}
	writeJSON(response, http.StatusOK, payload)
}

func (a *App) requiresDeferredResponse(interaction discord.Interaction) bool {
	if interaction.Type == interactionModal {
		return true
	}
	if interaction.Type != interactionComponent {
		return false
	}
	component, err := a.signer.Verify(interaction.Data.CustomID, a.now())
	if err != nil {
		return false
	}
	switch component.Action {
	case "ack", "unsuppress", "close-confirm":
		return true
	default:
		return false
	}
}

func (a *App) completeDeferredInteraction(interaction discord.Interaction) {
	operationContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	var err error
	switch interaction.Type {
	case interactionComponent:
		_, err = a.component(operationContext, interaction)
	case interactionModal:
		_, err = a.modal(operationContext, interaction)
	default:
		err = errors.New("unsupported deferred interaction type")
	}

	content := "Zabbix accepted the action."
	if errors.Is(err, zabbix.ErrMutationOutcomeUnknown) {
		a.metrics.errors.Add(1)
		a.logger.Warn("deferred interaction outcome unknown",
			"interaction_id", interaction.ID,
			"guild_id", interaction.GuildID,
			"user_id", interaction.Member.User.ID,
			"error", err,
		)
		content = "Zabbix did not confirm the final result. The action may have been applied; check the live event before retrying."
	} else if err != nil {
		a.metrics.errors.Add(1)
		a.logger.Warn("deferred interaction rejected",
			"interaction_id", interaction.ID,
			"guild_id", interaction.GuildID,
			"user_id", interaction.Member.User.ID,
			"error", err,
		)
		content = "Action rejected. The event or tenant authorization no longer matches."
	}
	editContext, editCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer editCancel()
	editErr := a.discord.EditOriginalInteraction(
		editContext,
		interaction.ApplicationID,
		interaction.Token,
		interactionMessage(content),
	)
	if editErr != nil {
		a.metrics.errors.Add(1)
		a.logger.Error("edit deferred Discord interaction",
			"interaction_id", interaction.ID,
			"error", editErr,
		)
		return
	}
	if err != nil {
		return
	}

	timer := time.NewTimer(a.successMessageTTL)
	defer timer.Stop()
	<-timer.C

	deleteContext, deleteCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer deleteCancel()
	if deleteErr := a.discord.DeleteOriginalInteraction(
		deleteContext,
		interaction.ApplicationID,
		interaction.Token,
	); deleteErr != nil {
		a.metrics.errors.Add(1)
		a.logger.Error("delete successful Discord interaction",
			"interaction_id", interaction.ID,
			"error", deleteErr,
		)
	}
}

func (a *App) WaitForDeferred(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		a.deferredJobs.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) command(ctx context.Context, interaction discord.Interaction) (any, error) {
	if interaction.Data.Name != "zabbix" || len(interaction.Data.Options) != 1 {
		return nil, errors.New("unsupported command")
	}
	routes := a.authorizedRoutes(interaction)
	if len(routes) == 0 {
		return nil, errors.New("no authorized route")
	}
	switch interaction.Data.Options[0].Name {
	case "status":
		version, err := a.zabbix.Version(ctx)
		if err != nil {
			return nil, err
		}
		problems, err := a.zabbix.Problems(ctx, 100)
		if err != nil {
			return nil, err
		}
		count := 0
		for routeName, route := range routes {
			for _, problem := range problems {
				matches, err := a.problemMatchesRoute(problem, routeName, route)
				if err != nil {
					return nil, err
				}
				if matches {
					count++
				}
			}
		}
		return ephemeral(fmt.Sprintf("Zabbix %s is reachable. %d routed problem(s) open.", version, count)), nil
	case "problems":
		problems, err := a.zabbix.Problems(ctx, 100)
		if err != nil {
			return nil, err
		}
		lines := make([]string, 0, 10)
		for _, problem := range problems {
			for routeName, route := range routes {
				matches, err := a.problemMatchesRoute(problem, routeName, route)
				if err != nil {
					return nil, err
				}
				if !matches {
					continue
				}
				lines = append(lines, fmt.Sprintf(
					"`%s` %s — %s",
					problem.EventID,
					severityName(problem.SeverityInt()),
					truncate(problem.Name, 160),
				))
				break
			}
			if len(lines) == 10 {
				break
			}
		}
		if len(lines) == 0 {
			lines = append(lines, "No routed open problems.")
		}
		return ephemeral(strings.Join(lines, "\n")), nil
	default:
		return nil, errors.New("unsupported subcommand")
	}
}

func (a *App) component(ctx context.Context, interaction discord.Interaction) (any, error) {
	component, err := a.signer.Verify(interaction.Data.CustomID, a.now())
	if err != nil {
		return nil, err
	}
	route, problem, err := a.authorizeEvent(ctx, interaction, component)
	if err != nil {
		return nil, err
	}
	actor := auditActor(interaction)

	switch component.Action {
	case "ack":
		err = a.zabbix.Acknowledge(
			ctx,
			problem.EventID,
			zabbix.ActionAcknowledge|zabbix.ActionMessage,
			"Acknowledged from Discord by "+actor,
			nil,
		)
	case "unsuppress":
		err = a.zabbix.Acknowledge(
			ctx,
			problem.EventID,
			zabbix.ActionUnsuppress|zabbix.ActionMessage,
			"Unsuppressed from Discord by "+actor,
			nil,
		)
	case "comment":
		return a.modalResponse(component, "comment-submit", "Add Zabbix comment", []modalField{
			{ID: "comment", Label: "Comment", Style: 2, MaxLength: 1024},
		})
	case "suppress":
		return a.modalResponse(component, "suppress-submit", "Suppress Zabbix problem", []modalField{
			{ID: "minutes", Label: "Duration in minutes (1-10080)", Style: 1, MaxLength: 5},
			{ID: "comment", Label: "Reason", Style: 2, MaxLength: 1024},
		})
	case "severity":
		return a.modalResponse(component, "severity-submit", "Change Zabbix severity", []modalField{
			{ID: "severity", Label: "Severity 0-5", Style: 1, MaxLength: 1},
			{ID: "comment", Label: "Reason", Style: 2, MaxLength: 1024},
		})
	case "close":
		confirmID, signErr := a.signer.Sign(discord.ComponentToken{
			Action:  "close-confirm",
			EventID: problem.EventID,
			Route:   component.Route,
			Expires: a.now().Add(5 * time.Minute).Unix(),
		})
		if signErr != nil {
			return nil, signErr
		}
		return map[string]any{
			"type": responseMessage,
			"data": map[string]any{
				"content":    "Close this Zabbix problem manually? This bypasses trigger recovery.",
				"flags":      ephemeralFlag,
				"components": []any{actionRow(button("Confirm close", 4, confirmID))},
			},
		}, nil
	case "close-confirm":
		err = a.zabbix.Acknowledge(
			ctx,
			problem.EventID,
			zabbix.ActionClose|zabbix.ActionMessage,
			"Closed manually from Discord by "+actor,
			nil,
		)
	default:
		return nil, errors.New("unsupported component action")
	}
	if err != nil {
		return nil, err
	}
	a.metrics.actions.Add(1)
	a.logger.Info("Zabbix event action from Discord",
		"action", component.Action,
		"event_id", problem.EventID,
		"route", component.Route,
		"user_id", interaction.Member.User.ID,
		"channel_id", route.ChannelID,
	)
	return ephemeral("Zabbix accepted the action."), nil
}

func (a *App) modal(ctx context.Context, interaction discord.Interaction) (any, error) {
	component, err := a.signer.Verify(interaction.Data.CustomID, a.now())
	if err != nil {
		return nil, err
	}
	_, problem, err := a.authorizeEvent(ctx, interaction, component)
	if err != nil {
		return nil, err
	}
	values := modalValues(interaction.Data.Components)
	actor := auditActor(interaction)
	switch component.Action {
	case "comment-submit":
		comment := strings.TrimSpace(values["comment"])
		if comment == "" {
			return nil, errors.New("comment is empty")
		}
		err = a.zabbix.Acknowledge(
			ctx,
			problem.EventID,
			zabbix.ActionMessage,
			truncate(comment, 1024)+"\n\nDiscord: "+actor,
			nil,
		)
	case "suppress-submit":
		minutes, parseErr := strconv.Atoi(values["minutes"])
		if parseErr != nil || minutes < 1 || minutes > 10080 {
			return nil, errors.New("invalid suppression duration")
		}
		err = a.zabbix.Acknowledge(
			ctx,
			problem.EventID,
			zabbix.ActionSuppress|zabbix.ActionMessage,
			truncate(values["comment"], 1024)+"\n\nSuppressed from Discord by "+actor,
			map[string]any{"suppress_until": a.now().Add(time.Duration(minutes) * time.Minute).Unix()},
		)
	case "severity-submit":
		severity, parseErr := strconv.Atoi(values["severity"])
		if parseErr != nil || severity < 0 || severity > 5 {
			return nil, errors.New("invalid severity")
		}
		err = a.zabbix.Acknowledge(
			ctx,
			problem.EventID,
			zabbix.ActionSeverity|zabbix.ActionMessage,
			truncate(values["comment"], 1024)+"\n\nSeverity changed from Discord by "+actor,
			map[string]any{"severity": severity},
		)
	default:
		return nil, errors.New("unsupported modal action")
	}
	if err != nil {
		return nil, err
	}
	a.metrics.actions.Add(1)
	return ephemeral("Zabbix accepted the action."), nil
}

func (a *App) authorizeEvent(
	ctx context.Context,
	interaction discord.Interaction,
	component discord.ComponentToken,
) (config.Route, zabbix.Problem, error) {
	route, ok := a.cfg.Routes[component.Route]
	if !ok ||
		route.GuildID != interaction.GuildID ||
		route.ChannelID != interaction.ChannelID ||
		!memberAllowed(route, interaction.Member) {
		return config.Route{}, zabbix.Problem{}, errors.New("route authorization failed")
	}
	problem, err := a.zabbix.Problem(ctx, component.EventID)
	if err != nil {
		return config.Route{}, zabbix.Problem{}, err
	}
	matches, err := a.problemMatchesRoute(problem, component.Route, route)
	if err != nil {
		return config.Route{}, zabbix.Problem{}, err
	}
	if !matches {
		return config.Route{}, zabbix.Problem{}, errors.New("live event tenant does not match route")
	}
	return route, problem, nil
}

func (a *App) problemMatchesRoute(
	problem zabbix.Problem,
	routeName string,
	route config.Route,
) (bool, error) {
	tags, err := routeTagMap(problem.Tags, a.cfg.RoutingTag, route)
	if err != nil {
		return false, err
	}
	if tags[a.cfg.RoutingTag] != routeName {
		return false, nil
	}
	for name, value := range route.RequiredTags {
		if tags[name] != value {
			return false, nil
		}
	}
	if len(route.RequiredHostGroupID) == 0 {
		return true, nil
	}
	for _, group := range problem.HostGroups {
		for _, allowed := range route.RequiredHostGroupID {
			if group.GroupID == allowed {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *App) authorizedRoutes(interaction discord.Interaction) map[string]config.Route {
	result := make(map[string]config.Route)
	for name, route := range a.cfg.Routes {
		if route.GuildID == interaction.GuildID &&
			route.ChannelID == interaction.ChannelID &&
			memberAllowed(route, interaction.Member) {
			result[name] = route
		}
	}
	return result
}

func memberAllowed(route config.Route, member discord.Member) bool {
	for _, allowed := range route.AllowedUserIDs {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(member.User.ID)) == 1 {
			return true
		}
	}
	for _, role := range member.Roles {
		for _, allowed := range route.AllowedRoleIDs {
			if subtle.ConstantTimeCompare([]byte(allowed), []byte(role)) == 1 {
				return true
			}
		}
	}
	return false
}

func (a *App) handleIngest(response http.ResponseWriter, request *http.Request) {
	deadline := time.Now().Add(a.ingestTimeout)
	controller := http.NewResponseController(response)
	if err := controller.SetReadDeadline(deadline); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		a.fail(response, "set ingest read deadline", err)
		return
	}
	defer func() {
		_ = controller.SetReadDeadline(time.Time{})
	}()
	operationContext, cancel := context.WithDeadline(request.Context(), deadline)
	defer cancel()

	if !bearerMatches(request.Header.Get("Authorization"), a.ingestToken) {
		a.metrics.rejected.Add(1)
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	var event IngestEvent
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, a.cfg.RequestMaxBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		var networkError net.Error
		if operationContext.Err() != nil ||
			(errors.As(err, &networkError) && networkError.Timeout()) {
			http.Error(response, "event read deadline exceeded", http.StatusRequestTimeout)
			return
		}
		http.Error(response, "invalid event", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "trailing event content", http.StatusBadRequest)
		return
	}
	if err := validateIngestEvent(event); err != nil {
		http.Error(response, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	routingTags, err := selectedUniqueTagMap(
		event.Tags,
		map[string]struct{}{a.cfg.RoutingTag: {}},
	)
	if err != nil {
		http.Error(response, "event contains ambiguous tags", http.StatusUnprocessableEntity)
		return
	}
	routeName := routingTags[a.cfg.RoutingTag]
	route, ok := a.cfg.Routes[routeName]
	if !ok {
		http.Error(response, "event route is not configured", http.StatusForbidden)
		return
	}
	tags, err := routeTagMap(event.Tags, a.cfg.RoutingTag, route)
	if err != nil {
		http.Error(response, "event contains ambiguous tags", http.StatusUnprocessableEntity)
		return
	}
	if !tagsMatch(tags, route.RequiredTags) {
		http.Error(response, "event route is not configured", http.StatusForbidden)
		return
	}
	resultTags := map[string]string{}
	suppressed := false
	if event.Status != "RESOLVED" {
		live, err := a.zabbix.Problem(operationContext, event.EventID)
		if err != nil {
			http.Error(response, "live problem does not match route", http.StatusForbidden)
			return
		}
		matches, err := a.problemMatchesRoute(live, routeName, route)
		if err != nil || !matches {
			http.Error(response, "live problem does not match route", http.StatusForbidden)
			return
		}
		suppressed = live.Suppressed == "1"
	}
	payload, err := a.eventMessage(event, routeName, suppressed)
	if err != nil {
		a.fail(response, "build Discord message", err)
		return
	}

	if event.Status == "PROBLEM" {
		release, err := a.correlationLocks.Acquire(
			operationContext,
			routeName+"\x00"+event.EventID,
		)
		if err != nil {
			http.Error(response, "event processing deadline exceeded", http.StatusGatewayTimeout)
			return
		}
		defer release()
		record, existed, err := a.correlations.Begin(
			event.EventID,
			routeName,
			route.ChannelID,
			a.now(),
		)
		if err != nil {
			a.fail(response, "persist pending Discord correlation", err)
			return
		}
		if record.MessageID == "" {
			var message discord.Message
			var found bool
			if existed {
				message, found, err = a.discord.FindMessageByNonce(
					operationContext,
					route.ChannelID,
					event.EventID,
					record.StartedAt,
				)
				if err != nil {
					a.fail(response, "reconcile pending Discord message", err)
					return
				}
			}
			if !found {
				message, err = a.discord.CreateMessage(
					operationContext,
					route.ChannelID,
					payload,
				)
			}
			if err != nil {
				a.fail(response, "create Discord message", err)
				return
			}
			if !expectedDiscordMessage(
				message,
				route.ChannelID,
				a.cfg.DiscordBotUserID,
			) {
				a.fail(response, "create Discord message", errors.New("unexpected message identity"))
				return
			}
			record, err = a.correlations.Complete(record, message.ID, a.now())
			if err != nil {
				a.fail(response, "persist Discord correlation", err)
				return
			}
		}

		for _, channelID := range route.MirrorChannelIDs {
			if record.MirrorMessages[channelID] != "" {
				continue
			}
			var mirrorExisted bool
			record, mirrorExisted, err = a.correlations.BeginMirror(
				record,
				channelID,
				a.now(),
			)
			if err != nil {
				a.fail(response, "persist pending Discord mirror", err)
				return
			}
			var message discord.Message
			var found bool
			if mirrorExisted {
				message, found, err = a.discord.FindMessageByNonce(
					operationContext,
					channelID,
					mirrorNonce(event.EventID, channelID),
					record.MirrorStartedAt[channelID],
				)
				if err != nil {
					a.fail(response, "reconcile pending Discord mirror", err)
					return
				}
			}
			if !found {
				mirrorPayload := readOnlyDiscordMessage(payload)
				mirrorPayload["nonce"] = mirrorNonce(event.EventID, channelID)
				message, err = a.discord.CreateMessage(
					operationContext,
					channelID,
					mirrorPayload,
				)
			}
			if err != nil {
				a.fail(response, "create Discord mirror", err)
				return
			}
			if !expectedDiscordMessage(message, channelID, a.cfg.DiscordBotUserID) {
				a.fail(response, "create Discord mirror", errors.New("unexpected message identity"))
				return
			}
			record, err = a.correlations.CompleteMirror(
				record,
				channelID,
				message.ID,
			)
			if err != nil {
				a.fail(response, "persist Discord mirror correlation", err)
				return
			}
		}
		resultTags = correlationTags(record)
	} else {
		channelID := tags["zbx_discord_ops_channel_id"]
		messageID := tags["zbx_discord_ops_message_id"]
		if channelID != route.ChannelID ||
			!isDecimalID(messageID) ||
			tags["zbx_discord_ops_route"] != routeName {
			http.Error(response, "missing or mismatched Discord correlation tags", http.StatusUnprocessableEntity)
			return
		}
		if err := a.discord.EditMessage(
			operationContext,
			channelID,
			messageID,
			payload,
		); err != nil {
			a.fail(response, "edit Discord message", err)
			return
		}
		record, found, err := a.correlations.Lookup(event.EventID, routeName)
		if err != nil {
			a.fail(response, "read Discord mirror correlations", err)
			return
		}
		if found {
			if record.ChannelID != channelID || record.MessageID != messageID {
				http.Error(response, "mismatched Discord correlation state", http.StatusUnprocessableEntity)
				return
			}
			mirrorPayload := readOnlyDiscordMessage(payload)
			for _, mirrorChannelID := range route.MirrorChannelIDs {
				mirrorMessageID := record.MirrorMessages[mirrorChannelID]
				if mirrorMessageID == "" {
					continue
				}
				if err := a.discord.EditMessage(
					operationContext,
					mirrorChannelID,
					mirrorMessageID,
					mirrorPayload,
				); err != nil {
					a.fail(response, "edit Discord mirror", err)
					return
				}
			}
		}
	}
	a.metrics.ingested.Add(1)
	writeJSON(response, http.StatusOK, map[string]any{"tags": resultTags})
}

func expectedDiscordMessage(message discord.Message, channelID, botUserID string) bool {
	return isDecimalID(message.ID) &&
		message.ChannelID == channelID &&
		message.Author.ID == botUserID
}

func readOnlyDiscordMessage(payload map[string]any) map[string]any {
	result := make(map[string]any, len(payload))
	for key, value := range payload {
		result[key] = value
	}
	result["components"] = []any{}
	return result
}

func mirrorNonce(eventID, channelID string) string {
	digest := sha256.Sum256([]byte("discord-mirror\x00" + eventID + "\x00" + channelID))
	return strconv.FormatUint(binary.BigEndian.Uint64(digest[:8]), 10)
}

func validateIngestEvent(event IngestEvent) error {
	if !isDecimalID(event.EventID) || event.Name == "" || event.Host == "" {
		return errors.New("event_id, name and host are required")
	}
	if event.Severity < 0 || event.Severity > 5 {
		return errors.New("severity must be between 0 and 5")
	}
	switch event.Status {
	case "PROBLEM", "UPDATE", "RESOLVED":
	default:
		return errors.New("status must be PROBLEM, UPDATE or RESOLVED")
	}
	if len(event.Name) > 2048 || len(event.Message) > 8192 || len(event.Tags) > 128 {
		return errors.New("event field exceeds limit")
	}
	return nil
}

func isDecimalID(value string) bool {
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

func (a *App) eventMessage(
	event IngestEvent,
	route string,
	suppressed bool,
) (map[string]any, error) {
	color := []int{0x97AAB3, 0x7499FF, 0xFFC859, 0xFFA059, 0xE97659, 0xE45959}[event.Severity]
	title := severityName(event.Severity) + ": " + truncate(event.Name, 220)
	if event.Status == "RESOLVED" {
		color = 0x59BA6A
		title = "Resolved: " + truncate(event.Name, 220)
	}
	embed := map[string]any{
		"title":       title,
		"description": truncate(event.Message, 3500),
		"color":       color,
		"fields": []any{
			map[string]any{"name": "Host", "value": truncate(event.Host, 1024), "inline": true},
			map[string]any{"name": "Event", "value": event.EventID, "inline": true},
			map[string]any{"name": "Route", "value": route, "inline": true},
		},
		"footer": map[string]any{"text": a.cfg.DisplayName},
	}
	if event.Clock > 0 {
		embed["timestamp"] = time.Unix(event.Clock, 0).UTC().Format(time.RFC3339)
	}
	if event.URL != "" {
		if !sameHTTPSOrigin(event.URL, a.cfg.ZabbixURL) {
			return nil, errors.New("event URL is outside the configured Zabbix origin")
		}
		embed["url"] = event.URL
	}
	payload := map[string]any{
		"embeds":           []any{embed},
		"allowed_mentions": map[string]any{"parse": []string{}},
		"components":       []any{},
	}
	if event.Status == "PROBLEM" {
		payload["nonce"] = event.EventID
		payload["enforce_nonce"] = true
	}
	if event.Status != "RESOLVED" {
		suppressionLabel := "Suppress"
		suppressionAction := "suppress"
		if suppressed {
			suppressionLabel = "Unsuppress"
			suppressionAction = "unsuppress"
		}
		actions := []struct {
			label  string
			style  int
			action string
		}{
			{"Acknowledge", 1, "ack"},
			{"Comment", 2, "comment"},
			{suppressionLabel, 2, suppressionAction},
			{"Severity", 2, "severity"},
			{"Close", 4, "close"},
		}
		buttons := make([]any, 0, len(actions))
		for _, action := range actions {
			customID, err := a.signer.Sign(discord.ComponentToken{
				Action:  action.action,
				EventID: event.EventID,
				Route:   route,
				Expires: a.now().Add(30 * 24 * time.Hour).Unix(),
			})
			if err != nil {
				return nil, err
			}
			buttons = append(buttons, button(action.label, action.style, customID))
		}
		payload["components"] = []any{map[string]any{"type": 1, "components": buttons}}
	}
	return payload, nil
}

func sameHTTPSOrigin(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return leftURL.Scheme == "https" &&
		rightURL.Scheme == "https" &&
		leftURL.Host == rightURL.Host &&
		leftURL.User == nil &&
		rightURL.User == nil
}

type modalField struct {
	ID        string
	Label     string
	Style     int
	MaxLength int
}

func (a *App) modalResponse(
	component discord.ComponentToken,
	action string,
	title string,
	fields []modalField,
) (any, error) {
	customID, err := a.signer.Sign(discord.ComponentToken{
		Action:  action,
		EventID: component.EventID,
		Route:   component.Route,
		Expires: a.now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return nil, err
	}
	rows := make([]any, 0, len(fields))
	for _, field := range fields {
		rows = append(rows, map[string]any{
			"type": 1,
			"components": []any{map[string]any{
				"type":       4,
				"custom_id":  field.ID,
				"label":      field.Label,
				"style":      field.Style,
				"required":   true,
				"max_length": field.MaxLength,
			}},
		})
	}
	return map[string]any{
		"type": responseModal,
		"data": map[string]any{
			"custom_id":  customID,
			"title":      title,
			"components": rows,
		},
	}, nil
}

func modalValues(rows []discord.ActionRow) map[string]string {
	result := make(map[string]string)
	for _, row := range rows {
		for _, component := range row.Components {
			result[component.CustomID] = component.Value
		}
	}
	return result
}

func (a *App) handleHealth(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleMetrics(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(response,
		"# HELP zabbix_discord_ops_interactions_total Verified Discord interactions.\n"+
			"# TYPE zabbix_discord_ops_interactions_total counter\n"+
			"zabbix_discord_ops_interactions_total %d\n"+
			"# HELP zabbix_discord_ops_rejected_total Rejected requests and interactions.\n"+
			"# TYPE zabbix_discord_ops_rejected_total counter\n"+
			"zabbix_discord_ops_rejected_total %d\n"+
			"# HELP zabbix_discord_ops_ingested_total Zabbix event notifications processed.\n"+
			"# TYPE zabbix_discord_ops_ingested_total counter\n"+
			"zabbix_discord_ops_ingested_total %d\n"+
			"# HELP zabbix_discord_ops_actions_total Zabbix mutations accepted from Discord.\n"+
			"# TYPE zabbix_discord_ops_actions_total counter\n"+
			"zabbix_discord_ops_actions_total %d\n"+
			"# HELP zabbix_discord_ops_errors_total Upstream and processing errors.\n"+
			"# TYPE zabbix_discord_ops_errors_total counter\n"+
			"zabbix_discord_ops_errors_total %d\n"+
			"# HELP zabbix_discord_ops_stale_completed_correlations Completed correlation records awaiting operator review.\n"+
			"# TYPE zabbix_discord_ops_stale_completed_correlations gauge\n"+
			"zabbix_discord_ops_stale_completed_correlations %d\n",
		a.metrics.interactions.Load(),
		a.metrics.rejected.Load(),
		a.metrics.ingested.Load(),
		a.metrics.actions.Load(),
		a.metrics.errors.Load(),
		a.metrics.staleCompletedCorrelations.Load(),
	)
}

func (a *App) fail(response http.ResponseWriter, operation string, err error) {
	a.metrics.errors.Add(1)
	a.logger.Error(operation, "error", err)
	http.Error(response, "upstream operation failed", http.StatusBadGateway)
}

func bearerMatches(header, token string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

func tagsMatch(tags, required map[string]string) bool {
	for name, value := range required {
		if tags[name] != value {
			return false
		}
	}
	return true
}

func routeTagMap(
	tags []zabbix.Tag,
	routingTag string,
	route config.Route,
) (map[string]string, error) {
	selected := map[string]struct{}{
		routingTag:                   {},
		"zbx_discord_ops_message_id": {},
		"zbx_discord_ops_channel_id": {},
		"zbx_discord_ops_route":      {},
	}
	for name := range route.RequiredTags {
		selected[name] = struct{}{}
	}
	return selectedUniqueTagMap(tags, selected)
}

func selectedUniqueTagMap(
	tags []zabbix.Tag,
	selected map[string]struct{},
) (map[string]string, error) {
	result := make(map[string]string, len(selected))
	for _, tag := range tags {
		if _, monitored := selected[tag.Tag]; !monitored {
			continue
		}
		if value, exists := result[tag.Tag]; exists && value != tag.Value {
			return nil, fmt.Errorf("tag %q has multiple values", tag.Tag)
		}
		result[tag.Tag] = tag.Value
	}
	return result, nil
}

func correlationTags(record correlation.Record) map[string]string {
	return map[string]string{
		"zbx_discord_ops_message_id": record.MessageID,
		"zbx_discord_ops_channel_id": record.ChannelID,
		"zbx_discord_ops_route":      record.Route,
	}
}

func auditActor(interaction discord.Interaction) string {
	return fmt.Sprintf(
		"%s (user %s, guild %s)",
		interaction.Member.User.Username,
		interaction.Member.User.ID,
		interaction.GuildID,
	)
}

func severityName(value int) string {
	names := []string{"Not classified", "Information", "Warning", "Average", "High", "Disaster"}
	if value < 0 || value >= len(names) {
		return "Unknown"
	}
	return names[value]
}

func button(label string, style int, customID string) map[string]any {
	return map[string]any{
		"type":      2,
		"style":     style,
		"label":     label,
		"custom_id": customID,
	}
}

func actionRow(components ...map[string]any) map[string]any {
	values := make([]any, 0, len(components))
	for _, component := range components {
		values = append(values, component)
	}
	return map[string]any{"type": 1, "components": values}
}

func ephemeral(content string) map[string]any {
	return map[string]any{
		"type": responseMessage,
		"data": ephemeralMessage(content),
	}
}

func deferredEphemeral() map[string]any {
	return map[string]any{
		"type": responseDeferredMessage,
		"data": map[string]any{"flags": ephemeralFlag},
	}
}

func ephemeralMessage(content string) map[string]any {
	message := interactionMessage(content)
	message["flags"] = ephemeralFlag
	return message
}

func interactionMessage(content string) map[string]any {
	return map[string]any{
		"content":          content,
		"allowed_mentions": map[string]any{"parse": []string{}},
	}
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func truncate(value string, maximum int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= maximum {
		return string(runes)
	}
	if maximum < 2 {
		return string(runes[:maximum])
	}
	return string(runes[:maximum-1]) + "…"
}
