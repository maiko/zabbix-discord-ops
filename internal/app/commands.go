package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maiko/zabbix-discord-ops/internal/config"
	"github.com/maiko/zabbix-discord-ops/internal/discord"
	"github.com/maiko/zabbix-discord-ops/internal/maintenancecard"
	"github.com/maiko/zabbix-discord-ops/internal/operation"
	"github.com/maiko/zabbix-discord-ops/internal/zabbix"
)

const (
	timeperiodOneTime = "0"
	maxCommandResults = 25
)

type maintenanceCacheEntry struct {
	ExpiresAt    time.Time
	Maintenances []zabbix.Maintenance
	Routes       map[string]string
	Targets      map[string][]zabbix.Host
}

func (a *App) commandV3(ctx context.Context, interaction discord.Interaction) (any, error) {
	if interaction.Data.Name != "zabbix" || len(interaction.Data.Options) != 1 {
		return nil, errors.New("unsupported command")
	}
	routes := a.authorizedRoutes(interaction)
	if len(routes) == 0 {
		return nil, errors.New("no authorized route")
	}
	root := interaction.Data.Options[0]
	switch root.Name {
	case "status":
		return a.commandStatus(ctx, routes)
	case "whoami":
		return a.commandWhoami(routes, interaction.Member), nil
	case "host":
		return a.commandHost(ctx, routes, optionString(root.Options, "host"))
	case "problem":
		return a.commandProblem(ctx, routes, optionString(root.Options, "event"))
	case "problems":
		return a.commandProblems(
			ctx,
			routes,
			optionString(root.Options, "host"),
			optionInt(root.Options, "severity", 0),
		)
	case "downtime":
		if len(root.Options) != 1 {
			return nil, errors.New("missing downtime action")
		}
		return a.commandDowntime(ctx, interaction, routes, root.Options[0])
	default:
		return nil, errors.New("unsupported subcommand")
	}
}

func (a *App) commandStatus(
	ctx context.Context,
	routes map[string]config.Route,
) (any, error) {
	version, err := a.zabbix.Version(ctx)
	if err != nil {
		return nil, err
	}
	problems, err := a.zabbix.Problems(ctx, 100)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, problem := range problems {
		for routeName, route := range routes {
			matches, matchErr := a.problemMatchesRoute(problem, routeName, route)
			if matchErr != nil {
				return nil, matchErr
			}
			if matches {
				count++
				break
			}
		}
	}
	return ephemeral(fmt.Sprintf(
		"Zabbix %s is reachable. %d routed problem(s) open.",
		version,
		count,
	)), nil
}

func (a *App) commandWhoami(
	routes map[string]config.Route,
	member discord.Member,
) any {
	names := make([]string, 0, len(routes))
	maintenance := make([]string, 0, len(routes))
	cancel := make([]string, 0, len(routes))
	for name, route := range routes {
		names = append(names, name)
		if route.MaintenanceEnabled {
			maintenance = append(maintenance, name)
		}
		if userIDAllowed(route.MaintenanceCancelAllowedUserIDs, member.User.ID) {
			cancel = append(cancel, name)
		}
	}
	sort.Strings(names)
	sort.Strings(maintenance)
	sort.Strings(cancel)
	if len(maintenance) == 0 {
		maintenance = []string{"none"}
	}
	if len(cancel) == 0 {
		cancel = []string{"none"}
	}
	return ephemeral(fmt.Sprintf(
		"User `%s`\nRoutes: `%s`\nMaintenance: `%s`\nCancel: `%s`",
		member.User.ID,
		strings.Join(names, "`, `"),
		strings.Join(maintenance, "`, `"),
		strings.Join(cancel, "`, `"),
	))
}

func (a *App) commandHost(
	ctx context.Context,
	routes map[string]config.Route,
	hostID string,
) (any, error) {
	host, routeName, _, err := a.authorizeHost(ctx, routes, hostID, false)
	if err != nil {
		return nil, err
	}
	return ephemeral(fmt.Sprintf(
		"**%s** (`%s`)\nRoute: `%s` · Monitoring: `%s` · Maintenance: `%s`",
		hostDisplayName(host),
		host.HostID,
		routeName,
		hostMonitoringState(host.Status),
		hostMaintenanceState(host),
	)), nil
}

func (a *App) commandProblem(
	ctx context.Context,
	routes map[string]config.Route,
	eventID string,
) (any, error) {
	problem, err := a.zabbix.Problem(ctx, eventID)
	if err != nil {
		return nil, err
	}
	for routeName, route := range routes {
		matches, matchErr := a.problemMatchesRoute(problem, routeName, route)
		if matchErr != nil {
			return nil, matchErr
		}
		if matches {
			return ephemeral(fmt.Sprintf(
				"`%s` %s — %s\nHost: %s · Route: `%s` · Acknowledged: `%s`",
				problem.EventID,
				severityName(problem.SeverityInt()),
				truncate(problem.Name, 160),
				problem.HostNames(),
				routeName,
				problem.Acknowledged,
			)), nil
		}
	}
	return nil, errors.New("problem is outside authorized routes")
}

func (a *App) commandProblems(
	ctx context.Context,
	routes map[string]config.Route,
	hostID string,
	minSeverity int,
) (any, error) {
	problems, err := a.zabbix.Problems(ctx, 100)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, 10)
	for _, problem := range problems {
		if problem.SeverityInt() < minSeverity || !problemHasHost(problem, hostID) {
			continue
		}
		for routeName, route := range routes {
			matches, matchErr := a.problemMatchesRoute(problem, routeName, route)
			if matchErr != nil {
				return nil, matchErr
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
}

func (a *App) commandDowntime(
	ctx context.Context,
	interaction discord.Interaction,
	routes map[string]config.Route,
	action discord.InteractionOption,
) (any, error) {
	switch action.Name {
	case "start":
		return a.startDowntime(ctx, interaction, routes, action.Options)
	case "list":
		return a.listDowntime(
			ctx,
			routes,
			optionString(action.Options, "host"),
			optionString(action.Options, "state"),
		)
	case "extend":
		return a.extendDowntime(ctx, interaction, routes, action.Options)
	case "end":
		return a.endDowntime(ctx, interaction, routes, action.Options)
	case "cancel":
		return a.cancelDowntime(ctx, interaction, routes, action.Options)
	default:
		return nil, errors.New("unsupported downtime action")
	}
}

func (a *App) startDowntime(
	ctx context.Context,
	interaction discord.Interaction,
	routes map[string]config.Route,
	options []discord.InteractionOption,
) (any, error) {
	hostID := optionString(options, "host")
	duration, err := parseDuration(optionString(options, "duration"), false)
	if err != nil {
		return nil, err
	}
	startDelay := time.Duration(0)
	if value := optionString(options, "starts_in"); value != "" {
		startDelay, err = parseDuration(value, true)
		if err != nil {
			return nil, err
		}
	}
	reason, err := validateReason(optionString(options, "reason"))
	if err != nil {
		return nil, err
	}
	host, routeName, _, err := a.authorizeHost(ctx, routes, hostID, true)
	if err != nil {
		return nil, err
	}
	start := a.now().Add(startDelay).Truncate(time.Minute)
	if start.Before(a.now().Add(-time.Minute)) {
		return nil, errors.New("invalid maintenance start")
	}
	end := start.Add(duration)
	record, replay, release, err := a.beginMaintenanceOperation(
		ctx, interaction, "start", routeName, hostID,
	)
	if err != nil {
		return nil, err
	}
	defer release()
	if replay != "" {
		return ephemeral(replay), nil
	}
	record, err = a.recordMaintenanceIntent(record, map[string]any{
		"host_id":      host.HostID,
		"active_since": start.Unix(),
		"active_till":  end.Unix(),
	})
	if err != nil {
		return nil, err
	}
	description := maintenanceAuditDescription(reason, interaction, routeName, "created")
	maintenanceID, err := a.maintenance.CreateMaintenance(ctx, map[string]any{
		"name": truncate(
			fmt.Sprintf("Discord [%s]: %s", interaction.ID, hostDisplayName(host)),
			128,
		),
		"description":      description,
		"active_since":     start.Unix(),
		"active_till":      end.Unix(),
		"maintenance_type": 0,
		"hosts":            []map[string]string{{"hostid": host.HostID}},
		"timeperiods": []map[string]any{{
			"timeperiod_type": 0,
			"start_date":      start.Unix(),
			"period":          int64(duration.Seconds()),
		}},
	})
	if err != nil {
		a.recordUnknownMutation(err)
		a.recordRejectedMaintenanceOperation(record, err)
		return nil, err
	}
	a.metrics.actions.Add(1)
	result := fmt.Sprintf(
		"Maintenance `%s` scheduled for **%s** from <t:%d:F> to <t:%d:F>.",
		maintenanceID,
		hostDisplayName(host),
		start.Unix(),
		end.Unix(),
	)
	if err := a.completeMaintenanceOperation(record, result, map[string]any{
		"maintenance_id": maintenanceID,
		"state":          "scheduled",
		"active_since":   start.Unix(),
		"active_till":    end.Unix(),
	}); err != nil {
		return nil, err
	}
	return ephemeral(result), nil
}

func (a *App) listDowntime(
	ctx context.Context,
	routes map[string]config.Route,
	hostID, stateFilter string,
) (any, error) {
	maintenances, err := a.authorizedMaintenances(ctx, routes)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, 10)
	now := a.now()
	for _, maintenance := range maintenances {
		if hostID != "" {
			hosts, hostErr := a.affectedMaintenanceHosts(ctx, maintenance)
			if hostErr != nil {
				return nil, hostErr
			}
			found := false
			for _, host := range hosts {
				found = found || host.HostID == hostID
			}
			if !found {
				continue
			}
		}
		state := maintenanceState(maintenance, now)
		if stateFilter != "" && !strings.EqualFold(state, stateFilter) {
			continue
		}
		lines = append(lines, fmt.Sprintf(
			"`%s` **%s** — %s · <t:%s:R>",
			maintenance.MaintenanceID,
			truncate(maintenance.Name, 80),
			titleState(state),
			maintenance.ActiveTill,
		))
		if len(lines) == 10 {
			break
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "No authorized maintenance windows.")
	}
	return ephemeral(strings.Join(lines, "\n")), nil
}

func (a *App) extendDowntime(
	ctx context.Context,
	interaction discord.Interaction,
	routes map[string]config.Route,
	options []discord.InteractionOption,
) (any, error) {
	maintenanceID := optionString(options, "maintenance")
	duration, err := parseDuration(optionString(options, "duration"), false)
	if err != nil {
		return nil, err
	}
	reason, err := validateReason(optionString(options, "reason"))
	if err != nil {
		return nil, err
	}
	maintenance, routeName, err := a.authorizeMaintenance(ctx, routes, maintenanceID, true)
	if err != nil {
		return nil, err
	}
	state := maintenanceState(maintenance, a.now())
	if state != "scheduled" && state != "active" {
		return nil, errors.New("only scheduled or active maintenance can be extended")
	}
	activeTill, err := unixField(maintenance.ActiveTill)
	if err != nil {
		return nil, err
	}
	params := map[string]any{
		"maintenanceid": maintenance.MaintenanceID,
		"active_till":   activeTill.Add(duration).Unix(),
		"description": appendMaintenanceAudit(
			maintenance.Description,
			maintenanceAuditDescription(
				reason,
				interaction,
				routeName,
				"extended by "+duration.String(),
			),
		),
	}
	if activeTill.Unix() > 2147483647-int64(duration.Seconds()) {
		return nil, errors.New("extended maintenance exceeds Zabbix timestamp range")
	}
	oneTime := oneTimeperiodIndexes(maintenance.Timeperiods)
	if len(oneTime) > 1 || (len(oneTime) == 1 && len(maintenance.Timeperiods) > 1) {
		return nil, errors.New("mixed or multiple one-time periods cannot be extended safely")
	}
	if len(oneTime) == 1 {
		periods, cleanErr := cleanTimeperiods(maintenance.Timeperiods)
		if cleanErr != nil {
			return nil, cleanErr
		}
		period := int64(periods[0]["period"].(int))
		if period > 2147483647-int64(duration.Seconds()) {
			return nil, errors.New("extended period exceeds Zabbix integer range")
		}
		periods[0]["period"] = int(period + int64(duration.Seconds()))
		params["timeperiods"] = periods
	}
	record, replay, release, err := a.beginMaintenanceOperation(
		ctx, interaction, "extend", routeName, maintenanceID,
	)
	if err != nil {
		return nil, err
	}
	defer release()
	if replay != "" {
		return ephemeral(replay), nil
	}
	record, err = a.recordMaintenanceIntent(record, map[string]any{
		"maintenance_id": maintenance.MaintenanceID,
		"active_till":    activeTill.Add(duration).Unix(),
	})
	if err != nil {
		return nil, err
	}
	if err := a.maintenance.UpdateMaintenance(ctx, params); err != nil {
		a.recordUnknownMutation(err)
		a.recordRejectedMaintenanceOperation(record, err)
		return nil, err
	}
	a.metrics.actions.Add(1)
	result := fmt.Sprintf(
		"Maintenance `%s` extended by %s.",
		maintenance.MaintenanceID,
		duration,
	)
	if err := a.completeMaintenanceOperation(record, result, map[string]any{
		"maintenance_id": maintenance.MaintenanceID,
		"state":          maintenanceState(maintenance, a.now()),
		"active_till":    activeTill.Add(duration).Unix(),
	}); err != nil {
		return nil, err
	}
	return ephemeral(result), nil
}

func (a *App) endDowntime(
	ctx context.Context,
	interaction discord.Interaction,
	routes map[string]config.Route,
	options []discord.InteractionOption,
) (any, error) {
	maintenanceID := optionString(options, "maintenance")
	reason, err := validateReason(optionString(options, "reason"))
	if err != nil {
		return nil, err
	}
	maintenance, routeName, err := a.authorizeMaintenance(ctx, routes, maintenanceID, true)
	if err != nil {
		return nil, err
	}
	if maintenanceState(maintenance, a.now()) != "active" {
		return nil, errors.New("only active maintenance can be ended")
	}
	activeSince, err := unixField(maintenance.ActiveSince)
	if err != nil {
		return nil, err
	}
	activeTill := a.now().Add(time.Minute).Truncate(time.Minute)
	if !activeTill.After(activeSince) {
		activeTill = activeSince.Add(time.Minute)
	}
	record, replay, release, err := a.beginMaintenanceOperation(
		ctx, interaction, "end", routeName, maintenanceID,
	)
	if err != nil {
		return nil, err
	}
	defer release()
	if replay != "" {
		return ephemeral(replay), nil
	}
	record, err = a.recordMaintenanceIntent(record, map[string]any{
		"maintenance_id": maintenance.MaintenanceID,
		"active_till":    activeTill.Unix(),
	})
	if err != nil {
		return nil, err
	}
	if err := a.maintenance.UpdateMaintenance(ctx, map[string]any{
		"maintenanceid": maintenance.MaintenanceID,
		"active_till":   activeTill.Unix(),
		"description": appendMaintenanceAudit(
			maintenance.Description,
			maintenanceAuditDescription(
				reason,
				interaction,
				routeName,
				"ending",
			),
		),
	}); err != nil {
		a.recordUnknownMutation(err)
		a.recordRejectedMaintenanceOperation(record, err)
		return nil, err
	}
	a.metrics.actions.Add(1)
	result := fmt.Sprintf(
		"Maintenance `%s` is ending; Zabbix state will be reconciled asynchronously.",
		maintenance.MaintenanceID,
	)
	record.FinalSnapshot["state"] = "ending"
	if _, err := a.maintenanceOps.Update(
		record,
		operation.Executing,
		result,
		record.FinalSnapshot,
		a.now(),
	); err != nil {
		return nil, err
	}
	return ephemeral(result), nil
}

func (a *App) cancelDowntime(
	ctx context.Context,
	interaction discord.Interaction,
	routes map[string]config.Route,
	options []discord.InteractionOption,
) (any, error) {
	maintenanceID := optionString(options, "maintenance")
	reason, err := validateReason(optionString(options, "reason"))
	if err != nil {
		return nil, err
	}
	maintenance, routeName, err := a.authorizeMaintenance(ctx, routes, maintenanceID, true)
	if err != nil {
		return nil, err
	}
	route := routes[routeName]
	if !userIDAllowed(route.MaintenanceCancelAllowedUserIDs, interaction.Member.User.ID) {
		a.metrics.maintenanceAuthRejected.Add(1)
		return nil, errors.New("cancel requires explicit user authorization")
	}
	if maintenanceState(maintenance, a.now()) != "scheduled" {
		return nil, errors.New("only future maintenance can be cancelled")
	}
	hosts, err := a.affectedMaintenanceHosts(ctx, maintenance)
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		if host.MaintenanceStatus == "1" {
			return nil, errors.New("a target host is currently in effective maintenance")
		}
	}
	hostIDs, hostNames := maintenanceHostIdentities(hosts)
	expiresAt := a.now().Add(5 * time.Minute)
	reasonLine := ""
	if reason != "" {
		reasonLine = "\nReason: " + truncate(reason, 300)
	}
	prompt := fmt.Sprintf(
		"Cancel future maintenance `%s` (**%s**)?\nTargets: %s\nWindow: <t:%s:F> → <t:%s:F>\nThis permanently deletes the Zabbix maintenance object.%s",
		maintenance.MaintenanceID,
		truncate(maintenance.Name, 100),
		strings.Join(hostNames, ", "),
		maintenance.ActiveSince,
		maintenance.ActiveTill,
		reasonLine,
	)
	if len([]rune(prompt)) > 2000 {
		return nil, errors.New(
			"exact maintenance target list exceeds Discord's confirmation limit",
		)
	}
	intent, existed, err := a.maintenanceOps.Begin(operation.Record{
		InteractionID: interaction.ID,
		Action:        "cancel",
		Route:         routeName,
		ObjectID:      maintenance.MaintenanceID,
		StartedAt:     a.now(),
		FinalSnapshot: map[string]any{
			"maintenance_id": maintenance.MaintenanceID,
			"name":           maintenance.Name,
			"active_since":   maintenance.ActiveSince,
			"active_till":    maintenance.ActiveTill,
			"host_ids":       hostIDs,
			"reason":         reason,
			"state":          "pending_confirmation",
			"expires_at":     expiresAt.Unix(),
		},
	})
	if err != nil {
		return nil, err
	}
	if existed && intent.Status != operation.Pending {
		return nil, errors.New("cancel intent was already consumed")
	}
	confirmID, err := a.signer.Sign(discord.ComponentToken{
		Action:        "maintenance-cancel-confirm",
		EventID:       interaction.ID,
		Route:         routeName,
		SubjectUserID: interaction.Member.User.ID,
		Expires:       expiresAt.Unix(),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"type": responseMessage,
		"data": map[string]any{
			"content": prompt,
			"flags":   ephemeralFlag,
			"components": []any{
				actionRow(button("Confirm cancellation", 4, confirmID)),
			},
		},
	}, nil
}

func (a *App) confirmCancelDowntime(
	ctx context.Context,
	interaction discord.Interaction,
	component discord.ComponentToken,
) (any, error) {
	route, ok := a.cfg.Routes[component.Route]
	if !ok || route.GuildID != interaction.GuildID ||
		route.ChannelID != interaction.ChannelID ||
		!memberAllowed(route, interaction.Member) ||
		component.SubjectUserID != interaction.Member.User.ID ||
		!route.MaintenanceEnabled {
		a.metrics.maintenanceAuthRejected.Add(1)
		return nil, errors.New("maintenance route authorization failed")
	}
	if !userIDAllowed(route.MaintenanceCancelAllowedUserIDs, interaction.Member.User.ID) {
		a.metrics.maintenanceAuthRejected.Add(1)
		return nil, errors.New("cancel requires explicit user authorization")
	}
	record, found, err := a.maintenanceOps.Get(component.EventID)
	if err != nil {
		return nil, err
	}
	if !found || record.Action != "cancel" ||
		record.Route != component.Route ||
		record.Status != operation.Pending {
		return nil, errors.New("cancel intent is missing or already consumed")
	}
	release, err := a.maintenanceLocks.Acquire(
		ctx,
		record.Route+"\x00"+record.ObjectID,
	)
	if err != nil {
		return nil, err
	}
	defer release()
	record, found, err = a.maintenanceOps.Get(component.EventID)
	if err != nil {
		return nil, err
	}
	if !found || record.Status != operation.Pending {
		return nil, errors.New("cancel intent is missing or already consumed")
	}
	routes := map[string]config.Route{component.Route: route}
	maintenance, routeName, err := a.authorizeMaintenance(
		ctx,
		routes,
		record.ObjectID,
		true,
	)
	if err != nil {
		return nil, err
	}
	if maintenanceState(maintenance, a.now()) != "scheduled" {
		return nil, errors.New("only future maintenance can be cancelled")
	}
	hosts, err := a.affectedMaintenanceHosts(ctx, maintenance)
	if err != nil {
		return nil, err
	}
	currentHostIDs, _ := maintenanceHostIdentities(hosts)
	expectedHostIDs, ok := snapshotStringSlice(
		record.FinalSnapshot,
		"host_ids",
	)
	if !ok ||
		!equalStrings(currentHostIDs, expectedHostIDs) ||
		fmt.Sprint(record.FinalSnapshot["name"]) != maintenance.Name ||
		fmt.Sprint(record.FinalSnapshot["active_since"]) != maintenance.ActiveSince ||
		fmt.Sprint(record.FinalSnapshot["active_till"]) != maintenance.ActiveTill {
		return nil, errors.New(
			"maintenance targets or window changed after confirmation was requested",
		)
	}
	for _, host := range hosts {
		if host.MaintenanceStatus == "1" {
			return nil, errors.New("a target host is currently in effective maintenance")
		}
	}
	catalog, err := a.maintenance.Maintenances(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err := a.syncMaintenanceCards(ctx, catalog, a.now()); err != nil {
		return nil, fmt.Errorf(
			"materialize maintenance card before deletion: %w",
			err,
		)
	}
	record.FinalSnapshot["state"] = "executing"
	record, err = a.maintenanceOps.Update(
		record,
		operation.Executing,
		"",
		record.FinalSnapshot,
		a.now(),
	)
	if err != nil {
		return nil, err
	}
	if err := a.maintenance.DeleteMaintenance(ctx, maintenance.MaintenanceID); err != nil {
		if errors.Is(err, zabbix.ErrMutationOutcomeUnknown) {
			current, reconcileErr := a.maintenance.Maintenances(ctx, []string{maintenance.MaintenanceID})
			if reconcileErr == nil && len(current) == 0 {
				err = nil
			}
		}
		if err != nil {
			a.recordUnknownMutation(err)
			a.recordRejectedMaintenanceOperation(record, err)
			return nil, err
		}
	}
	a.metrics.actions.Add(1)
	a.logger.Info(
		"maintenance cancelled from Discord",
		"maintenance_id", maintenance.MaintenanceID,
		"route", routeName,
		"reason", fmt.Sprint(record.FinalSnapshot["reason"]),
		"user_id", interaction.Member.User.ID,
	)
	result := fmt.Sprintf("Maintenance `%s` cancelled.", maintenance.MaintenanceID)
	record.FinalSnapshot["state"] = "cancelled"
	if err := a.completeMaintenanceOperation(
		record,
		result,
		record.FinalSnapshot,
	); err != nil {
		return nil, err
	}
	return ephemeral(result), nil
}

func (a *App) authorizeHost(
	ctx context.Context,
	routes map[string]config.Route,
	hostID string,
	forMaintenance bool,
) (zabbix.Host, string, config.Route, error) {
	if hostID == "" {
		return zabbix.Host{}, "", config.Route{}, errors.New("host is required")
	}
	hosts, err := a.maintenance.Hosts(ctx, []string{hostID})
	if err != nil {
		return zabbix.Host{}, "", config.Route{}, err
	}
	if len(hosts) != 1 || hosts[0].HostID != hostID {
		return zabbix.Host{}, "", config.Route{}, errors.New("host is not accessible")
	}
	routeName, route, err := uniqueHostRoute(hosts[0], routes, forMaintenance)
	if err != nil {
		return zabbix.Host{}, "", config.Route{}, err
	}
	if forMaintenance && len(route.MaintenanceHostIDs) > 0 &&
		!userIDAllowed(route.MaintenanceHostIDs, hostID) {
		return zabbix.Host{}, "", config.Route{}, errors.New("host is outside the runtime maintenance allowlist")
	}
	return hosts[0], routeName, route, nil
}

func (a *App) authorizeMaintenance(
	ctx context.Context,
	routes map[string]config.Route,
	maintenanceID string,
	enforceHostAllowlist bool,
) (zabbix.Maintenance, string, error) {
	if maintenanceID == "" {
		return zabbix.Maintenance{}, "", errors.New("maintenance is required")
	}
	maintenances, err := a.maintenance.Maintenances(ctx, []string{maintenanceID})
	if err != nil {
		return zabbix.Maintenance{}, "", err
	}
	if len(maintenances) != 1 || maintenances[0].MaintenanceID != maintenanceID {
		return zabbix.Maintenance{}, "", errors.New("maintenance is not editable")
	}
	routeName, hosts, err := a.maintenanceRouteAndHosts(ctx, routes, maintenances[0])
	if err != nil {
		return zabbix.Maintenance{}, "", err
	}
	if enforceHostAllowlist &&
		!maintenanceTargetsAllowlisted(routes[routeName], hosts) {
		return zabbix.Maintenance{}, "", errors.New(
			"maintenance targets are outside the runtime maintenance allowlist",
		)
	}
	return maintenances[0], routeName, nil
}

func (a *App) authorizedMaintenances(
	ctx context.Context,
	routes map[string]config.Route,
) ([]zabbix.Maintenance, error) {
	maintenances, err := a.maintenance.Maintenances(ctx, nil)
	if err != nil {
		return nil, err
	}
	result := make([]zabbix.Maintenance, 0, len(maintenances))
	for _, maintenance := range maintenances {
		if _, err := a.routeForMaintenance(ctx, routes, maintenance); err == nil {
			result = append(result, maintenance)
		}
	}
	return result, nil
}

func (a *App) routeForMaintenance(
	ctx context.Context,
	routes map[string]config.Route,
	maintenance zabbix.Maintenance,
) (string, error) {
	routeName, _, err := a.maintenanceRouteAndHosts(ctx, routes, maintenance)
	return routeName, err
}

func (a *App) maintenanceRouteAndHosts(
	ctx context.Context,
	routes map[string]config.Route,
	maintenance zabbix.Maintenance,
) (string, []zabbix.Host, error) {
	hosts, err := a.affectedMaintenanceHosts(ctx, maintenance)
	if err != nil {
		return "", nil, err
	}
	if len(hosts) == 0 {
		return "", nil, errors.New("maintenance has no accessible target hosts")
	}
	routeName := ""
	for _, host := range hosts {
		name, _, routeErr := uniqueHostRoute(host, routes, true)
		if routeErr != nil {
			return "", nil, routeErr
		}
		if routeName == "" {
			routeName = name
		} else if routeName != name {
			return "", nil, errors.New("maintenance spans multiple authorization routes")
		}
	}
	return routeName, hosts, nil
}

func (a *App) affectedMaintenanceHosts(
	ctx context.Context,
	maintenance zabbix.Maintenance,
) ([]zabbix.Host, error) {
	explicitIDs := make([]string, 0, len(maintenance.Hosts))
	for _, host := range maintenance.Hosts {
		explicitIDs = append(explicitIDs, host.HostID)
	}
	var explicit []zabbix.Host
	if len(explicitIDs) > 0 {
		var err error
		explicit, err = a.maintenance.Hosts(ctx, explicitIDs)
		if err != nil {
			return nil, err
		}
	}
	linked, err := a.maintenance.HostsByMaintenance(
		ctx,
		[]string{maintenance.MaintenanceID},
	)
	if err != nil {
		return nil, err
	}
	groupIDs := make([]string, 0, len(maintenance.HostGroups))
	for _, group := range maintenance.HostGroups {
		groupIDs = append(groupIDs, group.GroupID)
	}
	groupHosts, err := a.maintenance.HostsByGroups(ctx, groupIDs)
	if err != nil {
		return nil, err
	}
	unique := make(map[string]zabbix.Host)
	for _, hosts := range [][]zabbix.Host{explicit, linked, groupHosts} {
		for _, host := range hosts {
			if host.HostID != "" {
				unique[host.HostID] = host
			}
		}
	}
	result := make([]zabbix.Host, 0, len(unique))
	for _, host := range unique {
		result = append(result, host)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].HostID < result[right].HostID
	})
	return result, nil
}

func maintenanceTargetsAllowlisted(
	route config.Route,
	hosts []zabbix.Host,
) bool {
	if len(route.MaintenanceHostIDs) == 0 {
		return true
	}
	for _, host := range hosts {
		if !userIDAllowed(route.MaintenanceHostIDs, host.HostID) {
			return false
		}
	}
	return true
}

func maintenanceHostIdentities(
	hosts []zabbix.Host,
) ([]string, []string) {
	ids := make([]string, 0, len(hosts))
	names := make([]string, 0, len(hosts))
	for _, host := range hosts {
		ids = append(ids, host.HostID)
		names = append(
			names,
			fmt.Sprintf("%s [%s]", hostDisplayName(host), host.HostID),
		)
	}
	sort.Strings(ids)
	sort.Strings(names)
	return ids, names
}

func snapshotStringSlice(
	snapshot map[string]any,
	key string,
) ([]string, bool) {
	raw, ok := snapshot[key]
	if !ok {
		return nil, false
	}
	switch values := raw.(type) {
	case []string:
		result := append([]string(nil), values...)
		sort.Strings(result)
		return result, true
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, textOK := value.(string)
			if !textOK {
				return nil, false
			}
			result = append(result, text)
		}
		sort.Strings(result)
		return result, true
	default:
		return nil, false
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func uniqueHostRoute(
	host zabbix.Host,
	routes map[string]config.Route,
	forMaintenance bool,
) (string, config.Route, error) {
	matches := make([]string, 0, 2)
	for name, route := range routes {
		if forMaintenance && !route.MaintenanceEnabled {
			continue
		}
		if hostMatchesRoute(host, route) {
			matches = append(matches, name)
		}
	}
	if len(matches) != 1 {
		return "", config.Route{}, fmt.Errorf(
			"host must match exactly one authorized route; matched %d",
			len(matches),
		)
	}
	return matches[0], routes[matches[0]], nil
}

func hostMatchesRoute(host zabbix.Host, route config.Route) bool {
	groupMatch := false
	for _, group := range host.Groups {
		for _, expected := range route.RequiredHostGroupID {
			if group.GroupID == expected {
				groupMatch = true
			}
		}
	}
	if !groupMatch {
		return false
	}
	tags := make(map[string]string, len(host.Tags))
	duplicates := make(map[string]bool)
	for _, tag := range host.Tags {
		if existing, ok := tags[tag.Tag]; ok && existing != tag.Value {
			duplicates[tag.Tag] = true
		}
		tags[tag.Tag] = tag.Value
	}
	for key, expected := range route.HostMatchTags {
		if duplicates[key] || tags[key] != expected {
			return false
		}
	}
	return true
}

func (a *App) autocomplete(
	ctx context.Context,
	interaction discord.Interaction,
) (any, error) {
	if interaction.Data.Name != "zabbix" {
		return nil, errors.New("unsupported autocomplete")
	}
	routes := a.authorizedRoutes(interaction)
	if len(routes) == 0 {
		return autocompleteResponse(nil), nil
	}
	path, focused := focusedOption(interaction.Data.Options)
	if focused == nil {
		return autocompleteResponse(nil), nil
	}
	query := strings.ToLower(strings.TrimSpace(fmt.Sprint(focused.Value)))
	switch focused.Name {
	case "host":
		hosts, err := a.maintenance.Hosts(ctx, nil)
		if err != nil {
			return nil, err
		}
		choices := make([]map[string]any, 0, maxCommandResults)
		maintenanceStart := len(path) >= 3 &&
			path[len(path)-3].Name == "downtime" &&
			path[len(path)-2].Name == "start"
		for _, host := range hosts {
			routeName, route, routeErr := uniqueHostRoute(
				host,
				routes,
				maintenanceStart,
			)
			if routeErr != nil {
				continue
			}
			if maintenanceStart &&
				len(route.MaintenanceHostIDs) > 0 &&
				!userIDAllowed(route.MaintenanceHostIDs, host.HostID) {
				continue
			}
			label := hostDisplayName(host)
			if query != "" &&
				!strings.Contains(strings.ToLower(label), query) &&
				!strings.Contains(host.HostID, query) {
				continue
			}
			choices = append(choices, map[string]any{
				"name": truncate(
					label+" ["+host.HostID+"] · "+routeName,
					100,
				),
				"value": host.HostID,
			})
			if len(choices) == maxCommandResults {
				break
			}
		}
		return autocompleteResponse(choices), nil
	case "duration", "starts_in":
		values := durationChoicesForAutocomplete(focused.Name)
		choices := make([]map[string]any, 0, len(values))
		for _, value := range values {
			if query != "" && !strings.Contains(value, query) {
				continue
			}
			choices = append(choices, map[string]any{
				"name":  value,
				"value": value,
			})
		}
		return autocompleteResponse(choices), nil
	case "event":
		problems, err := a.zabbix.Problems(ctx, 100)
		if err != nil {
			return nil, err
		}
		choices := make([]map[string]any, 0, maxCommandResults)
		for _, problem := range problems {
			authorized := false
			for routeName, route := range routes {
				matches, matchErr := a.problemMatchesRoute(problem, routeName, route)
				if matchErr != nil {
					return nil, matchErr
				}
				authorized = authorized || matches
			}
			label := problem.EventID + " " + problem.Name
			if !authorized || (query != "" && !strings.Contains(strings.ToLower(label), query)) {
				continue
			}
			choices = append(choices, map[string]any{
				"name":  truncate(label, 100),
				"value": problem.EventID,
			})
			if len(choices) == maxCommandResults {
				break
			}
		}
		return autocompleteResponse(choices), nil
	case "maintenance":
		catalog, err := a.cachedMaintenanceCatalog(ctx, routes)
		if err != nil {
			return nil, err
		}
		action := ""
		if len(path) >= 2 {
			action = path[len(path)-2].Name
		}
		choices := make([]map[string]any, 0, maxCommandResults)
		for _, maintenance := range catalog.Maintenances {
			if action == "extend" || action == "end" || action == "cancel" {
				routeName := catalog.Routes[maintenance.MaintenanceID]
				if !maintenanceTargetsAllowlisted(
					routes[routeName],
					catalog.Targets[maintenance.MaintenanceID],
				) {
					continue
				}
			}
			state := maintenanceState(maintenance, a.now())
			if (action == "cancel" && state != "scheduled") ||
				(action == "end" && state != "active") ||
				(action == "extend" && state != "scheduled" && state != "active") {
				continue
			}
			label := maintenance.MaintenanceID + " " + maintenance.Name + " " + state
			if query != "" && !strings.Contains(strings.ToLower(label), query) {
				continue
			}
			choices = append(choices, map[string]any{
				"name":  truncate(label, 100),
				"value": maintenance.MaintenanceID,
			})
			if len(choices) == maxCommandResults {
				break
			}
		}
		return autocompleteResponse(choices), nil
	default:
		return autocompleteResponse(nil), nil
	}
}

func (a *App) cachedMaintenanceCatalog(
	ctx context.Context,
	routes map[string]config.Route,
) (maintenanceCacheEntry, error) {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	key := strings.Join(names, "\x00")
	now := a.now()
	a.maintenanceCacheMu.Lock()
	cached, ok := a.maintenanceCache[key]
	a.maintenanceCacheMu.Unlock()
	if ok && now.Before(cached.ExpiresAt) {
		return cached, nil
	}
	maintenances, err := a.maintenance.Maintenances(ctx, nil)
	if err != nil {
		return maintenanceCacheEntry{}, err
	}
	entry := maintenanceCacheEntry{
		ExpiresAt: now.Add(15 * time.Second),
		Routes:    make(map[string]string),
		Targets:   make(map[string][]zabbix.Host),
	}
	for _, maintenance := range maintenances {
		state := maintenanceState(maintenance, now)
		if state != "scheduled" && state != "active" {
			continue
		}
		routeName, hosts, routeErr := a.maintenanceRouteAndHosts(
			ctx,
			routes,
			maintenance,
		)
		if routeErr != nil {
			continue
		}
		entry.Maintenances = append(entry.Maintenances, maintenance)
		entry.Routes[maintenance.MaintenanceID] = routeName
		entry.Targets[maintenance.MaintenanceID] = hosts
	}
	a.maintenanceCacheMu.Lock()
	a.maintenanceCache[key] = entry
	a.maintenanceCacheMu.Unlock()
	return entry, nil
}

func autocompleteResponse(choices []map[string]any) map[string]any {
	if choices == nil {
		choices = []map[string]any{}
	}
	return map[string]any{
		"type": responseAutocomplete,
		"data": map[string]any{"choices": choices},
	}
}

func focusedOption(
	options []discord.InteractionOption,
) ([]discord.InteractionOption, *discord.InteractionOption) {
	for index := range options {
		option := &options[index]
		if option.Focused {
			return []discord.InteractionOption{*option}, option
		}
		if path, focused := focusedOption(option.Options); focused != nil {
			return append([]discord.InteractionOption{*option}, path...), focused
		}
	}
	return nil, nil
}

func optionString(options []discord.InteractionOption, name string) string {
	for _, option := range options {
		if option.Name == name {
			value, _ := option.Value.(string)
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func optionInt(options []discord.InteractionOption, name string, fallback int) int {
	for _, option := range options {
		if option.Name != name {
			continue
		}
		switch value := option.Value.(type) {
		case float64:
			return int(value)
		case int:
			return value
		case string:
			parsed, err := strconv.Atoi(value)
			if err == nil {
				return parsed
			}
		}
	}
	return fallback
}

func parseDuration(value string, allowZero bool) (time.Duration, error) {
	if allowZero && value == "" {
		return 0, nil
	}
	if len(value) < 2 {
		return 0, errors.New("duration must use one unit: Nm, Nh, or Nd")
	}
	unit := value[len(value)-1]
	if unit != 'm' && unit != 'h' && unit != 'd' {
		return 0, errors.New("duration must use one unit: Nm, Nh, or Nd")
	}
	number, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || number < 1 {
		return 0, errors.New("duration must use one positive integer unit")
	}
	duration := time.Duration(number) * time.Minute
	switch unit {
	case 'h':
		duration = time.Duration(number) * time.Hour
	case 'd':
		duration = time.Duration(number) * 24 * time.Hour
	}
	if duration < 5*time.Minute || duration > 7*24*time.Hour {
		return 0, errors.New("duration must be between 5m and 7d")
	}
	return duration, nil
}

func durationChoicesForAutocomplete(optionName string) []string {
	if optionName == "starts_in" {
		return []string{"5m", "15m", "30m", "1h", "2h", "4h", "8h", "24h", "2d", "7d"}
	}
	return []string{"5m", "15m", "30m", "1h", "2h", "4h", "8h", "12h", "24h", "2d", "3d", "7d"}
}

func validateReason(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len([]rune(value)) > 300 {
		return "", errors.New("reason must not exceed 300 characters")
	}
	return value, nil
}

func maintenanceAuditDescription(
	reason string,
	interaction discord.Interaction,
	routeName, action string,
) string {
	if reason == "" {
		reason = "No reason provided"
	}
	return truncate(fmt.Sprintf(
		"%s\n\nDiscord %s by %s on route %s\nDiscord interaction %s",
		reason,
		action,
		auditActor(interaction),
		routeName,
		interaction.ID,
	), 2048)
}

func unixField(value string) (time.Time, error) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, errors.New("invalid Zabbix timestamp")
	}
	return time.Unix(seconds, 0), nil
}

func oneTimeperiodIndexes(periods []zabbix.Timeperiod) []int {
	result := make([]int, 0, len(periods))
	for index, period := range periods {
		if period.TimeperiodType == timeperiodOneTime {
			result = append(result, index)
		}
	}
	return result
}

func cleanTimeperiods(
	periods []zabbix.Timeperiod,
) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(periods))
	for _, period := range periods {
		periodType, err := parseZabbixInt(period.TimeperiodType, "timeperiod_type")
		if err != nil {
			return nil, err
		}
		periodSeconds, err := parseZabbixInt(period.Period, "period")
		if err != nil {
			return nil, err
		}
		item := map[string]any{
			"timeperiod_type": periodType,
			"period":          periodSeconds,
		}
		for key, value := range map[string]string{
			"every": period.Every, "month": period.Month,
			"dayofweek": period.DayOfWeek, "day": period.Day,
			"start_time": period.StartTime, "start_date": period.StartDate,
		} {
			if value != "" {
				parsed, parseErr := parseZabbixInt(value, key)
				if parseErr != nil {
					return nil, parseErr
				}
				item[key] = parsed
			}
		}
		result = append(result, item)
	}
	return result, nil
}

func parseZabbixInt(value, field string) (int, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid Zabbix %s", field)
	}
	return int(parsed), nil
}

func appendMaintenanceAudit(existing, entry string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" {
		return truncate(entry, 2048)
	}
	remaining := 2048 - len([]rune(entry)) - 2
	if remaining <= 0 {
		return truncate(entry, 2048)
	}
	return truncate(existing, remaining) + "\n\n" + entry
}

func maintenanceState(maintenance zabbix.Maintenance, now time.Time) string {
	since, sinceErr := unixField(maintenance.ActiveSince)
	till, tillErr := unixField(maintenance.ActiveTill)
	if sinceErr != nil || tillErr != nil {
		return "unknown"
	}
	if now.Before(since) {
		return "scheduled"
	}
	if now.Before(till) {
		return "active"
	}
	return "ended"
}

func titleState(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func maintenanceHasHost(maintenance zabbix.Maintenance, hostID string) bool {
	if hostID == "" {
		return true
	}
	for _, host := range maintenance.Hosts {
		if host.HostID == hostID {
			return true
		}
	}
	return false
}

func problemHasHost(problem zabbix.Problem, hostID string) bool {
	if hostID == "" {
		return true
	}
	for _, host := range problem.Hosts {
		if host.HostID == hostID {
			return true
		}
	}
	return false
}

func hostDisplayName(host zabbix.Host) string {
	if host.Name != "" {
		return host.Name
	}
	return host.Host
}

func hostMonitoringState(status string) string {
	if status == "0" {
		return "enabled"
	}
	return "disabled"
}

func hostMaintenanceState(host zabbix.Host) string {
	if host.MaintenanceStatus == "1" {
		return "active (`" + host.MaintenanceID + "`)"
	}
	return "none"
}

func userIDAllowed(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (a *App) beginMaintenanceOperation(
	ctx context.Context,
	interaction discord.Interaction,
	action, route, objectID string,
) (operation.Record, string, func(), error) {
	release, err := a.maintenanceLocks.Acquire(ctx, route+"\x00"+objectID)
	if err != nil {
		return operation.Record{}, "", func() {}, err
	}
	record, existed, err := a.maintenanceOps.Begin(operation.Record{
		InteractionID: interaction.ID,
		Action:        action,
		Route:         route,
		ObjectID:      objectID,
		StartedAt:     a.now(),
	})
	if err != nil {
		release()
		return operation.Record{}, "", func() {}, err
	}
	if existed {
		if record.Status == operation.Completed {
			return record, record.Result, release, nil
		}
		release()
		return operation.Record{}, "", func() {}, errors.New(
			"the same maintenance operation is pending reconciliation",
		)
	}
	record, err = a.maintenanceOps.Update(
		record,
		operation.Executing,
		"",
		nil,
		a.now(),
	)
	if err != nil {
		release()
		return operation.Record{}, "", func() {}, err
	}
	return record, "", release, nil
}

func (a *App) completeMaintenanceOperation(
	record operation.Record,
	result string,
	snapshot map[string]any,
) error {
	_, err := a.maintenanceOps.Update(
		record,
		operation.Completed,
		result,
		snapshot,
		a.now(),
	)
	return err
}

func (a *App) recordMaintenanceIntent(
	record operation.Record,
	snapshot map[string]any,
) (operation.Record, error) {
	return a.maintenanceOps.Update(
		record,
		operation.Executing,
		"",
		snapshot,
		a.now(),
	)
}

func (a *App) recordUnknownMutation(err error) {
	if errors.Is(err, zabbix.ErrMutationOutcomeUnknown) {
		a.metrics.maintenanceMutationUnknown.Add(1)
	}
}

func (a *App) recordRejectedMaintenanceOperation(
	record operation.Record,
	mutationErr error,
) {
	if errors.Is(mutationErr, zabbix.ErrMutationOutcomeUnknown) {
		return
	}
	snapshot := record.FinalSnapshot
	if snapshot == nil {
		snapshot = map[string]any{}
	}
	snapshot["state"] = "rejected"
	if _, err := a.maintenanceOps.Update(
		record,
		operation.Completed,
		"Zabbix rejected the maintenance mutation.",
		snapshot,
		a.now(),
	); err != nil {
		a.metrics.errors.Add(1)
		a.logger.Error(
			"persist rejected maintenance operation",
			"interaction_id", record.InteractionID,
			"error", err,
		)
	}
}

func (a *App) reconcileMaintenanceState(ctx context.Context, now time.Time) {
	operationContext, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	maintenances, err := a.maintenance.Maintenances(operationContext, nil)
	if err != nil {
		a.failMaintenanceSync(ctx, "synchronize Zabbix maintenance state", err)
		return
	}
	if err := a.syncMaintenanceCards(operationContext, maintenances, now); err != nil {
		a.failMaintenanceSync(ctx, "synchronize Discord maintenance cards", err)
		return
	}
	if err := a.reconcileMaintenanceOperations(
		operationContext,
		maintenances,
		now,
	); err != nil {
		a.failMaintenanceSync(ctx, "reconcile maintenance mutation outcomes", err)
		return
	}
	oldest, pending, err := a.maintenanceOps.OldestPending(now)
	if err != nil {
		a.failMaintenanceSync(ctx, "inspect pending maintenance operations", err)
		return
	}
	a.metrics.maintenancePending.Store(uint64(pending))
	a.metrics.maintenancePendingAge.Store(int64(oldest.Seconds()))
	a.metrics.maintenanceLastSync.Store(now.Unix())
	a.metrics.maintenanceSyncDegraded.Store(0)
}

func (a *App) failMaintenanceSync(
	ctx context.Context,
	operationName string,
	syncErr error,
) {
	a.metrics.errors.Add(1)
	a.metrics.maintenanceSyncDegraded.Store(1)
	a.logger.Error(operationName, "error", syncErr)
	cardContext, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := a.markMaintenanceCardsDegraded(cardContext, a.now()); err != nil {
		a.metrics.errors.Add(1)
		a.logger.Error("mark maintenance cards sync degraded", "error", err)
	}
}

func (a *App) reconcileMaintenanceOperations(
	ctx context.Context,
	maintenances []zabbix.Maintenance,
	now time.Time,
) error {
	records, err := a.maintenanceOps.List()
	if err != nil {
		return err
	}
	byID := make(map[string]zabbix.Maintenance, len(maintenances))
	for _, maintenance := range maintenances {
		byID[maintenance.MaintenanceID] = maintenance
	}
	for _, record := range records {
		if record.Status == operation.Completed {
			continue
		}
		if record.FinalSnapshot == nil {
			continue
		}
		if record.Status == operation.Pending {
			expiresAt, ok := snapshotInt64(
				record.FinalSnapshot,
				"expires_at",
			)
			if record.Action == "cancel" && ok && now.Unix() >= expiresAt {
				record.FinalSnapshot["state"] = "expired"
				if _, err := a.maintenanceOps.Update(
					record,
					operation.Completed,
					"Discord cancellation confirmation expired without mutation.",
					record.FinalSnapshot,
					now,
				); err != nil {
					return err
				}
			}
			continue
		}
		var (
			confirmed bool
			result    string
			snapshot  = record.FinalSnapshot
		)
		switch record.Action {
		case "start":
			marker := "Discord interaction " + record.InteractionID
			hostID, _ := snapshot["host_id"].(string)
			for _, maintenance := range maintenances {
				if !strings.Contains(maintenance.Description, marker) {
					continue
				}
				hosts, hostErr := a.affectedMaintenanceHosts(ctx, maintenance)
				if hostErr != nil {
					return hostErr
				}
				found := false
				for _, host := range hosts {
					found = found || host.HostID == hostID
				}
				if !found {
					continue
				}
				confirmed = true
				snapshot["maintenance_id"] = maintenance.MaintenanceID
				snapshot["state"] = maintenanceState(maintenance, now)
				result = fmt.Sprintf(
					"Maintenance `%s` creation reconciled from live Zabbix state.",
					maintenance.MaintenanceID,
				)
				break
			}
		case "extend":
			maintenance, exists := byID[record.ObjectID]
			expectedTill, expectedOK := snapshotInt64(snapshot, "active_till")
			actualTill, actualErr := strconv.ParseInt(
				maintenance.ActiveTill,
				10,
				64,
			)
			confirmed = exists && expectedOK && actualErr == nil &&
				actualTill == expectedTill
			if confirmed {
				snapshot["state"] = maintenanceState(maintenance, now)
				result = fmt.Sprintf(
					"Maintenance `%s` %s reconciled from live Zabbix state.",
					record.ObjectID,
					record.Action,
				)
			}
		case "end":
			maintenance, exists := byID[record.ObjectID]
			expectedTill, expectedOK := snapshotInt64(snapshot, "active_till")
			actualTill, actualErr := strconv.ParseInt(
				maintenance.ActiveTill,
				10,
				64,
			)
			confirmed = exists && expectedOK && actualErr == nil &&
				actualTill == expectedTill && now.Unix() >= expectedTill
			if confirmed {
				hosts, hostErr := a.affectedMaintenanceHosts(ctx, maintenance)
				if hostErr != nil {
					return hostErr
				}
				for _, host := range hosts {
					if host.MaintenanceStatus == "1" &&
						host.MaintenanceID == record.ObjectID {
						confirmed = false
					}
				}
			}
			if confirmed {
				snapshot["state"] = "ended"
				result = fmt.Sprintf(
					"Maintenance `%s` end confirmed from live Zabbix state.",
					record.ObjectID,
				)
			}
		case "cancel":
			_, exists := byID[record.ObjectID]
			confirmed = !exists
			if confirmed {
				snapshot["state"] = "cancelled"
				result = fmt.Sprintf(
					"Maintenance `%s` cancellation reconciled from live Zabbix state.",
					record.ObjectID,
				)
			}
		}
		if !confirmed {
			continue
		}
		record, err = a.maintenanceOps.Update(
			record,
			operation.Reconciled,
			result,
			snapshot,
			now,
		)
		if err != nil {
			return err
		}
		if _, err := a.maintenanceOps.Update(
			record,
			operation.Completed,
			result,
			snapshot,
			now,
		); err != nil {
			return err
		}
	}
	return nil
}

func snapshotInt64(snapshot map[string]any, key string) (int64, bool) {
	value, ok := snapshot[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil
	default:
		return 0, false
	}
}

func (a *App) syncMaintenanceCards(
	ctx context.Context,
	maintenances []zabbix.Maintenance,
	now time.Time,
) error {
	a.maintenanceCardsMu.Lock()
	defer a.maintenanceCardsMu.Unlock()

	records, err := a.maintenanceCards.List()
	if err != nil {
		return err
	}
	recordByID := make(map[string]maintenancecard.Record, len(records))
	for _, record := range records {
		recordByID[record.MaintenanceID] = record
	}
	seen := make(map[string]struct{}, len(maintenances))
	for _, maintenance := range maintenances {
		activeTill, tillErr := unixField(maintenance.ActiveTill)
		if tillErr != nil {
			return tillErr
		}
		existing, tracked := recordByID[maintenance.MaintenanceID]
		if !tracked && activeTill.Before(now.Add(-5*time.Minute)) {
			continue
		}
		hosts, hostErr := a.affectedMaintenanceHosts(ctx, maintenance)
		if hostErr != nil {
			return hostErr
		}
		routeName := ""
		for _, host := range hosts {
			name, _, routeErr := uniqueHostRoute(host, a.cfg.Routes, true)
			if routeErr != nil {
				routeName = ""
				break
			}
			if routeName == "" {
				routeName = name
			} else if routeName != name {
				routeName = ""
				break
			}
		}
		if routeName == "" {
			continue
		}
		route := a.cfg.Routes[routeName]
		state := effectiveMaintenanceState(maintenance, hosts, now)
		if state == "ended" &&
			!strings.Contains(maintenance.Description, "Discord ending ") {
			state = "expired"
		}
		fingerprint, fingerprintErr := maintenanceFingerprint(
			routeName,
			maintenance,
			hosts,
			state,
		)
		if fingerprintErr != nil {
			return fingerprintErr
		}
		record := existing
		if !tracked {
			record = maintenancecard.Record{
				MaintenanceID:  maintenance.MaintenanceID,
				Route:          routeName,
				ChannelID:      route.ChannelID,
				MirrorMessages: map[string]string{},
			}
		}
		if record.MirrorMessages == nil {
			record.MirrorMessages = map[string]string{}
		}
		changed := record.State != state ||
			fmt.Sprint(record.FinalSnapshot["fingerprint"]) != fingerprint
		if record.Route != routeName || record.ChannelID != route.ChannelID {
			return errors.New("stored maintenance card route no longer matches")
		}
		payload := a.maintenanceCardMessage(
			routeName,
			maintenance,
			hosts,
			state,
			false,
		)
		if record.MessageID == "" {
			if !tracked {
				record.State = state
				record.LastSeenAt = now.UTC()
				record.FinalSnapshot = maintenanceSnapshot(
					maintenance,
					hosts,
					state,
				)
				record.FinalSnapshot["fingerprint"] = fingerprint
				if err := a.maintenanceCards.Put(record); err != nil {
					return err
				}
			}
			payload["nonce"] = maintenanceNonce(maintenance.MaintenanceID, route.ChannelID)
			payload["enforce_nonce"] = true
			message, found, findErr := a.discord.FindMessageByNonce(
				ctx,
				route.ChannelID,
				maintenanceNonce(maintenance.MaintenanceID, route.ChannelID),
				record.LastSeenAt,
			)
			if findErr != nil {
				a.metrics.maintenancePrimaryPublishErrors.Add(1)
				return findErr
			}
			if !found {
				message, findErr = a.discord.CreateMessage(
					ctx,
					route.ChannelID,
					payload,
				)
			}
			if findErr != nil {
				a.metrics.maintenancePrimaryPublishErrors.Add(1)
				return findErr
			}
			if !expectedDiscordMessage(message, route.ChannelID, a.cfg.DiscordBotUserID) {
				a.metrics.maintenancePrimaryPublishErrors.Add(1)
				return errors.New("unexpected primary maintenance card identity")
			}
			record.MessageID = message.ID
			if err := a.maintenanceCards.Put(record); err != nil {
				return err
			}
		} else if changed {
			if editErr := a.discord.EditMessage(
				ctx,
				route.ChannelID,
				record.MessageID,
				payload,
			); editErr != nil {
				a.metrics.maintenancePrimaryPublishErrors.Add(1)
				return editErr
			}
		}
		for _, channelID := range route.MirrorChannelIDs {
			mirrorPayload := a.maintenanceCardMessage(
				routeName,
				maintenance,
				hosts,
				state,
				true,
			)
			messageID, mirrorTracked := record.MirrorMessages[channelID]
			if messageID == "" {
				if !mirrorTracked {
					record.MirrorMessages[channelID] = ""
					if err := a.maintenanceCards.Put(record); err != nil {
						return err
					}
				}
				mirrorPayload["nonce"] = maintenanceNonce(maintenance.MaintenanceID, channelID)
				mirrorPayload["enforce_nonce"] = true
				message, found, findErr := a.discord.FindMessageByNonce(
					ctx,
					channelID,
					maintenanceNonce(maintenance.MaintenanceID, channelID),
					record.LastSeenAt,
				)
				if findErr != nil {
					a.metrics.maintenanceMirrorPublishErrors.Add(1)
					return findErr
				}
				if !found {
					message, findErr = a.discord.CreateMessage(
						ctx,
						channelID,
						mirrorPayload,
					)
				}
				if findErr != nil {
					a.metrics.maintenanceMirrorPublishErrors.Add(1)
					return findErr
				}
				if !expectedDiscordMessage(message, channelID, a.cfg.DiscordBotUserID) {
					a.metrics.maintenanceMirrorPublishErrors.Add(1)
					return errors.New("unexpected mirror maintenance card identity")
				}
				record.MirrorMessages[channelID] = message.ID
				if err := a.maintenanceCards.Put(record); err != nil {
					return err
				}
			} else if changed {
				if editErr := a.discord.EditMessage(
					ctx,
					channelID,
					messageID,
					mirrorPayload,
				); editErr != nil {
					a.metrics.maintenanceMirrorPublishErrors.Add(1)
					return editErr
				}
			}
		}
		record.State = state
		record.LastSeenAt = now.UTC()
		record.FinalSnapshot = maintenanceSnapshot(maintenance, hosts, state)
		record.FinalSnapshot["fingerprint"] = fingerprint
		if err := a.maintenanceCards.Put(record); err != nil {
			return err
		}
		seen[maintenance.MaintenanceID] = struct{}{}
	}
	for _, record := range records {
		if _, ok := seen[record.MaintenanceID]; ok ||
			record.State == "cancelled" || record.State == "ended" ||
			record.State == "expired" {
			continue
		}
		state := "ended"
		previousState := record.State
		if record.State == "sync_degraded" {
			if stored, ok := record.FinalSnapshot["state_before_degraded"].(string); ok {
				previousState = stored
			}
		}
		if previousState == "scheduled" || previousState == "activating" {
			state = "cancelled"
		}
		route, ok := a.cfg.Routes[record.Route]
		if !ok || !route.MaintenanceEnabled {
			continue
		}
		payload := missingMaintenanceCardMessage(record, state, a.cfg.DisplayName)
		if record.MessageID != "" {
			if err := a.discord.EditMessage(
				ctx,
				record.ChannelID,
				record.MessageID,
				payload,
			); err != nil {
				a.metrics.maintenancePrimaryPublishErrors.Add(1)
				return err
			}
		}
		for channelID, messageID := range record.MirrorMessages {
			if messageID == "" {
				continue
			}
			if err := a.discord.EditMessage(
				ctx,
				channelID,
				messageID,
				missingMaintenanceCardMessage(record, state, a.cfg.DisplayName),
			); err != nil {
				a.metrics.maintenanceMirrorPublishErrors.Add(1)
				return err
			}
		}
		record.State = state
		record.LastSeenAt = now.UTC()
		if record.FinalSnapshot == nil {
			record.FinalSnapshot = map[string]any{}
		}
		record.FinalSnapshot["state"] = state
		if err := a.maintenanceCards.Put(record); err != nil {
			return err
		}
	}
	currentRecords, err := a.maintenanceCards.List()
	if err != nil {
		return err
	}
	a.storeMaintenanceStateCounts(currentRecords)
	return nil
}

func (a *App) markMaintenanceCardsDegraded(
	ctx context.Context,
	now time.Time,
) error {
	a.maintenanceCardsMu.Lock()
	defer a.maintenanceCardsMu.Unlock()

	records, err := a.maintenanceCards.List()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.MessageID == "" ||
			record.State == "ended" ||
			record.State == "expired" ||
			record.State == "cancelled" {
			continue
		}
		payload := degradedMaintenanceCardMessage(record, a.cfg.DisplayName)
		if err := a.discord.EditMessage(
			ctx,
			record.ChannelID,
			record.MessageID,
			payload,
		); err != nil {
			a.metrics.maintenancePrimaryPublishErrors.Add(1)
			return err
		}
		for channelID, messageID := range record.MirrorMessages {
			if messageID == "" {
				continue
			}
			mirrorPayload := degradedMaintenanceCardMessage(
				record,
				a.cfg.DisplayName,
			)
			if err := a.discord.EditMessage(
				ctx,
				channelID,
				messageID,
				mirrorPayload,
			); err != nil {
				a.metrics.maintenanceMirrorPublishErrors.Add(1)
				return err
			}
		}
		if record.FinalSnapshot == nil {
			record.FinalSnapshot = map[string]any{}
		}
		if record.State != "sync_degraded" {
			record.FinalSnapshot["state_before_degraded"] = record.State
		}
		record.State = "sync_degraded"
		record.LastSeenAt = now.UTC()
		if err := a.maintenanceCards.Put(record); err != nil {
			return err
		}
	}
	return nil
}

func degradedMaintenanceCardMessage(
	record maintenancecard.Record,
	displayName string,
) map[string]any {
	return map[string]any{
		"embeds": []any{map[string]any{
			"title":       "Sync degraded: maintenance " + record.MaintenanceID,
			"description": "Live Zabbix maintenance state could not be confirmed. Actions remain fail-closed until synchronization recovers.",
			"color":       maintenanceStateColor("ending"),
			"fields": []any{
				map[string]any{"name": "Maintenance", "value": record.MaintenanceID, "inline": true},
				map[string]any{"name": "Route", "value": record.Route, "inline": true},
			},
			"footer": map[string]any{"text": displayName},
		}},
		"components": []any{},
	}
}

func (a *App) storeMaintenanceStateCounts(
	records []maintenancecard.Record,
) {
	counts := map[string]uint64{}
	for _, record := range records {
		counts[record.State]++
	}
	a.metrics.maintenanceScheduled.Store(counts["scheduled"])
	a.metrics.maintenanceActivating.Store(counts["activating"])
	a.metrics.maintenanceActive.Store(counts["active"])
	a.metrics.maintenanceEnding.Store(counts["ending"])
	a.metrics.maintenanceEnded.Store(counts["ended"])
	a.metrics.maintenanceExpired.Store(counts["expired"])
	a.metrics.maintenanceCancelled.Store(counts["cancelled"])
}

func (a *App) maintenanceCardMessage(
	routeName string,
	maintenance zabbix.Maintenance,
	hosts []zabbix.Host,
	state string,
	readOnly bool,
) map[string]any {
	names := make([]string, 0, len(hosts))
	for _, host := range hosts {
		names = append(names, hostDisplayName(host))
	}
	sort.Strings(names)
	description := strings.TrimSpace(maintenance.Description)
	if description == "" {
		description = "No reason provided."
	}
	payload := map[string]any{
		"embeds": []any{map[string]any{
			"title":       fmt.Sprintf("%s: %s", titleState(state), truncate(maintenance.Name, 180)),
			"description": truncate(description, 2000),
			"color":       maintenanceStateColor(state),
			"fields": []any{
				map[string]any{"name": "Hosts", "value": truncate(strings.Join(names, "\n"), 1024), "inline": false},
				map[string]any{"name": "Window", "value": fmt.Sprintf(
					"<t:%s:F> → <t:%s:F>", maintenance.ActiveSince, maintenance.ActiveTill,
				), "inline": false},
				map[string]any{"name": "Maintenance", "value": maintenance.MaintenanceID, "inline": true},
				map[string]any{"name": "Route", "value": routeName, "inline": true},
			},
			"footer": map[string]any{"text": a.cfg.DisplayName},
		}},
		"components": []any{},
	}
	if readOnly {
		payload["components"] = []any{}
	}
	return payload
}

func missingMaintenanceCardMessage(
	record maintenancecard.Record,
	state, displayName string,
) map[string]any {
	name := fmt.Sprint(record.FinalSnapshot["name"])
	if name == "" || name == "<nil>" {
		name = "maintenance " + record.MaintenanceID
	}
	description := fmt.Sprint(record.FinalSnapshot["description"])
	if description == "" || description == "<nil>" {
		description = "No reason provided."
	}
	targets := snapshotDisplayTargets(record.FinalSnapshot)
	window := fmt.Sprintf(
		"<t:%v:F> → <t:%v:F>",
		record.FinalSnapshot["active_since"],
		record.FinalSnapshot["active_till"],
	)
	resultText := "The maintenance object is no longer present in the editable Zabbix view."
	if state == "cancelled" {
		resultText = "Zabbix confirmed that the maintenance object was deleted."
	}
	return map[string]any{
		"embeds": []any{map[string]any{
			"title":       titleState(state) + ": " + truncate(name, 180),
			"description": truncate(description+"\n\n"+resultText, 2000),
			"color":       maintenanceStateColor(state),
			"fields": []any{
				map[string]any{"name": "Targets", "value": truncate(targets, 1024), "inline": false},
				map[string]any{"name": "Window", "value": window, "inline": false},
				map[string]any{"name": "Maintenance", "value": record.MaintenanceID, "inline": true},
				map[string]any{"name": "Route", "value": record.Route, "inline": true},
			},
			"footer": map[string]any{"text": displayName},
		}},
		"components": []any{},
	}
}

func effectiveMaintenanceState(
	maintenance zabbix.Maintenance,
	hosts []zabbix.Host,
	now time.Time,
) string {
	state := maintenanceState(maintenance, now)
	effective := false
	for _, host := range hosts {
		effective = effective || (host.MaintenanceStatus == "1" &&
			host.MaintenanceID == maintenance.MaintenanceID)
	}
	switch {
	case state == "scheduled":
		return "scheduled"
	case state == "active" && !effective:
		return "activating"
	case state == "active":
		return "active"
	case state == "ended" && effective:
		return "ending"
	default:
		return "ended"
	}
}

func maintenanceStateColor(state string) int {
	switch state {
	case "active":
		return 0xFFC859
	case "activating", "ending":
		return 0xFFA059
	case "cancelled":
		return 0x97AAB3
	case "ended", "expired":
		return 0x59BA6A
	default:
		return 0x7499FF
	}
}

func maintenanceSnapshot(
	maintenance zabbix.Maintenance,
	hosts []zabbix.Host,
	state string,
) map[string]any {
	hostIDs := make([]string, 0, len(hosts))
	hostNames := make([]string, 0, len(hosts))
	for _, host := range hosts {
		hostIDs = append(hostIDs, host.HostID)
		hostNames = append(
			hostNames,
			fmt.Sprintf("%s [%s]", hostDisplayName(host), host.HostID),
		)
	}
	sort.Strings(hostIDs)
	sort.Strings(hostNames)
	return map[string]any{
		"maintenance_id": maintenance.MaintenanceID,
		"name":           maintenance.Name,
		"description":    maintenance.Description,
		"state":          state,
		"active_since":   maintenance.ActiveSince,
		"active_till":    maintenance.ActiveTill,
		"host_ids":       hostIDs,
		"host_names":     hostNames,
	}
}

func snapshotDisplayTargets(snapshot map[string]any) string {
	values, ok := snapshotStringSlice(snapshot, "host_names")
	if ok && len(values) > 0 {
		return strings.Join(values, "\n")
	}
	values, ok = snapshotStringSlice(snapshot, "host_ids")
	if ok && len(values) > 0 {
		return strings.Join(values, "\n")
	}
	return "Unknown"
}

func maintenanceFingerprint(
	routeName string,
	maintenance zabbix.Maintenance,
	hosts []zabbix.Host,
	state string,
) (string, error) {
	hostIDs, _ := maintenanceHostIdentities(hosts)
	raw, err := json.Marshal(map[string]any{
		"route":          routeName,
		"maintenance_id": maintenance.MaintenanceID,
		"name":           maintenance.Name,
		"description":    maintenance.Description,
		"active_since":   maintenance.ActiveSince,
		"active_till":    maintenance.ActiveTill,
		"host_ids":       hostIDs,
		"state":          state,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func maintenanceNonce(maintenanceID, channelID string) string {
	digest := sha256.Sum256([]byte("maintenance-card\x00" + maintenanceID + "\x00" + channelID))
	return strconv.FormatUint(binary.BigEndian.Uint64(digest[:8]), 10)
}
