package app

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/maiko/zabbix-discord-ops/internal/config"
	"github.com/maiko/zabbix-discord-ops/internal/discord"
	"github.com/maiko/zabbix-discord-ops/internal/maintenancecard"
	"github.com/maiko/zabbix-discord-ops/internal/zabbix"
)

type fakeMaintenance struct {
	hosts          []zabbix.Host
	groupHosts     []zabbix.Host
	maintenances   []zabbix.Maintenance
	createParams   map[string]any
	updateParams   map[string]any
	deleteCalls    int
	emptyHostQuery bool
}

func (f *fakeMaintenance) Hosts(
	_ context.Context,
	hostIDs []string,
) ([]zabbix.Host, error) {
	if len(hostIDs) == 0 {
		f.emptyHostQuery = true
		return f.hosts, nil
	}
	result := make([]zabbix.Host, 0, len(hostIDs))
	for _, host := range f.hosts {
		for _, hostID := range hostIDs {
			if host.HostID == hostID {
				result = append(result, host)
			}
		}
	}
	return result, nil
}

func (f *fakeMaintenance) HostsByMaintenance(
	_ context.Context,
	maintenanceIDs []string,
) ([]zabbix.Host, error) {
	if len(maintenanceIDs) == 0 {
		return nil, nil
	}
	result := make([]zabbix.Host, 0)
	for _, maintenance := range f.maintenances {
		if maintenance.MaintenanceID != maintenanceIDs[0] {
			continue
		}
		for _, explicit := range maintenance.Hosts {
			for _, host := range f.hosts {
				if host.HostID == explicit.HostID {
					result = append(result, host)
				}
			}
		}
	}
	return result, nil
}

func (f *fakeMaintenance) HostsByGroups(
	_ context.Context,
	groupIDs []string,
) ([]zabbix.Host, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	return append([]zabbix.Host(nil), f.groupHosts...), nil
}

func (f *fakeMaintenance) Maintenances(
	_ context.Context,
	maintenanceIDs []string,
) ([]zabbix.Maintenance, error) {
	if len(maintenanceIDs) == 0 {
		return append([]zabbix.Maintenance(nil), f.maintenances...), nil
	}
	result := make([]zabbix.Maintenance, 0, len(maintenanceIDs))
	for _, maintenance := range f.maintenances {
		for _, maintenanceID := range maintenanceIDs {
			if maintenance.MaintenanceID == maintenanceID {
				result = append(result, maintenance)
			}
		}
	}
	return result, nil
}

func (f *fakeMaintenance) CreateMaintenance(
	_ context.Context,
	params map[string]any,
) (string, error) {
	f.createParams = params
	return "9001", nil
}

func (f *fakeMaintenance) UpdateMaintenance(
	_ context.Context,
	params map[string]any,
) error {
	f.updateParams = params
	return nil
}

func (f *fakeMaintenance) DeleteMaintenance(
	_ context.Context,
	maintenanceID string,
) error {
	f.deleteCalls++
	for index, maintenance := range f.maintenances {
		if maintenance.MaintenanceID == maintenanceID {
			f.maintenances = append(
				f.maintenances[:index],
				f.maintenances[index+1:]...,
			)
			return nil
		}
	}
	return errors.New("maintenance not found")
}

func maintenanceTestApp(t *testing.T) (*App, *fakeMaintenance) {
	t.Helper()
	application, _, _, _ := testApp(t)
	route := application.cfg.Routes["prod"]
	route.HostMatchTags = map[string]string{"tenant": "example"}
	route.MaintenanceEnabled = true
	route.MaintenanceHostIDs = []string{"2001"}
	route.MaintenanceCancelAllowedUserIDs = []string{"1005"}
	application.cfg.Routes["prod"] = route
	host := zabbix.Host{
		HostID: "2001",
		Host:   "host.example.test",
		Name:   "Host",
		Status: "0",
		Groups: []zabbix.HostGroup{{
			GroupID: "1003",
			Name:    "Tenants/Example",
		}},
		Tags: []zabbix.Tag{{Tag: "tenant", Value: "example"}},
	}
	maintenance := &fakeMaintenance{hosts: []zabbix.Host{host}}
	application.maintenance = maintenance
	return application, maintenance
}

func maintenanceInteraction(id string) discord.Interaction {
	return discord.Interaction{
		ID:            id,
		ApplicationID: "1006",
		Token:         "interaction-token",
		GuildID:       "1001",
		ChannelID:     "1002",
		Member: discord.Member{
			User:  discord.User{ID: "1005", Username: "operator"},
			Roles: []string{"1004"},
		},
	}
}

func TestStartDowntimeUsesTypedBoundedPayload(t *testing.T) {
	application, maintenance := maintenanceTestApp(t)
	routes := map[string]config.Route{
		"prod": application.cfg.Routes["prod"],
	}
	interaction := maintenanceInteraction("5001")
	payload, err := application.startDowntime(
		context.Background(),
		interaction,
		routes,
		[]discord.InteractionOption{
			{Name: "host", Value: "2001"},
			{Name: "duration", Value: "15m"},
			{Name: "reason", Value: "Routine work"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if payload == nil || maintenance.createParams == nil {
		t.Fatal("maintenance was not created")
	}
	if maintenance.createParams["name"] != "Discord [5001]: Host" {
		t.Fatalf("unexpected unique name: %#v", maintenance.createParams["name"])
	}
	periods, ok := maintenance.createParams["timeperiods"].([]map[string]any)
	if !ok || len(periods) != 1 {
		t.Fatalf("unexpected periods: %#v", maintenance.createParams["timeperiods"])
	}
	if _, ok := periods[0]["period"].(int64); !ok {
		t.Fatalf("period is not an integer: %#v", periods[0]["period"])
	}
	if maintenance.createParams["maintenance_type"] != 0 {
		t.Fatal("maintenance must collect data")
	}
}

func TestGroupTargetsAreExpandedAndCrossRouteFailsClosed(t *testing.T) {
	application, maintenance := maintenanceTestApp(t)
	maintenance.maintenances = []zabbix.Maintenance{{
		MaintenanceID: "9002",
		HostGroups: []zabbix.HostGroup{{
			GroupID: "1003",
			Name:    "Tenants/Example",
		}},
	}}
	maintenance.groupHosts = append([]zabbix.Host(nil), maintenance.hosts...)
	hosts, err := application.affectedMaintenanceHosts(
		context.Background(),
		maintenance.maintenances[0],
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].HostID != "2001" {
		t.Fatalf("group expansion returned %#v", hosts)
	}
	if maintenance.emptyHostQuery {
		t.Fatal("group-only expansion issued an unfiltered host query")
	}

	crossRoute := maintenance.hosts[0]
	crossRoute.HostID = "2002"
	crossRoute.Groups = []zabbix.HostGroup{{GroupID: "1007"}}
	crossRoute.Tags = []zabbix.Tag{{Tag: "tenant", Value: "other"}}
	maintenance.groupHosts = append(maintenance.groupHosts, crossRoute)
	routes := map[string]config.Route{
		"prod": application.cfg.Routes["prod"],
		"other": {
			RequiredHostGroupID: []string{"1007"},
			HostMatchTags:       map[string]string{"tenant": "other"},
			MaintenanceEnabled:  true,
		},
	}
	if _, _, err := application.maintenanceRouteAndHosts(
		context.Background(),
		routes,
		maintenance.maintenances[0],
	); err == nil {
		t.Fatal("cross-route group maintenance was authorized")
	}
}

func TestCancelConfirmationIsSnapshotBoundAndSingleUse(t *testing.T) {
	application, maintenance := maintenanceTestApp(t)
	now := application.now()
	maintenance.maintenances = []zabbix.Maintenance{{
		MaintenanceID: "9003",
		Name:          "Future maintenance",
		Description:   "Routine work",
		ActiveSince:   formatUnix(now.Add(time.Hour)),
		ActiveTill:    formatUnix(now.Add(2 * time.Hour)),
		Hosts:         []zabbix.Host{{HostID: "2001"}},
		Timeperiods: []zabbix.Timeperiod{{
			TimeperiodType: "0",
			StartDate:      formatUnix(now.Add(time.Hour)),
			Period:         "3600",
		}},
	}}
	routes := map[string]config.Route{
		"prod": application.cfg.Routes["prod"],
	}
	interaction := maintenanceInteraction("5002")
	response, err := application.cancelDowntime(
		context.Background(),
		interaction,
		routes,
		[]discord.InteractionOption{
			{Name: "maintenance", Value: "9003"},
			{Name: "reason", Value: "No longer needed"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	customID := confirmationCustomID(t, response)
	component, err := application.signer.Verify(customID, now)
	if err != nil {
		t.Fatal(err)
	}
	if component.SubjectUserID != interaction.Member.User.ID {
		t.Fatal("confirmation is not bound to the requesting user")
	}
	if _, err := application.confirmCancelDowntime(
		context.Background(),
		interaction,
		component,
	); err != nil {
		t.Fatal(err)
	}
	if maintenance.deleteCalls != 1 {
		t.Fatalf("delete calls = %d", maintenance.deleteCalls)
	}
	if _, err := application.confirmCancelDowntime(
		context.Background(),
		interaction,
		component,
	); err == nil {
		t.Fatal("consumed confirmation was accepted twice")
	}
	if maintenance.deleteCalls != 1 {
		t.Fatalf("replay caused %d delete calls", maintenance.deleteCalls)
	}
}

func TestPendingMaintenanceCardTerminalizesWhenObjectDisappears(t *testing.T) {
	application, _ := maintenanceTestApp(t)
	route := application.cfg.Routes["prod"]
	route.MirrorChannelIDs = []string{"1007"}
	application.cfg.Routes["prod"] = route
	now := application.now()
	record := maintenancecard.Record{
		MaintenanceID:  "9004",
		Route:          "prod",
		ChannelID:      "1002",
		MirrorMessages: map[string]string{"1007": ""},
		State:          "scheduled",
		LastSeenAt:     now,
		FinalSnapshot:  map[string]any{"state": "scheduled"},
	}
	if err := application.maintenanceCards.Put(record); err != nil {
		t.Fatal(err)
	}

	if err := application.syncMaintenanceCards(
		context.Background(),
		nil,
		now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	stored, found, err := application.maintenanceCards.Get("9004", "prod")
	if err != nil || !found {
		t.Fatalf("read terminal card: found=%t err=%v", found, err)
	}
	if stored.State != "cancelled" {
		t.Fatalf("pending card state = %q", stored.State)
	}
	discordClient := application.discord.(*fakeDiscord)
	if len(discordClient.editedMessages) != 0 {
		t.Fatalf("empty message IDs were edited: %#v", discordClient.editedMessages)
	}
}

func TestDegradedSyncSkipsPendingMirror(t *testing.T) {
	application, _ := maintenanceTestApp(t)
	now := application.now()
	record := maintenancecard.Record{
		MaintenanceID:  "9005",
		Route:          "prod",
		ChannelID:      "1002",
		MessageID:      "2001",
		MirrorMessages: map[string]string{"1007": ""},
		State:          "active",
		LastSeenAt:     now,
		FinalSnapshot:  map[string]any{"state": "active"},
	}
	if err := application.maintenanceCards.Put(record); err != nil {
		t.Fatal(err)
	}

	if err := application.markMaintenanceCardsDegraded(
		context.Background(),
		now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	stored, found, err := application.maintenanceCards.Get("9005", "prod")
	if err != nil || !found {
		t.Fatalf("read degraded card: found=%t err=%v", found, err)
	}
	if stored.State != "sync_degraded" {
		t.Fatalf("degraded card state = %q", stored.State)
	}
	discordClient := application.discord.(*fakeDiscord)
	if len(discordClient.editedMessages) != 1 ||
		discordClient.editedMessages[0] != "2001" {
		t.Fatalf("unexpected degraded edits: %#v", discordClient.editedMessages)
	}
}

func confirmationCustomID(t *testing.T, payload any) string {
	t.Helper()
	root := payload.(map[string]any)
	data := root["data"].(map[string]any)
	rows := data["components"].([]any)
	row := rows[0].(map[string]any)
	buttons := row["components"].([]any)
	button := buttons[0].(map[string]any)
	return button["custom_id"].(string)
}

func formatUnix(value time.Time) string {
	return strconv.FormatInt(value.Unix(), 10)
}
