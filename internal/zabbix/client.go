package zabbix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	ActionClose       = 1
	ActionAcknowledge = 2
	ActionMessage     = 4
	ActionSeverity    = 8
	ActionSuppress    = 32
	ActionUnsuppress  = 64
)

var ErrMutationOutcomeUnknown = errors.New("Zabbix mutation outcome unknown")

type Tag struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type Host struct {
	HostID string `json:"hostid"`
	Host   string `json:"host"`
	Name   string `json:"name"`
}

type HostGroup struct {
	GroupID string `json:"groupid"`
	Name    string `json:"name"`
}

type Problem struct {
	EventID       string      `json:"eventid"`
	ObjectID      string      `json:"objectid"`
	Name          string      `json:"name"`
	Severity      string      `json:"severity"`
	Acknowledged  string      `json:"acknowledged"`
	Suppressed    string      `json:"suppressed"`
	Clock         string      `json:"clock"`
	Tags          []Tag       `json:"tags"`
	Hosts         []Host      `json:"-"`
	HostGroups    []HostGroup `json:"-"`
	TriggerStatus string      `json:"-"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      uint64 `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type Client struct {
	url   string
	token string
	http  *http.Client
	id    atomic.Uint64
}

func NewClient(url, token string) *Client {
	return &Client{
		url:   url,
		token: token,
		http:  &http.Client{Timeout: 8 * time.Second},
	}
}

func (c *Client) call(ctx context.Context, method string, params, result any) error {
	return c.callWithAuth(ctx, method, params, result, true)
}

func (c *Client) callWithAuth(
	ctx context.Context,
	method string,
	params, result any,
	authenticated bool,
) error {
	requestBody, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      c.id.Add(1),
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	request.Header.Set("Content-Type", "application/json-rpc")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("Zabbix API %s: %w", method, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("Zabbix API %s returned HTTP %d", method, response.StatusCode)
	}
	var envelope rpcResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("decode Zabbix API %s: %w", method, err)
	}
	if envelope.Error != nil {
		return &apiError{
			method:  method,
			code:    envelope.Error.Code,
			message: envelope.Error.Message,
		}
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("decode Zabbix API %s result: %w", method, err)
	}
	return nil
}

type apiError struct {
	method  string
	code    int
	message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf(
		"Zabbix API %s failed (%d): %s",
		e.method,
		e.code,
		e.message,
	)
}

func (c *Client) Version(ctx context.Context) (string, error) {
	var version string
	err := c.callWithAuth(
		ctx,
		"apiinfo.version",
		map[string]any{},
		&version,
		false,
	)
	return version, err
}

func (c *Client) Problems(ctx context.Context, limit int) ([]Problem, error) {
	var problems []Problem
	err := c.call(ctx, "problem.get", map[string]any{
		"output":     []string{"eventid", "objectid", "name", "severity", "acknowledged", "suppressed", "clock"},
		"source":     0,
		"object":     0,
		"recent":     false,
		"sortfield":  []string{"eventid"},
		"sortorder":  "DESC",
		"limit":      limit,
		"selectTags": []string{"tag", "value"},
	}, &problems)
	if err != nil {
		return nil, err
	}
	if err := c.enrich(ctx, problems); err != nil {
		return nil, err
	}
	enabled := problems[:0]
	for _, problem := range problems {
		if problem.TriggerStatus == "0" {
			enabled = append(enabled, problem)
		}
	}
	return enabled, nil
}

func (c *Client) Problem(ctx context.Context, eventID string) (Problem, error) {
	var problems []Problem
	err := c.call(ctx, "problem.get", map[string]any{
		"output":     []string{"eventid", "objectid", "name", "severity", "acknowledged", "suppressed", "clock"},
		"eventids":   []string{eventID},
		"source":     0,
		"object":     0,
		"recent":     false,
		"selectTags": []string{"tag", "value"},
	}, &problems)
	if err != nil {
		return Problem{}, err
	}
	if len(problems) != 1 {
		return Problem{}, errors.New("Zabbix problem is not open or does not exist")
	}
	if err := c.enrich(ctx, problems); err != nil {
		return Problem{}, err
	}
	return problems[0], nil
}

func (c *Client) enrich(ctx context.Context, problems []Problem) error {
	if len(problems) == 0 {
		return nil
	}
	triggerIDs := make([]string, 0, len(problems))
	for index := range problems {
		triggerIDs = append(triggerIDs, problems[index].ObjectID)
	}
	var triggers []struct {
		TriggerID string `json:"triggerid"`
		Status    string `json:"status"`
		Hosts     []Host `json:"hosts"`
	}
	if err := c.call(ctx, "trigger.get", map[string]any{
		"output":      []string{"triggerid", "status"},
		"triggerids":  triggerIDs,
		"selectHosts": []string{"hostid", "host", "name"},
	}, &triggers); err != nil {
		return err
	}
	hostsByTrigger := make(map[string][]Host, len(triggers))
	statusByTrigger := make(map[string]string, len(triggers))
	uniqueHostIDs := make(map[string]struct{})
	for _, trigger := range triggers {
		if trigger.Status != "0" && trigger.Status != "1" {
			return errors.New("problem trigger has invalid status")
		}
		hostsByTrigger[trigger.TriggerID] = trigger.Hosts
		statusByTrigger[trigger.TriggerID] = trigger.Status
		for _, host := range trigger.Hosts {
			uniqueHostIDs[host.HostID] = struct{}{}
		}
	}
	hostIDs := make([]string, 0, len(uniqueHostIDs))
	for hostID := range uniqueHostIDs {
		hostIDs = append(hostIDs, hostID)
	}
	var hosts []struct {
		HostID string      `json:"hostid"`
		Groups []HostGroup `json:"hostgroups"`
	}
	if err := c.call(ctx, "host.get", map[string]any{
		"output":           []string{"hostid"},
		"hostids":          hostIDs,
		"selectHostGroups": []string{"groupid", "name"},
	}, &hosts); err != nil {
		return err
	}
	groupsByHost := make(map[string][]HostGroup, len(hosts))
	for _, host := range hosts {
		groupsByHost[host.HostID] = host.Groups
	}
	for index := range problems {
		problemHosts := hostsByTrigger[problems[index].ObjectID]
		if len(problemHosts) == 0 {
			return errors.New("problem trigger has no accessible host")
		}
		problems[index].Hosts = problemHosts
		problems[index].TriggerStatus = statusByTrigger[problems[index].ObjectID]
		seenGroups := make(map[string]struct{})
		for _, host := range problemHosts {
			for _, group := range groupsByHost[host.HostID] {
				if _, ok := seenGroups[group.GroupID]; ok {
					continue
				}
				seenGroups[group.GroupID] = struct{}{}
				problems[index].HostGroups = append(problems[index].HostGroups, group)
			}
		}
	}
	return nil
}

func (c *Client) Acknowledge(
	ctx context.Context,
	eventID string,
	action int,
	message string,
	extra map[string]any,
) error {
	params := map[string]any{
		"eventids": []string{eventID},
		"action":   action,
		"message":  message,
	}
	for key, value := range extra {
		params[key] = value
	}
	var result struct {
		EventIDs []string `json:"eventids"`
	}
	if err := c.call(ctx, "event.acknowledge", params, &result); err != nil {
		var rejected *apiError
		if errors.As(err, &rejected) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrMutationOutcomeUnknown, err)
	}
	if len(result.EventIDs) != 1 || result.EventIDs[0] != eventID {
		return fmt.Errorf(
			"%w: unexpected event.acknowledge result",
			ErrMutationOutcomeUnknown,
		)
	}
	return nil
}

func (p Problem) SeverityInt() int {
	value, _ := strconv.Atoi(p.Severity)
	return value
}

func (p Problem) HostNames() string {
	names := make([]string, 0, len(p.Hosts))
	for _, host := range p.Hosts {
		name := host.Name
		if name == "" {
			name = host.Host
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
