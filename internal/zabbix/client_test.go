package zabbix

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestVersionOmitsAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if authorization := request.Header.Get("Authorization"); authorization != "" {
			t.Errorf("apiinfo.version sent Authorization: %q", authorization)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"jsonrpc":"2.0","result":"7.4.12","id":1}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "must-not-be-sent")
	version, err := client.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "7.4.12" {
		t.Fatalf("got version %q", version)
	}
}

func TestAcknowledgeClassifiesUnconfirmedTransportOutcome(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(
		_ http.ResponseWriter,
		_ *http.Request,
	) {
		<-release
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := client.Acknowledge(ctx, "101", ActionAcknowledge, "ack", nil)
	close(release)
	if !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("transport timeout was not classified as outcome unknown: %v", err)
	}
}

func TestAcknowledgeKeepsZabbixAPIRejectionDefinitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		_ *http.Request,
	) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(
			`{"jsonrpc":"2.0","error":{"code":-32500,"message":"Application error."},"id":1}`,
		))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	err := client.Acknowledge(context.Background(), "101", ActionAcknowledge, "ack", nil)
	if err == nil || errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("API rejection was not kept definitive: %v", err)
	}
}

func TestProblemsEnrichesAndFiltersDisabledTriggersInThreeBatchedCalls(t *testing.T) {
	t.Helper()
	var mu sync.Mutex
	methods := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var rpc rpcRequest
		if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
			t.Error(err)
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods = append(methods, rpc.Method)
		mu.Unlock()
		var result any
		switch rpc.Method {
		case "problem.get":
			result = []map[string]any{
				{"eventid": "101", "objectid": "201", "name": "one", "severity": "4"},
				{"eventid": "102", "objectid": "202", "name": "two", "severity": "5"},
				{"eventid": "103", "objectid": "203", "name": "disabled", "severity": "4"},
			}
		case "trigger.get":
			result = []map[string]any{
				{
					"triggerid": "201",
					"status":    "0",
					"hosts": []map[string]string{
						{"hostid": "301", "host": "host-one", "name": "Host One"},
					},
				},
				{
					"triggerid": "202",
					"status":    "0",
					"hosts": []map[string]string{
						{"hostid": "301", "host": "host-one", "name": "Host One"},
						{"hostid": "302", "host": "host-two", "name": "Host Two"},
					},
				},
				{
					"triggerid": "203",
					"status":    "1",
					"hosts": []map[string]string{
						{"hostid": "301", "host": "host-one", "name": "Host One"},
					},
				},
			}
		case "host.get":
			result = []map[string]any{
				{
					"hostid": "301",
					"hostgroups": []map[string]string{
						{"groupid": "401", "name": "Tenants/Lab"},
					},
				},
				{
					"hostid": "302",
					"hostgroups": []map[string]string{
						{"groupid": "402", "name": "Production"},
					},
				},
			}
		default:
			t.Errorf("unexpected method %q", rpc.Method)
			http.Error(response, "unexpected method", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"jsonrpc": "2.0",
			"result":  result,
			"id":      rpc.ID,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	problems, err := client.Problems(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 ||
		len(problems[0].Hosts) != 1 ||
		len(problems[0].HostGroups) != 1 ||
		len(problems[1].Hosts) != 2 ||
		len(problems[1].HostGroups) != 2 ||
		problems[0].TriggerStatus != "0" ||
		problems[1].TriggerStatus != "0" {
		t.Fatalf("unexpected enrichment: %#v", problems)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(methods) != 3 {
		t.Fatalf("made %d API calls: %v", len(methods), methods)
	}
}

func TestProblemKeepsDisabledTriggerAvailableForHistoricalInteraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var rpc rpcRequest
		if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
			t.Error(err)
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		var result any
		switch rpc.Method {
		case "problem.get":
			result = []map[string]any{
				{"eventid": "101", "objectid": "201", "name": "historical", "severity": "4"},
			}
		case "trigger.get":
			result = []map[string]any{
				{
					"triggerid": "201",
					"status":    "1",
					"hosts": []map[string]string{
						{"hostid": "301", "host": "host-one", "name": "Host One"},
					},
				},
			}
		case "host.get":
			result = []map[string]any{
				{
					"hostid": "301",
					"hostgroups": []map[string]string{
						{"groupid": "401", "name": "Tenants/Lab"},
					},
				},
			}
		default:
			t.Errorf("unexpected method %q", rpc.Method)
			http.Error(response, "unexpected method", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"jsonrpc": "2.0",
			"result":  result,
			"id":      rpc.ID,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	problem, err := client.Problem(t.Context(), "101")
	if err != nil {
		t.Fatal(err)
	}
	if problem.EventID != "101" ||
		problem.TriggerStatus != "1" ||
		len(problem.Hosts) != 1 ||
		len(problem.HostGroups) != 1 {
		t.Fatalf("unexpected historical problem: %#v", problem)
	}
}

func TestProblemRejectsMissingOrInvalidTriggerMetadata(t *testing.T) {
	tests := []struct {
		name      string
		trigger   map[string]any
		wantError string
	}{
		{
			name: "missing status",
			trigger: map[string]any{
				"triggerid": "201",
				"hosts": []map[string]string{
					{"hostid": "301", "host": "host-one", "name": "Host One"},
				},
			},
			wantError: "problem trigger has invalid status",
		},
		{
			name: "invalid status",
			trigger: map[string]any{
				"triggerid": "201",
				"status":    "2",
				"hosts": []map[string]string{
					{"hostid": "301", "host": "host-one", "name": "Host One"},
				},
			},
			wantError: "problem trigger has invalid status",
		},
		{
			name:      "missing trigger",
			wantError: "problem trigger has no accessible host",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				var rpc rpcRequest
				if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
					t.Error(err)
					http.Error(response, "bad request", http.StatusBadRequest)
					return
				}
				var result any
				switch rpc.Method {
				case "problem.get":
					result = []map[string]any{
						{"eventid": "101", "objectid": "201", "name": "problem", "severity": "4"},
					}
				case "trigger.get":
					if test.trigger == nil {
						result = []map[string]any{}
					} else {
						result = []map[string]any{test.trigger}
					}
				case "host.get":
					result = []map[string]any{}
				default:
					t.Errorf("unexpected method %q", rpc.Method)
					http.Error(response, "unexpected method", http.StatusBadRequest)
					return
				}
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]any{
					"jsonrpc": "2.0",
					"result":  result,
					"id":      rpc.ID,
				})
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			_, err := client.Problem(t.Context(), "101")
			if err == nil || err.Error() != test.wantError {
				t.Fatalf("got error %v, want %q", err, test.wantError)
			}
		})
	}
}
