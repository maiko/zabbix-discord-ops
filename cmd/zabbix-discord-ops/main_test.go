package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheckAcceptsLoopbackOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := healthcheck(server.URL); err != nil {
		t.Fatal(err)
	}
}

func TestHealthcheckRejectsNonLoopbackAndRedirect(t *testing.T) {
	if err := healthcheck("http://192.0.2.1/healthz"); err == nil {
		t.Fatal("expected non-loopback rejection")
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "/elsewhere")
		response.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	err := healthcheck(server.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}
