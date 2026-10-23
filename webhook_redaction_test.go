package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- M8

func TestFix_M8_RedactErrDropsURL(t *testing.T) {
	secret := "bot123456:SECRETTOKEN"
	_, err := http.NewRequest("POST", "http://x/"+secret, nil)
	_ = err
	ue := &url.Error{Op: "Post", URL: "https://api.telegram.org/" + secret + "/sendMessage", Err: errors.New("connection refused")}
	r := redactErr(fmt.Errorf("wrapped: %w", ue))
	if strings.Contains(r.Error(), "SECRETTOKEN") || strings.Contains(r.Error(), "telegram") {
		t.Fatalf("redacted error still leaks the URL: %q", r.Error())
	}
	if !strings.Contains(r.Error(), "connection refused") {
		t.Fatalf("redacted error lost the cause: %q", r.Error())
	}
	plain := errors.New("plain")
	if redactErr(plain) != plain {
		t.Fatal("non-url errors must pass through unchanged")
	}
}

func TestFix_M8_PostJSONErrorDoesNotLeakToken(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = nil
		defer func() { alertRetryDelays = old }()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		srv.Close() // refuse connections
		pw := NewProbeWorker(nil)
		err := pw.postJSON(srv.URL+"/bot123:SECRETTOKEN/sendMessage", map[string]interface{}{"text": "x"})
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "SECRETTOKEN") {
			t.Fatalf("postJSON error leaks the token: %q", err.Error())
		}
	})
}
