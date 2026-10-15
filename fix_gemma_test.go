package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var subject string

func TestFix_C1_NoProviderSecretSurvivesMasking(t *testing.T) {
	// 1. Pure function test
	t.Run("PureFunction", func(t *testing.T) {
		cases := []struct {
			input    string
			expected string
		}{
			{"https://api.telegram.org/bot123456789:AAEhBP0av28yC9tG_exampleTOKEN/sendMessage", "https://api.telegram.org/***"},
			{"https://discord.com/api/webhooks/111111/SECRETTOKEN", "https://discord.com/***"},
			{"https://chat.googleapis.com/v1/spaces/AAA/messages?key=K&token=T", "https://chat.googleapis.com/***"},
			{"invalid-url", "***"},
			{"", ""},
		}

		for _, c := range cases {
			got := webhookMasked(c.input)
			if got != c.expected {
				t.Errorf("webhookMasked(%q) = %q, want %q", c.input, got, c.expected)
			}
		}
	})

	// 2. API integration test
	t.Run("APIIntegration", func(t *testing.T) {
		d := newTestDB(t)
		srv := NewServer(d, NewProbeWorker(d))
		httpSrv := httptest.NewServer(srv.authGate())
		defer httpSrv.Close()

		d.SetSetting("auth_bootstrapped", "1")

		// Set secrets
		telegramURL := "https://api.telegram.org/bot123456789:AAEhBP0av28yC9tG_exampleTOKEN/sendMessage"
		discordURL := "https://discord.com/api/webhooks/111111/SECRETTOKEN"
		googleChatURL := "https://chat.googleapis.com/v1/spaces/AAA/messages?key=K&token=T"

		_ = d.SetSetting("telegram_url", telegramURL)
		_ = d.SetSetting("discord_url", discordURL)
		_ = d.SetSetting("google_chat_url", googleChatURL)

		resp, err := http.Get(httpSrv.URL + "/api/settings")
		if err != nil {
			t.Fatalf("failed GET /api/settings: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got status %d, want 200", resp.StatusCode)
		}

		var settings struct {
			Providers []struct {
				Kind string `json:"kind"`
				URL  string `json:"url"`
			} `json:"providers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
			t.Fatalf("failed decode: %v", err)
		}

		for _, p := range settings.Providers {
			// Check for known secrets in the masked URL
			if p.Kind == "telegram" {
				if strings.Contains(p.URL, "AAEhBP0av28yC9tG_exampleTOKEN") {
					t.Errorf("telegram URL still contains secret: %q", p.URL)
				}
			}
			if p.Kind == "discord" {
				if strings.Contains(p.URL, "SECRETTOKEN") {
					t.Errorf("discord URL still contains secret: %q", p.URL)
				}
			}
			if p.Kind == "google_chat" {
				if strings.Contains(p.URL, "token=T") || strings.Contains(p.URL, "key=K") {
					t.Errorf("google_chat URL still contains secret: %q", p.URL)
				}
			}

			// Verify masking shape (Scheme://Host/*** or ***)
			if p.URL != "" && !strings.HasSuffix(p.URL, "/***") && p.URL != "***" {
				t.Errorf("unexpected URL format for %s: %q", p.Kind, p.URL)
			}
		}
	})
}

func TestFix_g1_SecurityHeaders(t *testing.T) {
	d := newTestDB(t)
	srv := NewServer(d, NewProbeWorker(d))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	d.SetSetting("auth_bootstrapped", "1")
	// Enable auth by adding a user
	if err := srv.auth.AddUser("admin", "password123"); err != nil {
		t.Fatalf("failed to add admin user: %v", err)
	}

	checkHeaders := func(name string, url string, expectedStatus int) {
		resp, err := http.Get(httpSrv.URL + url)
		if err != nil {
			t.Fatalf("%s: failed GET %s: %v", name, url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != expectedStatus {
			t.Fatalf("%s: got status %d, want %d", name, resp.StatusCode, expectedStatus)
		}

		if expectedStatus == http.StatusOK {
			headers := []string{
				"X-Content-Type-Options",
				"X-Frame-Options",
				"Referrer-Policy",
				"Content-Security-Policy",
			}
			for _, h := range headers {
				if got := resp.Header.Get(h); got == "" {
					t.Errorf("%s: missing header %s", name, h)
				}
			}
			// Check specific values
			if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", name, resp.Header.Get("X-Content-Type-Options"))
			}
			if resp.Header.Get("X-Frame-Options") != "DENY" {
				t.Errorf("%s: X-Frame-Options = %q, want DENY", name, resp.Header.Get("X-Frame-Options"))
			}
			if resp.Header.Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("%s: Referrer-Policy = %q, want no-referrer", name, resp.Header.Get("Referrer-Policy"))
			}
			if resp.Header.Get("Content-Security-Policy") != "frame-ancestors 'none'" {
				t.Errorf("%s: CSP = %q, want frame-ancestors 'none'", name, resp.Header.Get("Content-Security-Policy"))
			}
		}
	}

	// 1) GET /
	checkHeaders("GET /", "/", http.StatusOK)

	// 2) GET /api/healthz
	checkHeaders("GET /api/healthz", "/api/healthz", http.StatusOK)

	// 3) Unauthenticated 401 API response
	// Since auth is enabled, an unauthenticated request to an /api/ endpoint should be 401.
	resp, err := http.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/sensors: got %d, want 401", resp.StatusCode)
	}
	// Check headers on 401 too
	headers := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
	}
	for _, h := range headers {
		if got := resp.Header.Get(h); got == "" {
			t.Errorf("unauthenticated 401: missing header %s", h)
		}
	}
}

func TestFix_g4_SMTPHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)

	var mu sync.Mutex
	var fullMsg string
	done := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { fmt.Fprint(conn, s) }
		w("220 test ESMTP\r\n")
		dataMode := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				close(done)
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(trimmed)

			mu.Lock()
			fullMsg += line
			mu.Unlock()

			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				w("250-test\r\n250 OK\r\n")
			case strings.HasPrefix(upper, "MAIL"):
				w("250 OK\r\n")
			case strings.HasPrefix(upper, "RCPT"):
				w("250 OK\r\n")
			case strings.HasPrefix(upper, "DATA"):
				w("354 go ahead\r\n")
				dataMode = true
			case dataMode:
				if trimmed == "." {
					dataMode = false
					w("250 OK\r\n")
				} else {
					// Continue reading
				}
			case strings.HasPrefix(upper, "QUIT"):
				w("221 bye\r\n")
				close(done)
				return
			default:
				w("250 OK\r\n")
			}
		}
	}()

	d := newTestDB(t)
	d.SetSetting("smtp_host", host)
	d.SetSetting("smtp_port", portStr)
	d.SetSetting("smtp_from", "pulsemon@test.local")
	d.SetSetting("smtp_to", "ops@test.local")
	d.SetSetting("smtp_tls_mode", "none")
	pw := NewProbeWorker(d)

	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { smtpDial = origDial })

	subject = "✅ pulsemon: recovered"
	bodyContent := "body content"
	if err := pw.sendSMTP(t.Context(), subject, bodyContent); err != nil {
		t.Fatalf("sendSMTP: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for SMTP server")
	}

	mu.Lock()
	defer mu.Unlock()

	// Parse the email from the full conversation.
	// fullMsg holds only what the CLIENT sent, so the message is everything
	// after the DATA command line.
	parts := strings.SplitN(fullMsg, "DATA\r\n", 2)
	if len(parts) < 2 {
		t.Fatalf("could not find DATA response in:\n%s", fullMsg)
	}
	emailMsg := parts[1]

	// The email ends at the first "\". on its own line.
	emailLines := strings.Split(emailMsg, "\r\n.")
	if len(emailLines) < 1 {
		t.Fatalf("could not find end of email in:\n%s", emailMsg)
	}
	emailMsg = emailLines[0]

	// 1. Check headers exist
	headers := []string{
		"Date:",
		"Message-ID:",
		"MIME-Version:",
		"Subject:",
	}
	for _, h := range headers {
		if !strings.Contains(emailMsg, h) {
			t.Fatalf("missing header %q in email:\n%s", h, emailMsg)
		}
	}

	// 2. Check Subject encoding
	expectedSubject := mime.QEncoding.Encode("utf-8", subject)
	if !strings.Contains(emailMsg, "Subject: "+expectedSubject) {
		t.Fatalf("subject not correctly encoded. got %q, want %q in email:\n%s",
			extractSubject(emailMsg), expectedSubject, emailMsg)
	}

	// 3. Check blank line between headers and body
	emailParts := strings.SplitN(emailMsg, "\r\n\r\n", 2)
	if len(emailParts) < 2 {
		t.Fatalf("could not find blank line between headers and body in email:\n%s", emailMsg)
	}
	if !strings.HasPrefix(emailParts[1], bodyContent) {
		t.Fatalf("body mismatch. got %q, want %q", emailParts[1], bodyContent)
	}

	// 4. Check Message-ID domain
	idLine := extractHeader(emailMsg, "Message-ID")
	if idLine == "" {
		t.Fatal("Message-ID header is empty")
	}
	// RFC 5322: msg-id is "<" id-left "@" id-right ">".
	if !strings.HasPrefix(idLine, "<") || !strings.HasSuffix(idLine, "@test.local>") {
		t.Fatalf("Message-ID must be <id@test.local>, got %q", idLine)
	}
}

func extractHeader(msg, header string) string {
	lines := strings.Split(msg, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, header+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, header+":"))
		}
	}
	return ""
}

func extractSubject(msg string) string {
	return extractHeader(msg, "Subject")
}

func TestFix_g6_GraphTotalsMatchBuckets(t *testing.T) {
	// Setup DB
	d := newTestDB(t)
	// Go through the real mux so the {id} path value is populated.
	mux := NewServer(d, NewProbeWorker(d)).Mux()

	sensorID := "test-sensor"
	_, err := d.Exec("INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sensorID, "Test Sensor", "127.0.0.1", "icmp", 60, 1000, 10, 30, 2.0, "up", "up", time.Now())
	if err != nil {
		t.Fatalf("exec: %v", err)
	}

	// Insert probes
	now := time.Now()
	// 10 probes, 2 lost
	for i := 0; i < 10; i++ {
		rtt := 50.0
		isLost := false
		if i%5 == 0 { // i = 0 and 5 -> exactly 2 lost
			rtt = 0
			isLost = true
		}
		ts := now.Add(time.Duration(-i) * time.Minute).Format(time.RFC3339Nano)
		var rttVal interface{}
		if isLost {
			rttVal = nil
		} else {
			rttVal = rtt
		}
		_, err := d.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?, ?, ?)", sensorID, ts, rttVal)
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
	}

	// Test 1h range
	req := httptest.NewRequest(http.MethodGet, "/api/sensors/"+sensorID+"/graph?range=1h", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}

	var resp struct {
		Total     int          `json:"total"`
		LostTotal int          `json:"lost_total"`
		Points    []GraphPoint `json:"points"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Total != 10 {
		t.Errorf("Total: got %d, want 10", resp.Total)
	}
	if resp.LostTotal != 2 {
		t.Errorf("LostTotal: got %d, want 2", resp.LostTotal)
	}

	// Sum totals from points
	sumTotal := 0
	sumLost := 0
	for _, p := range resp.Points {
		sumTotal += p.Total
		sumLost += p.Lost
	}
	if sumTotal != 10 {
		t.Errorf("Sum of bucket totals must match grand total: got %d, want 10", sumTotal)
	}
	if sumLost != 2 {
		t.Errorf("Sum of bucket lost must match grand lost_total: got %d, want 2", sumLost)
	}
}
