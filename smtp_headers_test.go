package main

import (
	"bufio"
	"context"
	"fmt"
	"mime"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

var subject string

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
