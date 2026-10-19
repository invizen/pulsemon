package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// TLS certificate/key management from the dashboard (Settings → TLS).
//
// Uploads are validated IN MEMORY before anything touches disk: the
// cert must parse, the key must parse, and the key's public key must
// match the cert's. A mismatched or corrupt pair is rejected with 400
// and the running listener is left completely alone. Only a verified
// pair is written to <data>/tls/, the port setting updated, and a
// restart requested.

// tlsInfo is the GET /api/settings "tls" field.
type tlsInfo struct {
	Enabled  bool   `json:"enabled"`
	Source   string `json:"source"` // "env" | "dashboard" | ""
	Port     int    `json:"port"`
	Subject  string `json:"subject,omitempty"`
	Expiry   string `json:"expiry,omitempty"`
	HTTPAddr string `json:"http_addr"` // what the HTTP listener uses
}

// tlsPayload computes the TLS status for the settings payload. It reads
// the files (if present) so the dashboard can show subject/expiry even
// though the running listener was started before the last upload.
func (s *Server) tlsPayload() tlsInfo {
	c := loadListenerCfg(s.db)
	info := tlsInfo{Port: c.httpsPort, HTTPAddr: listenAddr()}
	if c.certPath != "" {
		info.Enabled = true
		info.Source = c.source
		if cert, _ := tlsX509Cert(c.certPath); cert != nil {
			info.Subject = cert.Subject.CommonName
			info.Expiry = cert.NotAfter.Format("2006-01-02")
		}
	}
	return info
}

// tlsX509Cert parses one PEM cert file.
func tlsX509Cert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM CERTIFICATE block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

var keyPEMTypes = []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"}

// tlsValidatePair checks certPEM + keyPEM: both parse, and the key's
// public key matches the cert's. Returns the parsed cert on success.
// PEM inputs may be base64 of the PEM text or raw base64 DER — both are
// accepted so users can paste either form.
func tlsValidatePair(certPEM, keyPEM string) (*x509.Certificate, error) {
	certBlock, err := pemBlockFromUpload(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("certificate: %v", err)
	}
	keyBlock, err := pemBlockFromUpload(keyPEM, keyPEMTypes...)
	if err != nil {
		return nil, fmt.Errorf("private key: %v", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate parse: %v", err)
	}
	pubKey, err := parsePrivateKey(keyBlock)
	if err != nil {
		return nil, fmt.Errorf("private key: %v", err)
	}
	if !pubKeyEquals(pubKey, cert.PublicKey) {
		return nil, errors.New("private key does not match certificate")
	}
	return cert, nil
}

// pemBlockFromUpload accepts a PEM block (with or without headers) or
// raw base64 DER, and returns a PEM block whose type matches one of
// wantTypes.
func pemBlockFromUpload(in string, wantTypes ...string) (*pem.Block, error) {
	if len(wantTypes) == 0 {
		return nil, fmt.Errorf("no PEM types given")
	}
	// 1. Direct PEM decode (text with headers, or with CRLF/whitespace junk).
	if block, _ := pem.Decode([]byte(in)); block != nil {
		if !pemTypeOK(block, wantTypes) {
			return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
		}
		return block, nil
	}
	// 2. Base64 of PEM text (file pasted as one line).
	if dec, err := base64.StdEncoding.DecodeString(in); err == nil {
		if block, _ := pem.Decode(dec); block != nil {
			if !pemTypeOK(block, wantTypes) {
				return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
			}
			return block, nil
		}
	}
	// 3. Raw base64 DER (no headers at all — the common "export" format).
	if der, err := base64.StdEncoding.DecodeString(in); err == nil {
		if len(der) > 100 { // a real cert/key, not a typo
			return &pem.Block{Type: wantTypes[0], Bytes: der}, nil
		}
	}
	first := wantTypes[0]
	for _, t := range wantTypes[1:] {
		first += "/" + t
	}
	return nil, fmt.Errorf("could not find a %s PEM block or base64 DER", first)
}

func pemTypeOK(b *pem.Block, wantTypes []string) bool {
	for _, t := range wantTypes {
		if b.Type == t {
			return true
		}
	}
	return false
}

// pubKeyEquals reports whether priv (a public key of some concrete type)
// matches certPub — the two types involved are *rsa.PublicKey and
// *ecdsa.PublicKey, each with its own Equal method.
func pubKeyEquals(priv, certPub any) bool {
	switch a := priv.(type) {
	case *rsa.PublicKey:
		b, ok := certPub.(*rsa.PublicKey)
		return ok && a.Equal(b)
	case *ecdsa.PublicKey:
		b, ok := certPub.(*ecdsa.PublicKey)
		return ok && a.Equal(b)
	case ed25519.PublicKey:
		// x509 yields ed25519.PublicKey by value (2026-10-19 review m3).
		b, ok := certPub.(ed25519.PublicKey)
		return ok && a.Equal(b)
	case *ed25519.PublicKey:
		b, ok := certPub.(ed25519.PublicKey)
		return ok && a.Equal(b)
	default:
		return false
	}
}

// parsePrivateKey accepts PKCS8 ("PRIVATE KEY"), PKCS1 ("RSA PRIVATE KEY"),
// and SEC1 ("EC PRIVATE KEY") blocks, and returns the public key.
func parsePrivateKey(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return pubKeyFromAny(key), nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &key.PublicKey, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &key.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", block.Type)
	}
}

func pubKeyFromAny(key interface{}) interface{} {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	// PKCS8 Ed25519 keys parse to ed25519.PrivateKey; the default case
	// passed the PRIVATE key through, so pubKeyEquals never matched and a
	// valid Ed25519 pair was rejected (2026-10-19 review m3).
	case ed25519.PrivateKey:
		return k.Public()
	case *ed25519.PrivateKey:
		return k.Public()
	default:
		return key
	}
}

// handleTLSSettingsPut: POST /api/settings/tls
// Body: {"cert": "<pem-or-base64>", "key": "<pem-or-base64>", "port": 443}
// cert+key together = install/replace the pair; port alone = change port.
func (s *Server) handleTLSSettingsPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
		Port *int   `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	if req.Cert == "" && req.Key == "" && req.Port == nil {
		respondWithError(w, http.StatusBadRequest, "nothing to update: send cert+key or a port")
		return
	}

	// Pair validation comes FIRST: when a cert+key arrive together with a
	// port, a rejected pair must not have silently moved the stored port
	// already (the running listener would then differ from the stored
	// config with no restart applied to reconcile them).
	cert := req.Cert
	key := req.Key
	if (cert == "") != (key == "") {
		respondWithError(w, http.StatusBadRequest, "cert and key must be sent together")
		return
	}
	var parsed *x509.Certificate
	var err error
	if cert != "" {
		parsed, err = tlsValidatePair(cert, key)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid certificate/key pair: "+err.Error())
			return
		}
	}

	// Port range validation. Persistence happens AFTER the files are in
	// place (below), so a failed pair upload can never leave a new port
	// stored alongside the old pair.
	if req.Port != nil {
		if *req.Port < 1 || *req.Port > 65535 {
			respondWithError(w, http.StatusBadRequest, "port out of range (1-65535)")
			return
		}
	}

	if cert != "" {
		// What lands on disk: the FULL chain (leaf + every intermediate),
		// canonical PEM (2026-10-19 review F5).
		certFile, err := fullchainPEM(cert)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid certificate: "+err.Error())
			return
		}
		dir := tlsDir(s.db)
		// Owner-only: key.pem is a private key and the dir lives next to
		// the secret-holding DB.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			respondInternal(w, "create cert dir", err)
			return
		}
		certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		// Atomic install: write BOTH files to temp files in the same dir
		// (0600, as CreateTemp makes them), re-validate the pair as it
		// will land on disk (tls.LoadX509KeyPair on the temps), then
		// rename key then cert into place. A failure anywhere before the
		// renames leaves the previously installed pair untouched — no
		// mismatched pair, no boot crash loop.
		//
		// Crash safety (2026-10-19 review F18, minimum-acceptable variant
		// of the spec's F2): both temps are fsynced BEFORE close and the
		// directory is fsynced after the renames, so a crash loses at most
		// the window between the two renames (microseconds) — the old
		// pair stays loadable on either side of it. The spec's preferred
		// generation-dir+symlink design was not used because the existing
		// install test pins the flat-file rename contract (a directory at
		// the key target must fail the install and leave the old pair).
		tmpCert, err := os.CreateTemp(dir, ".cert.pem.tmp*")
		if err != nil {
			respondInternal(w, "temp cert", err)
			return
		}
		certName := tmpCert.Name()
		tmpKey, err := os.CreateTemp(dir, ".key.pem.tmp*")
		if err != nil {
			tmpCert.Close()
			os.Remove(certName)
			respondInternal(w, "temp key", err)
			return
		}
		keyName := tmpKey.Name()
		install := func() error {
			if _, err := tmpCert.Write([]byte(certFile)); err != nil {
				return err
			}
			if err := tmpCert.Sync(); err != nil { // F18: durable before rename
				return err
			}
			if err := tmpCert.Close(); err != nil {
				return err
			}
			if _, err := tmpKey.Write([]byte(normPEM(key, keyPEMType(key)))); err != nil {
				return err
			}
			if err := tmpKey.Sync(); err != nil { // F18: durable before rename
				return err
			}
			if err := tmpKey.Close(); err != nil {
				return err
			}
			if _, err := tls.LoadX509KeyPair(certName, keyName); err != nil {
				return err
			}
			if err := os.Rename(keyName, keyPath); err != nil {
				return err
			}
			if err := os.Rename(certName, certPath); err != nil {
				return err
			}
			// F18: make the two renames durable (best effort — some
			// filesystems do not support directory fsync).
			if d, derr := os.Open(dir); derr == nil {
				if serr := d.Sync(); serr != nil {
					log.Printf("TLS: directory fsync after install failed: %v", serr)
				}
				d.Close()
			}
			return nil
		}
		if err := install(); err != nil {
			os.Remove(certName)
			os.Remove(keyName)
			respondInternal(w, "install cert", err)
			return
		}
		log.Printf("TLS: certificate installed (%s, expires %s, %d PEM block(s))",
			parsed.Subject.CommonName, parsed.NotAfter.Format("2006-01-02"), countPEMBlocks(certFile))
	}

	// Persist the port ONLY after the pair is in place (or when only the
	// port changed): the running listener must never be left with a port
	// that belongs to a pair it does not have.
	if req.Port != nil {
		if err := s.db.SetSetting("listener_https_port", fmt.Sprintf("%d", *req.Port)); err != nil {
			respondInternal(w, "save port", err)
			return
		}
	}

	// Response is flushed BEFORE the restart is triggered: the restart
	// kills this process (SIGTERM via systemctl, or os.Exit via re-exec),
	// so the client must already have the answer. The 200ms delay gives
	// net/http time to write the response to the wire.
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "applied",
		"restarting": true,
		"tls":        s.tlsPayload(),
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		out := requestRestart()
		if out.hint != "" {
			log.Printf("TLS config applied but auto-restart unavailable: %s", out.hint)
		}
	}()
}

// handleTLSSettingsDelete: DELETE /api/settings/tls — remove the
// dashboard-installed cert/key, fall back to plain HTTP on the HTTP port.
// Refuses when the pair comes from env (PULSEMON_CERT) — that is an
// install-time choice the dashboard must not clobber.
func (s *Server) handleTLSSettingsDelete(w http.ResponseWriter, r *http.Request) {
	c := loadListenerCfg(s.db)
	if c.source == "env" {
		respondWithError(w, http.StatusConflict, "TLS is configured by environment (PULSEMON_CERT/PULSEMON_KEY); stop those to use the dashboard upload")
		return
	}
	if c.source != "dashboard" {
		respondWithError(w, http.StatusConflict, "no dashboard-installed certificate to remove")
		return
	}
	dir := tlsDir(s.db)
	if err := os.Remove(filepath.Join(dir, "cert.pem")); err != nil && !errors.Is(err, os.ErrNotExist) {
		respondInternal(w, "remove cert", err)
		return
	}
	if err := os.Remove(filepath.Join(dir, "key.pem")); err != nil && !errors.Is(err, os.ErrNotExist) {
		respondInternal(w, "remove key", err)
		return
	}
	log.Printf("TLS: certificate removed — reverting to plain HTTP on %s", listenAddr())
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "removed",
		"restarting": true,
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		out := requestRestart()
		if out.hint != "" {
			log.Printf("TLS removal applied but auto-restart unavailable: %s", out.hint)
		}
	}()
}

// normPEM returns canonical PEM text (header + wrapped base64 + footer)
// for whatever accepted form was uploaded.
func normPEM(in, wantType string) string {
	if block, _ := pemBlockFromUpload(in, wantType); block != nil {
		return string(pem.EncodeToMemory(block))
	}
	return in
}

// fullchainPEM returns canonical PEM text containing ALL CERTIFICATE blocks
// in the upload, in order (2026-10-19 review F5). The old normPEM path kept
// only the FIRST block, so a fullchain upload (leaf + intermediates, the
// normal "cat leaf.pem intermediate.pem" form) stored a leaf-only file and
// clients failed with "unknown authority". Accepts the same input forms as
// pemBlockFromUpload: direct PEM text (multiple blocks), base64 of PEM
// text, or raw base64 DER (a single certificate — no chain possible).
// Validation (tlsValidatePair) still checks the FIRST block (the leaf)
// against the key, as before; this only changes what gets stored.
func fullchainPEM(in string) (string, error) {
	var raw []byte
	if b, _ := pem.Decode([]byte(in)); b != nil {
		raw = []byte(in)
	} else if dec, err := base64.StdEncoding.DecodeString(in); err == nil {
		if b, _ := pem.Decode(dec); b != nil {
			raw = dec
		}
	}
	if raw != nil {
		var blocks []*pem.Block
		rest := raw
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				return "", fmt.Errorf("unexpected PEM type %q in certificate", b.Type)
			}
			blocks = append(blocks, b)
		}
		if len(blocks) == 0 {
			return "", errors.New("no PEM CERTIFICATE block found")
		}
		var out []byte
		for _, b := range blocks {
			out = append(out, pem.EncodeToMemory(b)...)
		}
		return string(out), nil
	}
	// Raw base64 DER (no headers at all — the common "export" format):
	// exactly one certificate.
	if der, err := base64.StdEncoding.DecodeString(in); err == nil && len(der) > 100 {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
	}
	return "", errors.New("no PEM CERTIFICATE block found")
}

// countPEMBlocks counts the PEM blocks in text (log line: lets an operator
// see at a glance whether the stored cert kept its intermediates, F5).
func countPEMBlocks(text string) int {
	n := 0
	rest := []byte(text)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return n
		}
		n++
	}
}

// keyPEMType returns the PEM type the uploaded key block had, so the
// written file keeps the format OpenSSL and Go both expect.
func keyPEMType(in string) string {
	if block, _ := pem.Decode([]byte(in)); block != nil && block.Type != "" {
		return block.Type
	}
	if dec, err := base64.StdEncoding.DecodeString(in); err == nil {
		if block, _ := pem.Decode(dec); block != nil && block.Type != "" {
			return block.Type
		}
	}
	return "PRIVATE KEY"
}
