package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// acceptsGzip reports whether r's Accept-Encoding advertises gzip with a
// non-zero quality factor. A bare "gzip" (the common case, e.g.
// "gzip, deflate, br") qualifies; an explicit "gzip;q=0" declines it.
// Encoding names compare case-insensitively (RFC 9110 §8.4: coding names
// are case-insensitive), so "GZIP" qualifies too.
func acceptsGzip(r *http.Request) bool {
	ae := r.Header.Get("Accept-Encoding")
	if ae == "" {
		return false
	}
	for _, part := range strings.Split(ae, ",") {
		enc := strings.TrimSpace(part)
		q := 1.0
		if i := strings.IndexByte(enc, ';'); i >= 0 {
			name := strings.TrimSpace(enc[:i])
			for _, p := range strings.Split(enc[i+1:], ";") {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "q=") {
					if f, err := strconv.ParseFloat(strings.TrimPrefix(p, "q="), 64); err == nil {
						q = f
					}
				}
			}
			enc = name
		}
		if strings.EqualFold(enc, "gzip") && q > 0 {
			return true
		}
	}
	return false
}

// gzipPool reuses deflate compressors across requests: a fresh
// gzip.NewWriter allocates ~800 KB of window + hash state, and every /api/
// response on the 5s dashboard poll used to pay that allocation. A pointer
// (not a value) so tests can swap in an instrumented pool without copying
// the noCopy Pool.
var gzipPool = &sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

// gzipResponseWriter streams the response body through gzip. The
// compressor is initialized LAZILY on the first body write, so a
// bodyless response (204 No Content, 304 Not Modified, 1xx, or a
// status-only WriteHeader with no body) gets no gzip trailer AND no
// Content-Encoding — a 20-byte footer after a 204 is a protocol
// violation, a 0-byte "gzip" body is an invalid stream
// (ERR_CONTENT_DECODING_FAILED), and that trailer is exactly what a
// SIGTERM'd update handler (performRestart) used to leave truncated
// mid-stream.
//
// The final status is forwarded to the server DEFERRED — at the first
// body byte (beginBody) or at Close if the response is bodyless —
// because Go 1.24+ snapshots the header map at WriteHeader: a
// Content-Encoding set after the handler's WriteHeader (the old
// "lazy" shape) is silently dropped, while a CE set in WriteHeader
// leaks onto bodyless statuses. Deferring puts the CE decision in the
// snapshot exactly when a body is about to flow. A 1xx is forwarded
// immediately (it is informational and bodyless by definition); a later
// final status then defers as usual and clears the bypass.
//
// Unwrap exposes the underlying writer: http.ResponseController
// (handleUpdate's 90s SetWriteDeadline) and http.MaxBytesReader's
// requestTooLarge connection-close reach the real connection only through
// it — without it both fail silently (ErrNotSupported leaves the 30s
// server WriteTimeout active on a ~60s self-update; the hook cannot close
// the connection after a 413).
type gzipResponseWriter struct {
	http.ResponseWriter
	gz        *gzip.Writer // nil until the first body write
	status    int
	bypass    bool // true while the current status is bodyless (1xx/204/304)
	forwarded bool // the recorded status has been forwarded to the server
}

// Unwrap implements the http.ResponseWriter unwrapper contract.
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// headerOnly reports statuses that must not carry a body.
func headerOnly(status int) bool {
	return status == http.StatusNoContent || status == http.StatusNotModified || (status >= 100 && status < 200)
}

// WriteHeader records the status. A 1xx/204/304 is forwarded immediately
// (no Content-Encoding — there is no body to decode); a final status is
// recorded but deferred to beginBody (a body is coming: CE goes into the
// header snapshot) or Close (bodyless: forwarded without CE), so the
// snapshot semantics of net/http's WriteHeader are honored.
func (g *gzipResponseWriter) WriteHeader(status int) {
	g.status = status
	if headerOnly(status) {
		g.bypass = true
		g.forwarded = true
		g.ResponseWriter.Header().Del("Content-Encoding")
		g.ResponseWriter.WriteHeader(status)
		return
	}
	g.bypass = false
	g.forwarded = false
}

// flushHeaders forwards the recorded status with Content-Encoding set —
// called only when a body is about to flow (first Write / Flush), so the
// CE lands in the server's header snapshot.
func (g *gzipResponseWriter) flushHeaders() {
	if g.forwarded {
		return
	}
	g.forwarded = true
	h := g.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	g.ResponseWriter.WriteHeader(g.status)
}

// beginBody applies the header handling before the first body byte: for
// the implicit-200 case (no explicit WriteHeader) it records 200, then
// forwards the status with the gzip advertisement.
func (g *gzipResponseWriter) beginBody() {
	if g.status == 0 {
		g.status = http.StatusOK
	}
	g.flushHeaders()
}

// ensureGz takes a pooled compressor (re-pointed at this response) on
// first use.
func (g *gzipResponseWriter) ensureGz() *gzip.Writer {
	if g.gz == nil {
		g.gz = gzipPool.Get().(*gzip.Writer)
		g.gz.Reset(g.ResponseWriter)
	}
	return g.gz
}

// Write streams the body through gzip. Writes after a bodyless status are
// discarded (matching net/http's checkWrite: 0, nil) WITHOUT touching the
// compressor, so no trailer can appear after a 204.
func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if g.bypass {
		return 0, nil
	}
	g.beginBody()
	return g.ensureGz().Write(b)
}

// Flush pushes the gzip stream and the underlying transport so streaming
// endpoints (update progress, TLS settings) deliver progress as it is
// produced, not only at the end.
func (g *gzipResponseWriter) Flush() {
	if g.bypass {
		return
	}
	g.beginBody()
	gz := g.ensureGz()
	gz.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Close finishes the response: a bodyless final status (recorded via
// WriteHeader, never written) is forwarded NOW without Content-Encoding
// (a 0-byte "gzip" stream is invalid); a status that already carried a
// body was forwarded at its first byte. Then the gzip trailer is written
// and the compressor returned to the pool. No-op for bodyless responses
// that never took a compressor; safe to call twice; the authGate defers
// exactly one Close per request.
func (g *gzipResponseWriter) Close() error {
	if g.status != 0 && !g.forwarded {
		g.forwarded = true
		g.ResponseWriter.Header().Del("Content-Encoding")
		g.ResponseWriter.Header().Del("Content-Length")
		g.ResponseWriter.WriteHeader(g.status)
	}
	if g.gz == nil {
		return nil
	}
	err := g.gz.Close()
	g.gz.Reset(io.Discard)
	gzipPool.Put(g.gz)
	g.gz = nil
	return err
}
