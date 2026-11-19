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
// response on the 5s dashboard poll used to pay that allocation.
var gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

// gzipResponseWriter streams the response body through gzip. The
// compressor is initialized LAZILY on the first body write, so a
// bodyless response (204 No Content, 304 Not Modified, 1xx) gets no gzip
// trailer — a 20-byte footer after a 204 is a protocol violation, and
// that trailer is exactly what a SIGTERM'd update handler
// (performRestart) used to leave truncated mid-stream
// (ERR_CONTENT_DECODING_FAILED on the 202).
//
// Unwrap exposes the underlying writer: http.ResponseController
// (handleUpdate's 90s SetWriteDeadline) and http.MaxBytesReader's
// requestTooLarge connection-close reach the real connection only through
// it — without it both fail silently (ErrNotSupported leaves the 30s
// server WriteTimeout active on a ~60s self-update; the hook cannot close
// the connection after a 413).
type gzipResponseWriter struct {
	http.ResponseWriter
	gz     *gzip.Writer // nil until the first body write
	status int
	bypass bool // 1xx/204/304: bodyless — no gzip, no trailer
}

// Unwrap implements the http.ResponseWriter unwrapper contract.
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// headerOnly reports statuses that must not carry a body.
func headerOnly(status int) bool {
	return status == http.StatusNoContent || status == http.StatusNotModified || (status >= 100 && status < 200)
}

// WriteHeader records the status. Bodyless statuses bypass gzip entirely
// (Content-Encoding is dropped so the client doesn't expect a body);
// everything else drops Content-Length (the compressed byte count differs
// from the raw body — the server falls back to chunked encoding) and
// advertises gzip.
func (g *gzipResponseWriter) WriteHeader(status int) {
	g.status = status
	h := g.ResponseWriter.Header()
	if headerOnly(status) {
		g.bypass = true
		h.Del("Content-Encoding")
	} else {
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
	}
	g.ResponseWriter.WriteHeader(status)
}

// beginBody applies the implicit-200 header handling for handlers that
// write without an explicit WriteHeader (the http server sends the headers
// on the first Write).
func (g *gzipResponseWriter) beginBody() {
	if g.status == 0 {
		g.status = http.StatusOK
		g.ResponseWriter.Header().Del("Content-Length")
		g.ResponseWriter.Header().Set("Content-Encoding", "gzip")
	}
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

// Close writes the gzip trailer and returns the compressor to the pool.
// No-op for bodyless responses (nothing was compressed) and safe to call
// twice; the authGate defers exactly one Close per request.
func (g *gzipResponseWriter) Close() error {
	if g.gz == nil {
		return nil
	}
	err := g.gz.Close()
	g.gz.Reset(io.Discard)
	gzipPool.Put(g.gz)
	g.gz = nil
	return err
}
