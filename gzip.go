package main

import (
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
)

// acceptsGzip reports whether r's Accept-Encoding advertises gzip with a
// non-zero quality factor. A bare "gzip" (the common case, e.g.
// "gzip, deflate, br") qualifies; an explicit "gzip;q=0" declines it.
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
		if enc == "gzip" && q > 0 {
			return true
		}
	}
	return false
}

// gzipResponseWriter streams the response body through gzip. It supports
// http.Flusher (so the update-progress and TLS-settings streaming endpoints
// keep delivering progress through the wrapper) and drops Content-Length
// before the headers are sent: with gzip the compressed byte count differs
// from the raw body, so a stale length would desynchronize the client — the
// server falls back to chunked transfer encoding instead.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	started bool
}

// WriteHeader suppresses Content-Length (the gzip body has a different byte
// count than the raw body) before the status + headers are flushed.
func (g *gzipResponseWriter) WriteHeader(status int) {
	g.ResponseWriter.Header().Del("Content-Length")
	g.ResponseWriter.WriteHeader(status)
}

// Write streams the body through gzip. The first write also drops
// Content-Length, covering handlers that write without an explicit
// WriteHeader (the http server sends the headers on the first Write).
func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.started {
		g.started = true
		g.ResponseWriter.Header().Del("Content-Length")
	}
	return g.gz.Write(b)
}

// Flush pushes the gzip stream and the underlying transport so streaming
// endpoints deliver progress as it is produced, not only at the end.
func (g *gzipResponseWriter) Flush() {
	if !g.started {
		g.started = true
		g.ResponseWriter.Header().Del("Content-Length")
	}
	g.gz.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
