package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// staticETags caches the strong ETag of each embedded asset. The embedded
// bytes never change for the life of the process, so each path is hashed once.
var staticETags sync.Map // path -> quoted hex sha256

// staticETag returns the strong ETag (a quoted hex SHA-256 of data) for path.
func staticETag(path string, data []byte) string {
	if v, ok := staticETags.Load(path); ok {
		return v.(string)
	}
	sum := sha256.Sum256(data)
	tag := `"` + hex.EncodeToString(sum[:]) + `"`
	staticETags.Store(path, tag)
	return tag
}

// etagMatches reports whether an If-None-Match header value matches tag. It
// accepts "*" and a comma-separated list, and ignores a weak "W/" prefix
// (If-None-Match uses weak comparison, RFC 9110 §13.1.2).
func etagMatches(header, tag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.TrimPrefix(part, "W/") == tag {
			return true
		}
	}
	return false
}
