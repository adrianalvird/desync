//pkg/util/util.go

package util

import (
	"net/url"
	"strings"
)

// ExtractHost returns host:port from a raw URL string.
func ExtractHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// GetPath returns the path+query of a URL string.
func GetPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}