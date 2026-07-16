// pkg/detector/modules/helpers.go

package modules

import (
	"net/url"
)

// extractHost returns the host (including port) from a raw URL string.
func extractHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// getPath returns the path + query string of a raw URL.
func getPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}