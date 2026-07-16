// pkg/session/session.go

package session

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BaselineResult holds the fingerprint (status, headers, body, timing stats)
// collected from multiple requests to a baseline URL.
type BaselineResult struct {
	StatusCode int
	Headers    http.Header
	Body       []byte

	AvgTime       time.Duration
	StdDevTime    time.Duration
	TimingSamples []time.Duration
}

// Session manages raw TLS/TCP connections (via connection pool) to a single host
// and keeps baseline information used for comparison.
type Session struct {
	Host   string
	scheme string // "https" or "http"

	baseline *BaselineResult
	pool     *connPool // connection pool, defined in pool.go
}

// NewSession creates a new session for the given host (must include port,
// e.g. "example.com:443"). Scheme is inferred from the port.
func NewSession(host string) *Session {
	scheme := "https"
	if strings.HasSuffix(host, ":80") {
		scheme = "http"
	}
	// pool size of 5 reusable connections
	return &Session{
		Host:   host,
		scheme: scheme,
		pool:   newConnPool(host, scheme, 5),
	}
}

// FingerprintBaseline sends `samples` GET requests to the baseline URL,
// records timing statistics, and stores the first response's status/headers/body.
// It returns the constructed BaselineResult or an error.
func (s *Session) FingerprintBaseline(ctx context.Context, targetURL string, samples int) (*BaselineResult, error) {
	if samples < 1 {
		samples = 3
	}
	var timings []time.Duration
	var firstResp *http.Response
	var firstBody []byte

	for i := 0; i < samples; i++ {
		resp, dur, err := s.doRequest(ctx, "GET", targetURL, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("baseline request %d: %w", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		timings = append(timings, dur)
		if i == 0 {
			firstResp = resp
			firstBody = body
		}
	}

	avg, stddev := stats(timings)
	s.baseline = &BaselineResult{
		StatusCode:    firstResp.StatusCode,
		Headers:       firstResp.Header,
		Body:          firstBody,
		AvgTime:       avg,
		StdDevTime:    stddev,
		TimingSamples: timings,
	}
	return s.baseline, nil
}

// GetBaseline returns the previously computed baseline (nil if none).
func (s *Session) GetBaseline() *BaselineResult {
	return s.baseline
}

// SendProbeAndVictims sends a raw probe request (the smuggling payload) and
// then sequentially sends a clean GET request for each victim URL **on the same
// TCP connection**. It returns the victim responses, the round‑trip durations,
// and any error that prevented the whole sequence.
func (s *Session) SendProbeAndVictims(ctx context.Context, probeData []byte, victimURLs []string) (
	[]*http.Response, []time.Duration, error) {

	conn, err := s.pool.Get()
	if err != nil {
		return nil, nil, fmt.Errorf("get connection: %w", err)
	}
	defer s.pool.Put(conn)

	// Apply context deadline
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// 1. Send the probe
	if _, err := conn.Write(probeData); err != nil {
		return nil, nil, fmt.Errorf("write probe: %w", err)
	}

	var responses []*http.Response
	var durations []time.Duration
	bufReader := bufio.NewReader(conn)

	// 2. Send each victim request and read its response
	for i, vurl := range victimURLs {
		reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
			getPath(vurl), extractHost(vurl))

		start := time.Now()
		if _, err := conn.Write([]byte(reqStr)); err != nil {
			return nil, nil, fmt.Errorf("write victim %d: %w", i, err)
		}

		resp, err := http.ReadResponse(bufReader, nil)
		dur := time.Since(start)
		if err != nil {
			return nil, nil, fmt.Errorf("read victim %d: %w", i, err)
		}

		// Drain body completely so the connection can be reused
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		responses = append(responses, resp)
		durations = append(durations, dur)
	}
	return responses, durations, nil
}

// doRequest performs a single HTTP request using a (possibly fresh) connection
// from the pool and returns the response, total time, and any error.
func (s *Session) doRequest(ctx context.Context, method, targetURL string,
	headers map[string]string, body []byte) (*http.Response, time.Duration, error) {

	conn, err := s.pool.Get()
	if err != nil {
		return nil, 0, err
	}
	defer s.pool.Put(conn)

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	u, _ := url.Parse(targetURL)
	reqStr := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n",
		method, u.RequestURI(), u.Host)
	for k, v := range headers {
		reqStr += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	reqStr += "\r\n"
	if body != nil {
		reqStr += string(body)
	}

	start := time.Now()
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return nil, 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	dur := time.Since(start)
	if err != nil {
		return nil, 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp, dur, nil
}

// stats computes arithmetic mean and population standard deviation of a
// slice of durations.
func stats(durations []time.Duration) (time.Duration, time.Duration) {
	if len(durations) == 0 {
		return 0, 0
	}
	var sum float64
	for _, d := range durations {
		sum += float64(d)
	}
	avg := time.Duration(sum / float64(len(durations)))
	if len(durations) < 2 {
		return avg, 0
	}
	var variance float64
	for _, d := range durations {
		diff := float64(d - avg)
		variance += diff * diff
	}
	// population stddev (divide by N)
	stddev := time.Duration(variance / float64(len(durations)))
	return avg, stddev
}

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