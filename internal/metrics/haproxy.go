// Package metrics collects HAProxy runtime statistics via the stats Unix socket.
package metrics

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// MinHAProxyStatsRefresh is the minimum interval between socket reads (cache TTL).
const MinHAProxyStatsRefresh = 5 * time.Second

// StatsSocketPath returns the configured stats socket path or the default under stateDir.
func StatsSocketPath(gs config.GlobalSettings, stateDir string) string {
	if p := strings.TrimSpace(gs.HAProxyStatsSocketPath); p != "" {
		return p
	}
	return filepath.Join(stateDir, "haproxy", "admin.sock")
}

// FrontendStat is one HAProxy frontend aggregate row (svname=FRONTEND).
type FrontendStat struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	SessionsCur  int64  `json:"sessions_cur"`
	SessionsMax  int64  `json:"sessions_max"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	ReqRate      int64  `json:"req_rate"`
	HTTP2xx      int64  `json:"http_2xx"`
	HTTP4xx      int64  `json:"http_4xx"`
	HTTP5xx      int64  `json:"http_5xx"`
	TotalReqHint int64  `json:"total_req_hint"` // sum of hrsp_* columns (cumulative responses)
}

// ServerStat is one server line under a backend.
type ServerStat struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	SessionsCur int64  `json:"sessions_cur"`
}

// BackendStat is one HAProxy backend (aggregate + servers).
type BackendStat struct {
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Health      string       `json:"health"` // derived from servers when present
	SessionsCur int64        `json:"sessions_cur"`
	SessionsMax int64        `json:"sessions_max"`
	BytesIn     int64        `json:"bytes_in"`
	BytesOut    int64        `json:"bytes_out"`
	ReqRate     int64        `json:"req_rate"`
	HTTP2xx     int64        `json:"http_2xx"`
	HTTP4xx     int64        `json:"http_4xx"`
	HTTP5xx     int64        `json:"http_5xx"`
	Servers     []ServerStat `json:"servers"`
}

// HAProxyReport is the JSON payload for GET /api/v1/stats/haproxy.
type HAProxyReport struct {
	CollectedAt time.Time      `json:"collected_at"`
	Frontends   []FrontendStat `json:"frontends"`
	Backends    []BackendStat  `json:"backends"`
	Error       string         `json:"error,omitempty"`
}

// SummaryReport is the JSON payload for GET /api/v1/stats/summary.
type SummaryReport struct {
	TotalRequests   int64   `json:"total_requests"`
	BlockedRequests int64   `json:"blocked_requests"`
	ActiveSessions  int64   `json:"active_sessions"`
	ReqRate         float64 `json:"req_rate"`
	BackendsUp      int64   `json:"backends_up"`
	BackendsDown    int64   `json:"backends_down"`
	Error           string  `json:"error,omitempty"`
}

// HAProxyCollector fetches and parses HAProxy "show stat" with a short-lived cache.
type HAProxyCollector struct {
	mu       sync.Mutex
	lastPath string
	lastAt   time.Time
	last     *HAProxyReport
	lastErr  error
}

// NewHAProxyCollector creates a collector with a 5s cache per socket path.
func NewHAProxyCollector() *HAProxyCollector {
	return &HAProxyCollector{}
}

// Fetch returns cached HAProxy stats when fresh enough; otherwise reads the Unix socket.
func (c *HAProxyCollector) Fetch(socketPath string) (*HAProxyReport, error) {
	now := time.Now()
	c.mu.Lock()
	if c.last != nil && c.lastPath == socketPath && now.Sub(c.lastAt) < MinHAProxyStatsRefresh {
		out := *c.last
		err := c.lastErr
		c.mu.Unlock()
		return &out, err
	}
	c.mu.Unlock()

	rep, err := fetchHAProxyStatsOnce(socketPath)
	c.mu.Lock()
	c.lastPath = socketPath
	c.lastAt = now
	if rep != nil {
		c.last = rep
	} else {
		c.last = &HAProxyReport{Error: errString(err)}
	}
	c.lastErr = err
	out := *c.last
	c.mu.Unlock()
	return &out, err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func fetchHAProxyStatsOnce(socketPath string) (*HAProxyReport, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, fmt.Errorf("stats socket path is empty")
	}
	raw, err := haproxyShowStat(socketPath)
	if err != nil {
		return nil, err
	}
	rep, err := ParseShowStatCSV(raw)
	if err != nil {
		return nil, err
	}
	rep.CollectedAt = time.Now().UTC()
	return rep, nil
}

func haproxyShowStat(socketPath string) ([]byte, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("stats socket %q: %w", socketPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "show stat\n"); err != nil {
		return nil, err
	}
	const maxRead = 16 << 20
	b, err := io.ReadAll(io.LimitReader(conn, maxRead))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ParseShowStatCSV parses HAProxy native CSV from "show stat" (header line starts with '#').
func ParseShowStatCSV(data []byte) (*HAProxyReport, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var header []string
	var rows [][]string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			r := csv.NewReader(strings.NewReader(strings.TrimSpace(strings.TrimPrefix(line, "#"))))
			r.LazyQuotes = true
			var err error
			header, err = r.Read()
			if err != nil {
				return nil, fmt.Errorf("stats csv header: %w", err)
			}
			continue
		}
		r := csv.NewReader(strings.NewReader(line))
		r.LazyQuotes = true
		r.FieldsPerRecord = -1
		rec, err := r.Read()
		if err != nil {
			continue
		}
		rows = append(rows, rec)
	}
	if len(header) == 0 {
		return nil, fmt.Errorf("stats csv: missing header")
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	_, okPx := idx["pxname"]
	_, okSv := idx["svname"]
	if !okPx || !okSv {
		return nil, fmt.Errorf("stats csv: missing pxname/svname")
	}
	_, hasType := idx["type"]

	var frontends []FrontendStat
	backOrder := []string{}
	backMap := map[string]*BackendStat{}

	for _, rec := range rows {
		if len(rec) < len(header) {
			// pad short rows
			for len(rec) < len(header) {
				rec = append(rec, "")
			}
		}
		px := field(rec, idx, "pxname")
		sv := field(rec, idx, "svname")
		if px == "" {
			continue
		}
		typ := int64(-1)
		if hasType {
			typ = parseInt64(field(rec, idx, "type"))
		}

		if (!hasType && sv == "FRONTEND") || (hasType && typ == 0 && sv == "FRONTEND") {
			frontends = append(frontends, FrontendStat{
				Name:         px,
				Status:       field(rec, idx, "status"),
				SessionsCur:  parseInt64(field(rec, idx, "scur")),
				SessionsMax:  parseInt64(field(rec, idx, "smax")),
				BytesIn:      parseInt64(field(rec, idx, "bin")),
				BytesOut:     parseInt64(field(rec, idx, "bout")),
				ReqRate:      parseInt64(field(rec, idx, "rate")),
				HTTP2xx:      http2xxSum(rec, idx),
				HTTP4xx:      parseInt64(field(rec, idx, "hrsp_4xx")),
				HTTP5xx:      parseInt64(field(rec, idx, "hrsp_5xx")),
				TotalReqHint: hrspTotal(rec, idx),
			})
			continue
		}

		if (!hasType && sv == "BACKEND") || (hasType && typ == 1 && sv == "BACKEND") {
			b := &BackendStat{
				Name:        px,
				Status:      field(rec, idx, "status"),
				SessionsCur: parseInt64(field(rec, idx, "scur")),
				SessionsMax: parseInt64(field(rec, idx, "smax")),
				BytesIn:     parseInt64(field(rec, idx, "bin")),
				BytesOut:    parseInt64(field(rec, idx, "bout")),
				ReqRate:     parseInt64(field(rec, idx, "rate")),
				HTTP2xx:     http2xxSum(rec, idx),
				HTTP4xx:     parseInt64(field(rec, idx, "hrsp_4xx")),
				HTTP5xx:     parseInt64(field(rec, idx, "hrsp_5xx")),
				Servers:     nil,
			}
			backMap[px] = b
			backOrder = append(backOrder, px)
			continue
		}

		if hasType && typ == 2 {
			if b, ok := backMap[px]; ok {
				b.Servers = append(b.Servers, ServerStat{
					Name:        sv,
					Status:      field(rec, idx, "status"),
					SessionsCur: parseInt64(field(rec, idx, "scur")),
				})
			}
			continue
		}
		if !hasType && sv != "FRONTEND" && sv != "BACKEND" {
			if b, ok := backMap[px]; ok {
				b.Servers = append(b.Servers, ServerStat{
					Name:        sv,
					Status:      field(rec, idx, "status"),
					SessionsCur: parseInt64(field(rec, idx, "scur")),
				})
			}
		}
	}

	backends := make([]BackendStat, 0, len(backOrder))
	for _, name := range backOrder {
		b := backMap[name]
		b.Health = deriveBackendHealth(b)
		backends = append(backends, *b)
	}

	return &HAProxyReport{Frontends: frontends, Backends: backends}, nil
}

func field(rec []string, idx map[string]int, key string) string {
	i, ok := idx[key]
	if !ok || i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func parseInt64(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func http2xxSum(rec []string, idx map[string]int) int64 {
	return parseInt64(field(rec, idx, "hrsp_1xx")) +
		parseInt64(field(rec, idx, "hrsp_2xx")) +
		parseInt64(field(rec, idx, "hrsp_3xx"))
}

func hrspTotal(rec []string, idx map[string]int) int64 {
	var t int64
	for _, k := range []string{"hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other"} {
		t += parseInt64(field(rec, idx, k))
	}
	return t
}

func deriveBackendHealth(b *BackendStat) string {
	if len(b.Servers) == 0 {
		return strings.ToLower(strings.TrimSpace(b.Status))
	}
	up, down := 0, 0
	for _, s := range b.Servers {
		st := strings.ToUpper(strings.TrimSpace(s.Status))
		if st == "UP" || strings.HasPrefix(st, "UP ") {
			up++
			continue
		}
		if strings.HasPrefix(st, "DOWN") || strings.HasPrefix(st, "MAINT") || strings.HasPrefix(st, "NOLB") || strings.Contains(st, "DOWN") {
			down++
			continue
		}
		up++
	}
	if down == 0 {
		return "healthy"
	}
	if up == 0 {
		return "down"
	}
	return "degraded"
}

// BuildSummary aggregates HAProxyReport for the dashboard summary API.
func BuildSummary(rep *HAProxyReport) SummaryReport {
	if rep == nil {
		return SummaryReport{}
	}
	out := SummaryReport{}
	if rep.Error != "" {
		out.Error = rep.Error
	}
	var reqRate int64
	var active int64
	var totalHint int64
	var blocked int64
	hasFEHTTPS := false
	for _, fe := range rep.Frontends {
		if strings.EqualFold(strings.TrimSpace(fe.Name), "fe_https") {
			hasFEHTTPS = true
			break
		}
	}
	for _, fe := range rep.Frontends {
		reqRate += fe.ReqRate
		active += fe.SessionsCur
		totalHint += fe.TotalReqHint
		if hasFEHTTPS && !strings.EqualFold(strings.TrimSpace(fe.Name), "fe_https") {
			continue
		}
		blocked += fe.HTTP4xx + fe.HTTP5xx
	}
	var up, down int64
	for _, be := range rep.Backends {
		for _, sv := range be.Servers {
			st := strings.ToUpper(strings.TrimSpace(sv.Status))
			if st == "UP" || strings.HasPrefix(st, "UP ") {
				up++
			} else if strings.Contains(st, "DOWN") || strings.HasPrefix(st, "MAINT") || strings.HasPrefix(st, "NOLB") {
				down++
			}
		}
	}
	out.TotalRequests = totalHint
	out.BlockedRequests = blocked
	out.ActiveSessions = active
	out.ReqRate = float64(reqRate)
	out.BackendsUp = up
	out.BackendsDown = down
	return out
}

// SummarizeFromSocket reads once (no cache) — for tests.
func SummarizeFromSocket(socketPath string) (SummaryReport, *HAProxyReport, error) {
	rep, err := fetchHAProxyStatsOnce(socketPath)
	if err != nil {
		s := BuildSummary(&HAProxyReport{Error: err.Error()})
		s.Error = err.Error()
		return s, nil, err
	}
	return BuildSummary(rep), rep, nil
}
