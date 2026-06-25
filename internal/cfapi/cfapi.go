// Package cfapi is a small Cloudflare API v4 client covering exactly what splitdns
// needs: enumerate zones, list a host's DNS records, and create/update/delete
// records. It deliberately avoids a heavyweight SDK to stay lightweight and
// dependency-free. The base URL is injectable so the test harness (and sandbox mock
// Cloudflare) can point it at an in-process server; the bearer token is supplied by
// the caller, which reads it from a 0400 file.
//
// A Client satisfies both ddns.RecordSource and ddns.Editor. Construct one with the
// read token for the mirror/record lookups and one with the DNS:Edit token for the
// writer (least privilege, design §security).
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/gutschke/splitdns/internal/model"
)

// DefaultBaseURL is the production Cloudflare API root.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// writeTTL is the TTL applied to records the writer creates (seconds). Internal
// names do not need long caching; a low value bounds staleness after a change.
const writeTTL = 60

// Client is a Cloudflare API client.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client

	mu    sync.Mutex
	zones map[string]string // zoneID -> zoneName (lazy, cached)
}

// New returns a Client. baseURL "" defaults to production; hc nil uses a sane
// bounded http.Client.
func New(baseURL, token string, hc *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, hc: hc}
}

// envelope is the standard Cloudflare response wrapper.
type envelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
	Info    *resultInfo     `json:"result_info,omitempty"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

type zoneRec struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type dnsRec struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content"`
	Proxied  bool    `json:"proxied"`
	TTL      int     `json:"ttl"`
	Priority float64 `json:"priority"`
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*envelope, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("cfapi: %s %s: bad response (status %d): %w", method, path, resp.StatusCode, err)
	}
	if !env.Success {
		return &env, fmt.Errorf("cfapi: %s %s: %s", method, path, formatErrors(env.Errors, resp.StatusCode))
	}
	return &env, nil
}

func formatErrors(errs []cfError, status int) string {
	if len(errs) == 0 {
		return fmt.Sprintf("status %d", status)
	}
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = fmt.Sprintf("%d %s", e.Code, e.Message)
	}
	return strings.Join(parts, "; ")
}

// Zones returns and caches the account's zoneID->zoneName map (paginated).
func (c *Client) Zones(ctx context.Context) (map[string]string, error) {
	c.mu.Lock()
	if c.zones != nil {
		z := c.zones
		c.mu.Unlock()
		return z, nil
	}
	c.mu.Unlock()

	zones := map[string]string{}
	for page := 1; ; page++ {
		q := url.Values{"per_page": {"50"}, "page": {fmt.Sprint(page)}}
		env, err := c.do(ctx, http.MethodGet, "/zones", q, nil)
		if err != nil {
			return nil, err
		}
		var zs []zoneRec
		if err := json.Unmarshal(env.Result, &zs); err != nil {
			return nil, fmt.Errorf("cfapi: decode zones: %w", err)
		}
		for _, z := range zs {
			zones[z.ID] = strings.ToLower(z.Name)
		}
		if env.Info == nil || env.Info.TotalPages <= page || len(zs) == 0 {
			break
		}
	}
	c.mu.Lock()
	c.zones = zones
	c.mu.Unlock()
	return zones, nil
}

// RecordsForHost implements ddns.RecordSource: it returns the non-proxied A/AAAA
// records whose relative owner equals shortHost, across every zone (the §4.4
// cross-source join). The query uses Cloudflare's exact-name filter per zone.
func (c *Client) RecordsForHost(ctx context.Context, shortHost string) ([]model.RR, error) {
	zones, err := c.Zones(ctx)
	if err != nil {
		return nil, err
	}
	shortHost = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(shortHost), "."))
	var out []model.RR
	for zoneID, zoneName := range zones {
		fqdn := shortHost + "." + zoneName
		q := url.Values{"name": {fqdn}, "per_page": {"100"}}
		env, err := c.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records", q, nil)
		if err != nil {
			return nil, err
		}
		var recs []dnsRec
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, fmt.Errorf("cfapi: decode records: %w", err)
		}
		for _, r := range recs {
			typ, ok := abType(r.Type)
			if !ok || r.Proxied {
				continue
			}
			out = append(out, model.RR{
				Name:     ensureDot(strings.ToLower(r.Name)),
				Type:     typ,
				Class:    dns.ClassINET,
				Content:  r.Content,
				ZoneID:   zoneID,
				RecordID: r.ID,
				Proxied:  r.Proxied,
			})
		}
	}
	return out, nil
}

// Record is a Cloudflare DNS record as returned by the API (all types). It is the
// input to the mirror's zone builder.
type Record struct {
	ID       string
	Type     string
	Name     string
	Content  string
	Proxied  bool
	TTL      int
	Priority float64
}

// AllRecords returns every DNS record in a zone, draining all pages (no silent
// truncation cap, design §2.5). Used by the mirror to build the authoritative zone.
func (c *Client) AllRecords(ctx context.Context, zoneID string) ([]Record, error) {
	var out []Record
	for page := 1; ; page++ {
		q := url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}
		env, err := c.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records", q, nil)
		if err != nil {
			return nil, err
		}
		var recs []dnsRec
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, fmt.Errorf("cfapi: decode records: %w", err)
		}
		for _, r := range recs {
			out = append(out, Record{ID: r.ID, Type: r.Type, Name: r.Name, Content: r.Content, Proxied: r.Proxied, TTL: r.TTL, Priority: r.Priority})
		}
		if env.Info == nil || env.Info.TotalPages <= page || len(recs) == 0 {
			break
		}
	}
	return out, nil
}

// Create implements ddns.Editor.
func (c *Client) Create(ctx context.Context, zoneID, name string, typ uint16, content string) (string, error) {
	body := map[string]any{
		"type":    dns.TypeToString[typ],
		"name":    strings.TrimSuffix(name, "."),
		"content": content,
		"ttl":     writeTTL,
		"proxied": false,
	}
	env, err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", nil, body)
	if err != nil {
		return "", err
	}
	var rec dnsRec
	if err := json.Unmarshal(env.Result, &rec); err != nil {
		return "", fmt.Errorf("cfapi: decode created record: %w", err)
	}
	return rec.ID, nil
}

// Update implements ddns.Editor (PATCH reuses the existing record ID).
func (c *Client) Update(ctx context.Context, zoneID, recordID, name string, typ uint16, content string) error {
	body := map[string]any{
		"type":    dns.TypeToString[typ],
		"name":    strings.TrimSuffix(name, "."),
		"content": content,
		"ttl":     writeTTL,
		"proxied": false,
	}
	_, err := c.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+recordID, nil, body)
	return err
}

// Delete implements ddns.Editor.
func (c *Client) Delete(ctx context.Context, zoneID, recordID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil)
	return err
}

func abType(s string) (uint16, bool) {
	switch strings.ToUpper(s) {
	case "A":
		return dns.TypeA, true
	case "AAAA":
		return dns.TypeAAAA, true
	default:
		return 0, false
	}
}

func ensureDot(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
