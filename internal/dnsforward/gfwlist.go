package dnsforward

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/aghrenameio"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/ioutil"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// GFWListConfig is the configuration for routing GFWList domains through
// dedicated upstream DNS servers.
type GFWListConfig struct {
	// URL is the address of a Base64-encoded GFWList.
	URL string `yaml:"url"`

	// UpstreamDNS is the list of upstream DNS servers used for matching domains.
	UpstreamDNS []string `yaml:"upstream_dns"`

	// Enabled controls whether GFWList-based upstream routing is enabled.
	Enabled bool `yaml:"enabled"`

	// RefreshIntervalHours is the interval between GFWList refreshes.
	RefreshIntervalHours uint32 `yaml:"refresh_interval"`
}

const (
	maxGFWListSize = 16 * 1024 * 1024
	gfwDomainBatch = 128
)

func (c GFWListConfig) validate() (err error) {
	if !c.Enabled {
		return nil
	}

	if len(c.UpstreamDNS) == 0 {
		return errors.Error("gfwlist upstream servers are empty")
	}
	if c.RefreshIntervalHours < 1 || c.RefreshIntervalHours > 168 {
		return fmt.Errorf(
			"gfwlist refresh interval must be between 1 and 168 hours: %d",
			c.RefreshIntervalHours,
		)
	}

	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("parsing gfwlist url: %w", err)
	}

	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("gfwlist url must use http or https: %q", c.URL)
	}

	return nil
}

func fetchGFWList(ctx context.Context, cli *http.Client, urlStr string) (domains []string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("creating gfwlist request: %w", err)
	}

	// #nosec G704 -- The URL is explicitly configured by the administrator.
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading gfwlist: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading gfwlist: got status code %d", resp.StatusCode)
	}

	encoded, err := io.ReadAll(ioutil.LimitReader(resp.Body, maxGFWListSize))
	if err != nil {
		return nil, fmt.Errorf("reading gfwlist: %w", err)
	}

	domains, err = parseGFWList(encoded)
	if err != nil {
		return nil, fmt.Errorf("parsing gfwlist: %w", err)
	}

	return domains, nil
}

func parseGFWList(encoded []byte) (domains []string, err error) {
	encoded = bytes.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}

		return r
	}, encoded)

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}

	included := map[string]struct{}{}
	excluded := map[string]struct{}{}
	s := bufio.NewScanner(bytes.NewReader(decoded[:n]))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}

		isException := strings.HasPrefix(line, "@@")
		line = strings.TrimPrefix(line, "@@")
		domain := domainFromGFWRule(line)
		if domain == "" {
			continue
		}

		if isException {
			excluded[domain] = struct{}{}
		} else {
			included[domain] = struct{}{}
		}
	}
	if err = s.Err(); err != nil {
		return nil, err
	}

	for domain := range included {
		if domainIsExcluded(domain, excluded) {
			delete(included, domain)
		}
	}

	domains = make([]string, 0, len(included))
	for domain := range included {
		domains = append(domains, domain)
	}
	slices.Sort(domains)

	if len(domains) == 0 {
		return nil, errors.Error("gfwlist contains no supported domains")
	}

	return domains, nil
}

func domainFromGFWRule(rule string) (domain string) {
	rule = strings.TrimSpace(rule)
	if rule == "" || strings.HasPrefix(rule, "/") {
		return ""
	}

	rule = strings.TrimLeft(rule, "|")
	if strings.Contains(rule, "://") {
		u, err := url.Parse(rule)
		if err != nil {
			return ""
		}

		domain = u.Hostname()
	} else {
		if i := strings.IndexAny(rule, "^/*?|="); i >= 0 {
			rule = rule[:i]
		}

		domain = rule
	}

	domain = strings.Trim(strings.ToLower(domain), ".")
	if domain == "" || !strings.Contains(domain, ".") {
		return ""
	}
	if _, ipErr := netip.ParseAddr(domain); ipErr == nil {
		return ""
	}

	for _, label := range strings.Split(domain, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return ""
			}
		}
	}

	return domain
}

func domainIsExcluded(domain string, excluded map[string]struct{}) (ok bool) {
	for {
		if _, ok = excluded[domain]; ok {
			return true
		}

		i := strings.IndexByte(domain, '.')
		if i < 0 {
			return false
		}

		domain = domain[i+1:]
	}
}

func writeGFWListCache(path string, domains []string) (err error) {
	f, err := aghrenameio.NewPendingFile(path, aghos.DefaultPermFile)
	if err != nil {
		return err
	}
	defer func() { err = aghrenameio.WithDeferredCleanup(err, f) }()

	_, err = f.Write([]byte(strings.Join(domains, "\n") + "\n"))

	return err
}

func readGFWListCache(path string) (domains []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for _, domain := range strings.Fields(string(data)) {
		if normalized := domainFromGFWRule(domain); normalized != "" {
			domains = append(domains, normalized)
		}
	}

	if len(domains) == 0 {
		return nil, errors.Error("gfwlist cache contains no domains")
	}

	return domains, nil
}

func gfwListUpstreamSpecs(domains, upstreams []string) (specs []string) {
	for start := 0; start < len(domains); start += gfwDomainBatch {
		end := min(start+gfwDomainBatch, len(domains))
		domainSpec := "[/" + strings.Join(domains[start:end], "/") + "/]"
		for _, ups := range upstreams {
			if ups = strings.TrimSpace(ups); ups != "" {
				specs = append(specs, domainSpec+ups)
			}
		}
	}

	return specs
}

func (conf *ServerConfig) loadGFWListUpstreams(
	ctx context.Context,
	l *slog.Logger,
) (specs []string, err error) {
	c := conf.GFWList
	if !c.Enabled {
		return nil, nil
	}

	if err = c.validate(); err != nil {
		return nil, err
	}
	if conf.GFWListHTTPClient == nil {
		return nil, errors.Error("gfwlist http client is nil")
	}
	if conf.GFWListCachePath == "" {
		return nil, errors.Error("gfwlist cache path is empty")
	}

	domains, err := fetchGFWList(ctx, conf.GFWListHTTPClient, c.URL)
	if err == nil {
		if cacheErr := writeGFWListCache(conf.GFWListCachePath, domains); cacheErr != nil {
			l.WarnContext(ctx, "writing gfwlist cache", slogutil.KeyError, cacheErr)
		}
	} else {
		l.WarnContext(ctx, "downloading gfwlist; using cache", slogutil.KeyError, err)
		domains, err = readGFWListCache(conf.GFWListCachePath)
		if err != nil {
			return nil, fmt.Errorf("loading gfwlist cache: %w", err)
		}
	}

	l.InfoContext(ctx, "loaded gfwlist domains", "count", len(domains))

	return gfwListUpstreamSpecs(domains, c.UpstreamDNS), nil
}
