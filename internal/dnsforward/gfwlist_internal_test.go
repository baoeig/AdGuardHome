package dnsforward

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGFWList(t *testing.T) {
	t.Parallel()

	list := `! comment
[AutoProxy 0.2.9]
||example.com
||sub.example.com^
|https://www.example.net/path
@@||sub.example.com
|http://192.0.2.1/
/regexp/
||invalid_domain.example
`
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(list)))
	base64.StdEncoding.Encode(encoded, []byte(list))

	domains, err := parseGFWList(encoded)
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com", "www.example.net"}, domains)
}

func TestGFWListUpstreamSpecs(t *testing.T) {
	t.Parallel()

	specs := gfwListUpstreamSpecs(
		[]string{"example.com", "example.net"},
		[]string{"1.1.1.1", "tls://dns.google"},
	)

	assert.Equal(t, []string{
		"[/example.com/example.net/]1.1.1.1",
		"[/example.com/example.net/]tls://dns.google",
	}, specs)
}

func TestServerConfigLoadGFWListUpstreams(t *testing.T) {
	t.Parallel()

	list := "||example.com\n||example.net\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(list))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(encoded))
	}))
	t.Cleanup(srv.Close)

	conf := &ServerConfig{
		Config: Config{GFWList: GFWListConfig{
			Enabled:              true,
			URL:                  srv.URL,
			UpstreamDNS:          []string{"1.1.1.1"},
			RefreshIntervalHours: defaultGFWListRefreshInterval,
		}},
		GFWListHTTPClient: srv.Client(),
		GFWListCachePath:  filepath.Join(t.TempDir(), "gfwlist_domains.txt"),
	}

	specs, err := conf.loadGFWListUpstreams(context.Background(), slogutil.NewDiscardLogger())
	require.NoError(t, err)
	assert.Equal(t, []string{"[/example.com/example.net/]1.1.1.1"}, specs)

	srv.Close()
	specs, err = conf.loadGFWListUpstreams(context.Background(), slogutil.NewDiscardLogger())
	require.NoError(t, err)
	assert.Equal(t, []string{"[/example.com/example.net/]1.1.1.1"}, specs)
}
