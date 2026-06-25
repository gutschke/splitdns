// Package netnse2e holds end-to-end tests that run the real splitdns components
// inside an isolated network namespace (design S24). Egress is structurally
// impossible here, so these tests prove behavior against in-namespace mocks only
// and can never reach the production resolver or Cloudflare.
package netnse2e

import (
	"testing"

	"github.com/gutschke/splitdns/internal/netnstest"
)

func TestMain(m *testing.M) {
	netnstest.RunMain(m)
}
