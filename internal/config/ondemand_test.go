package config

import (
	"strings"
	"testing"
	"time"
)

func TestMDNSOnDemandDefaults(t *testing.T) {
	c := Default()
	if !c.MDNS.ResolveOnDemand || !c.MDNS.ServeDNSSD {
		t.Error("resolve_on_demand and serve_dnssd should default true")
	}
	if got := c.MDNS.ResolveOnDemandWaitDuration(); got != 300*time.Millisecond {
		t.Errorf("default wait = %v, want 300ms", got)
	}
	c.MDNS.ResolveOnDemandWait = "10ms" // below floor
	if got := c.MDNS.ResolveOnDemandWaitDuration(); got != 50*time.Millisecond {
		t.Errorf("wait = %v, want clamp to 50ms floor", got)
	}
	c.MDNS.ResolveOnDemandWait = "9s" // above cap
	if got := c.MDNS.ResolveOnDemandWaitDuration(); got != 2*time.Second {
		t.Errorf("wait = %v, want clamp to 2s cap", got)
	}
}

func TestResolveOnDemandWaitValidation(t *testing.T) {
	c := Default()
	c.MDNS.ResolveOnDemandWait = "notaduration"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "resolve_on_demand_wait") {
		t.Errorf("a bad wait string must fail Validate mentioning the key; got %v", err)
	}
	c.MDNS.ResolveOnDemandWait = "300ms"
	if err := c.Validate(); err != nil {
		t.Errorf("a valid config was rejected: %v", err)
	}
}
