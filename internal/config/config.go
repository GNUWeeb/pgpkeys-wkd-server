// Package config reads matcha's settings from the environment.
package config

import (
	"fmt"
	"net"
)

// Config holds every setting matcha reads at startup.
type Config struct {
	// WKDAddr is the listen address of the WKD surface, which only the
	// nginx in front of the mail domain should reach.
	WKDAddr string
	// DashboardAddr is the listen address of the dashboard.
	DashboardAddr string
	// DatabasePath is the SQLite database file; it is created if missing.
	DatabasePath string
}

// Load builds a Config from getenv (os.Getenv in production), applying
// defaults for unset variables and rejecting invalid values.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		WKDAddr:       envOr(getenv, "WKD_ADDR", "127.0.0.1:8080"),
		DashboardAddr: envOr(getenv, "DASHBOARD_ADDR", "127.0.0.1:8081"),
		DatabasePath:  envOr(getenv, "DATABASE_PATH", "matcha.db"),
	}
	for name, addr := range map[string]string{"WKD_ADDR": c.WKDAddr, "DASHBOARD_ADDR": c.DashboardAddr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if c.WKDAddr == c.DashboardAddr {
		return Config{}, fmt.Errorf("WKD_ADDR and DASHBOARD_ADDR must differ, both are %q", c.WKDAddr)
	}
	return c, nil
}

func envOr(getenv func(string) string, name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}
