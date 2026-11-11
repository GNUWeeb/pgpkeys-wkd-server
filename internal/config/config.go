// Package config reads matcha's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/mail"
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
	// EmailDomain is the one mail domain whose members may log in and
	// whose keys are served, lower case.
	EmailDomain string
	// BaseURL is the public URL of the dashboard, without a trailing
	// slash; mailed login links point below it.
	BaseURL string
	// RealIPHeader names the request header that carries the client's
	// address when the dashboard sits behind a reverse proxy (for
	// example X-Real-IP). Empty: use the connection's address.
	RealIPHeader string
	// Gravatar has the dashboard show the photos members keep at
	// Gravatar, fetched by the server. On unless GRAVATAR is off.
	Gravatar bool
	// SMTP is the mail server and sender of the login mails.
	SMTP mail.Config
}

// Load builds a Config from getenv (os.Getenv in production), applying
// defaults for unset variables and rejecting invalid values.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		WKDAddr:       envOr(getenv, "WKD_ADDR", "127.0.0.1:8080"),
		DashboardAddr: envOr(getenv, "DASHBOARD_ADDR", "127.0.0.1:8081"),
		DatabasePath:  DatabasePath(getenv),
		EmailDomain:   strings.ToLower(envOr(getenv, "EMAIL_DOMAIN", "gnuweeb.org")),
		BaseURL:       strings.TrimSuffix(envOr(getenv, "BASE_URL", "https://pgp.gnuweeb.org"), "/"),
		RealIPHeader:  getenv("REAL_IP_HEADER"),
		SMTP: mail.Config{
			Host:     getenv("SMTP_HOST"),
			TLS:      envOr(getenv, "SMTP_TLS", mail.TLSStartTLS),
			Username: getenv("SMTP_USERNAME"),
			Password: getenv("SMTP_PASSWORD"),
		},
	}
	c.SMTP.From = envOr(getenv, "MAIL_FROM", "pgp@"+c.EmailDomain)

	switch g := envOr(getenv, "GRAVATAR", "on"); g {
	case "on", "off":
		c.Gravatar = g == "on"
	default:
		return Config{}, fmt.Errorf("GRAVATAR: %q is not on or off", g)
	}
	for name, addr := range map[string]string{"WKD_ADDR": c.WKDAddr, "DASHBOARD_ADDR": c.DashboardAddr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if c.WKDAddr == c.DashboardAddr {
		return Config{}, fmt.Errorf("WKD_ADDR and DASHBOARD_ADDR must differ, both are %q", c.WKDAddr)
	}
	if c.EmailDomain == "" || strings.ContainsAny(c.EmailDomain, "@ /") {
		return Config{}, fmt.Errorf("EMAIL_DOMAIN: %q is not a domain", c.EmailDomain)
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" {
		return Config{}, fmt.Errorf("BASE_URL: %q is not an http(s) URL without path", c.BaseURL)
	}

	if c.SMTP.Host == "" {
		return Config{}, errors.New("SMTP_HOST is required")
	}
	switch c.SMTP.TLS {
	case mail.TLSImplicit, mail.TLSStartTLS, mail.TLSNone:
	default:
		return Config{}, fmt.Errorf("SMTP_TLS: %q is not one of implicit, starttls, none", c.SMTP.TLS)
	}
	defPort := "587"
	if c.SMTP.TLS == mail.TLSImplicit {
		defPort = "465"
	}
	if c.SMTP.Port, err = strconv.Atoi(envOr(getenv, "SMTP_PORT", defPort)); err != nil || c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
		return Config{}, fmt.Errorf("SMTP_PORT: %q is not a port", getenv("SMTP_PORT"))
	}
	if (c.SMTP.Username == "") != (c.SMTP.Password == "") {
		return Config{}, errors.New("SMTP_USERNAME and SMTP_PASSWORD must be set together")
	}
	if !strings.Contains(c.SMTP.From, "@") || strings.ContainsAny(c.SMTP.From, " <>\r\n") {
		return Config{}, fmt.Errorf("MAIL_FROM: %q is not a bare address", c.SMTP.From)
	}
	return c, nil
}

func envOr(getenv func(string) string, name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}

// DatabasePath returns DATABASE_PATH or its default. Commands that only
// need the database, such as the keyring export, read it alone.
func DatabasePath(getenv func(string) string) string {
	return envOr(getenv, "DATABASE_PATH", "matcha.db")
}
