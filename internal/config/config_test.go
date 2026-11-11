package config

import (
	"strings"
	"testing"
)

func load(env map[string]string) (Config, error) {
	return Load(func(k string) string { return env[k] })
}

func TestDefaults(t *testing.T) {
	c, err := load(map[string]string{"SMTP_HOST": "mail.gnuweeb.org", "ROOT_KEY": "ed9a 91c5 9eda bbe1 977c  848b a19b 0054 411e c812"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTP.Port != 587 || c.SMTP.TLS != "starttls" || c.SMTP.From != "pgp@gnuweeb.org" ||
		c.BaseURL != "https://pgp.gnuweeb.org" || c.EmailDomain != "gnuweeb.org" || !c.Gravatar ||
		c.RootKey != "ED9A91C59EDABBE1977C848BA19B0054411EC812" {
		t.Errorf("defaults: %+v", c)
	}
	c, err = load(map[string]string{"SMTP_HOST": "h", "SMTP_TLS": "implicit", "EMAIL_DOMAIN": "Example.ORG", "BASE_URL": "http://localhost:8081/", "GRAVATAR": "off"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTP.Port != 465 || c.SMTP.From != "pgp@example.org" || c.BaseURL != "http://localhost:8081" || c.Gravatar || c.RootKey != "" {
		t.Errorf("implicit TLS: %+v", c)
	}
}

func TestRejects(t *testing.T) {
	base := map[string]string{"SMTP_HOST": "h"}
	for name, tc := range map[string]struct {
		set  map[string]string
		want string
	}{
		"no smtp host":      {map[string]string{"SMTP_HOST": ""}, "SMTP_HOST"},
		"tls mode":          {map[string]string{"SMTP_TLS": "yes"}, "SMTP_TLS"},
		"port":              {map[string]string{"SMTP_PORT": "70000"}, "SMTP_PORT"},
		"user without pw":   {map[string]string{"SMTP_USERNAME": "u"}, "SMTP_PASSWORD"},
		"from with name":    {map[string]string{"MAIL_FROM": "PGP <pgp@gnuweeb.org>"}, "MAIL_FROM"},
		"base url path":     {map[string]string{"BASE_URL": "https://pgp.gnuweeb.org/x"}, "BASE_URL"},
		"base url scheme":   {map[string]string{"BASE_URL": "ftp://pgp.gnuweeb.org"}, "BASE_URL"},
		"domain with @":     {map[string]string{"EMAIL_DOMAIN": "a@b"}, "EMAIL_DOMAIN"},
		"same addresses":    {map[string]string{"WKD_ADDR": ":1", "DASHBOARD_ADDR": ":1"}, "must differ"},
		"address sans port": {map[string]string{"WKD_ADDR": "localhost"}, "WKD_ADDR"},
		"gravatar":          {map[string]string{"GRAVATAR": "yes"}, "GRAVATAR"},
		"root key":          {map[string]string{"ROOT_KEY": "1234"}, "ROOT_KEY"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range tc.set {
			env[k] = v
		}
		if _, err := load(env); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %s", name, err, tc.want)
		}
	}
}
