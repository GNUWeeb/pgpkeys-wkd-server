package mail

import (
	"context"
	"strings"
	"testing"
)

func TestComposeRejectsHeaderInjection(t *testing.T) {
	m := New(Config{From: "pgp@gnuweeb.org"})
	for _, to := range []string{"a@gnuweeb.org\r\nBcc: x@evil.org", "a@gnuweeb.org>", "a@gnuweeb.org\n"} {
		if _, err := m.compose(to, "s", "b"); err == nil {
			t.Errorf("compose accepted recipient %q", to)
		}
	}
	if err := m.Send(context.Background(), "a@gnuweeb.org\r\nBcc: x@evil.org", "s", "b"); err == nil {
		t.Error("Send accepted an injected recipient")
	}
}

func TestComposeUsesCRLF(t *testing.T) {
	m := New(Config{From: "pgp@gnuweeb.org"})
	msg, err := m.compose("a@gnuweeb.org", "Log in", "line 1\nline 2\r\n")
	if err != nil {
		t.Fatal(err)
	}
	s := string(msg)
	if strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\n") {
		t.Error("bare LF in message")
	}
	if !strings.Contains(s, "\r\n\r\nline 1\r\nline 2\r\n") || !strings.Contains(s, "Message-ID: <") ||
		!strings.Contains(s, "@gnuweeb.org>\r\n") {
		t.Errorf("message:\n%s", s)
	}
}
