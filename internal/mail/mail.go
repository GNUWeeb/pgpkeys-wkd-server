// Package mail sends plain-text mail over SMTP.
package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// TLS modes of the SMTP connection.
const (
	TLSImplicit = "implicit" // TLS from the first byte (usually port 465)
	TLSStartTLS = "starttls" // plain connection upgraded with STARTTLS (usually 587); required
	TLSNone     = "none"     // no TLS; only for a local catcher
)

// Config describes the SMTP server and the sender.
type Config struct {
	Host     string
	Port     int
	TLS      string
	Username string // empty: no authentication
	Password string
	From     string // envelope and header sender, a bare address
}

// Mailer sends mail with a fixed configuration.
type Mailer struct {
	cfg Config
}

// New returns a Mailer for cfg.
func New(cfg Config) *Mailer { return &Mailer{cfg: cfg} }

// Send delivers one plain-text message to a single recipient. ctx bounds
// the whole SMTP conversation.
func (m *Mailer) Send(ctx context.Context, to, subject, body string) error {
	msg, err := m.compose(to, subject, body)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	tlsConfig := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if m.cfg.TLS == TLSImplicit {
		tc := tls.Client(conn, tlsConfig)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if m.cfg.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp %s: server does not offer STARTTLS", addr)
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if m.cfg.Username != "" {
		// PlainAuth refuses to send the password unless the connection
		// is TLS or goes to localhost.
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.cfg.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// compose builds the message with CRLF line ends.
func (m *Mailer) compose(to, subject, body string) ([]byte, error) {
	for _, v := range []string{to, m.cfg.From} {
		if strings.ContainsAny(v, "\r\n<>") {
			return nil, fmt.Errorf("invalid address %q", v)
		}
	}
	var id [16]byte
	rand.Read(id[:])
	_, domain, _ := strings.Cut(m.cfg.From, "@")

	var b strings.Builder
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", m.cfg.From)
	header("To", to)
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	header("Auto-Submitted", "auto-generated")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String()), nil
}
