// Command matcha serves GNUWeeb members' OpenPGP keys through Web Key
// Directory and a dashboard where members manage them.
//
// Usage:
//
//	matcha              run the service
//	matcha export DIR   write the keyring into DIR (keys/, keys/expired/)
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/config"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/export"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/mail"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/reminder"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var err error
	switch args := os.Args[1:]; {
	case len(args) == 0:
		err = run(log)
	case len(args) == 2 && args[0] == "export":
		err = exportKeys(args[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: matcha [export DIR]")
		os.Exit(2)
	}
	if err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

// exportKeys writes the keyring into dir and prints each file it wrote
// or removed. It needs only DATABASE_PATH, and refuses a database that
// does not exist: opening one would create it empty, and an empty
// export removes every key file in dir.
func exportKeys(dir string) error {
	path := config.DatabasePath(os.Getenv)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("DATABASE_PATH: %s does not exist", path)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, path)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := export.Write(ctx, st, dir, time.Now())
	if err != nil {
		return err
	}
	for _, p := range res.Written {
		fmt.Println("write", p)
	}
	for _, p := range res.Removed {
		fmt.Println("remove", p)
	}
	return nil
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer st.Close()

	mailer := mail.New(cfg.SMTP)
	dash := web.New(web.Options{
		Domain:       cfg.EmailDomain,
		BaseURL:      cfg.BaseURL,
		RealIPHeader: cfg.RealIPHeader,
	}, st, mailer, log)

	// The daily key check mails expiry reminders until shutdown.
	var reminders sync.WaitGroup
	reminders.Go(func() { reminder.New(st, mailer, cfg.BaseURL, log).Loop(ctx, time.Now) })

	servers := []*http.Server{
		newServer(cfg.WKDAddr, wkd.NewHandler(st, log)),
		newServer(cfg.DashboardAddr, dash),
	}
	err = serve(ctx, log, servers)
	stop()
	reminders.Wait()
	dash.Wait()
	return err
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// serve runs every server until ctx is cancelled or one of them fails,
// then shuts all of them down.
func serve(ctx context.Context, log *slog.Logger, servers []*http.Server) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, srv := range servers {
		g.Go(func() error {
			log.Info("listening", "addr", srv.Addr)
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
		g.Go(func() error {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		})
	}
	return g.Wait()
}
