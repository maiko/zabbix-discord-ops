package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/maiko/zabbix-discord-ops/internal/app"
	"github.com/maiko/zabbix-discord-ops/internal/config"
)

var version = "dev"

func main() {
	configPath := flag.String(
		"config",
		"/etc/zabbix-discord-ops/config.json",
		"path to the non-secret JSON configuration",
	)
	healthcheckURL := flag.String(
		"healthcheck",
		"",
		"check a loopback HTTP health endpoint and exit",
	)
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version)
		return
	}
	if *healthcheckURL != "" {
		if err := healthcheck(*healthcheckURL); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	secrets, err := config.LoadSecrets()
	if err != nil {
		logger.Error("credential loading failed", "error", err)
		os.Exit(1)
	}
	application, err := app.New(cfg, secrets, logger)
	if err != nil {
		logger.Error("application initialization failed", "error", err)
		os.Exit(1)
	}
	identityContext, cancelIdentity := context.WithTimeout(context.Background(), 5*time.Second)
	if err := application.ValidateDiscordIdentity(identityContext); err != nil {
		cancelIdentity()
		logger.Error("Discord identity validation failed", "error", err)
		os.Exit(1)
	}
	cancelIdentity()

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           application.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       8 * time.Second,
		WriteTimeout:      12 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go application.RunMaintenance(ctx)
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		defer close(shutdownDone)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("HTTP shutdown failed", "error", err)
		}
		if err := application.WaitForDeferred(shutdownCtx); err != nil {
			logger.Error("deferred interaction shutdown failed", "error", err)
		}
	}()

	logger.Info("Zabbix Ops listening", "address", cfg.Listen, "version", version)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server failed", "error", err)
		os.Exit(1)
	}
	if ctx.Err() != nil {
		<-shutdownDone
	}
}

func healthcheck(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return errors.New("healthcheck URL must be an absolute HTTP URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("healthcheck URL must use an IP loopback address")
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("healthcheck redirects are not allowed")
		},
	}
	response, err := client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned HTTP %d", response.StatusCode)
	}
	return nil
}
