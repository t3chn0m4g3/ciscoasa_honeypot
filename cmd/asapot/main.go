package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/chain"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/ike"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/webvpn"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func run() error {
	https := flag.String("https", ":8443", "HTTPS listen address")
	udp := flag.String("ike", ":500", "IKE listen address")
	natt := flag.String("natt", ":4500", "NAT-T listen address")
	id := flag.String("identity", "/var/lib/ciscoasa/identity.json", "Persistent identity")
	logpath := flag.String("log", "/var/log/ciscoasa/ciscoasa.json", "JSONL log")
	payloads := flag.String("payloads", "/var/lib/ciscoasa/payloads", "Inert upload storage")
	flag.Parse()
	p, err := identity.Load(*id)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(*logpath), 0700); err != nil {
		return err
	}
	l, err := eventlog.New(*logpath)
	if err != nil {
		return err
	}
	store, err := chain.New(*payloads)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(p.Certificate), []byte(p.PrivateKey))
	if err != nil {
		return err
	}
	server := webvpn.New(p, l, store).HTTPServer(*https)
	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}}
	tcp, err := net.Listen("tcp", *https)
	if err != nil {
		return err
	}
	defer tcp.Close()
	addr, err := net.ResolveUDPAddr("udp", *udp)
	if err != nil {
		return err
	}
	u, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer u.Close()
	addr, err = net.ResolveUDPAddr("udp", *natt)
	if err != nil {
		return err
	}
	v, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 3)
	is := ike.New(p, l)
	go func() { errs <- is.Serve(ctx, u, false) }()
	go func() { errs <- is.Serve(ctx, v, true) }()
	go func() { errs <- server.ServeTLS(webvpn.Limit(tcp), "", "") }()
	select {
	case <-ctx.Done():
	case err = <-errs:
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdown)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
