package main

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// servePreview exposes the loopback-only demo through a reverse proxy so it
// can be reviewed behind an HTTPS preview gateway. It rewrites Host and
// Origin to the loopback upstream, which is exactly what the production
// server's DNS-rebinding and same-origin checks require, and adjusts the CSP
// so the browser may open the secure WebSocket on the public host.
// This exists only in the demo binary; syspulse.exe has no such mode.
func servePreview(listen, upstream string, log *slog.Logger) error {
	target := &url.URL{Scheme: "http", Host: upstream}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Host = upstream
			if pr.In.Header.Get("Origin") != "" {
				pr.Out.Header.Set("Origin", "http://"+upstream)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			pub := resp.Request.Header.Get("X-Forwarded-Host")
			if csp := resp.Header.Get("Content-Security-Policy"); csp != "" && pub != "" {
				resp.Header.Set("Content-Security-Policy",
					strings.Replace(csp, "ws://"+upstream, "ws://"+pub+" wss://"+pub, 1))
			}
			return nil
		},
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("preview proxy listening", "addr", listen, "upstream", upstream)
	return (&http.Server{Handler: rp, ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}
