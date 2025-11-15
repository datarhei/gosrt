package srt

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	promListenDefault       = "127.0.0.1:9000" // ":9000" to listen on all interfaces
	promPathDefault         = "/metrics"
	promMaxRequestsInFlight = 10
	promEnableOpenMetrics   = true
	quantileError           = 0.05
	summaryVecMaxAge        = 5 * time.Minute
)

// initPromHandler starts the Prometheus HTTP handler with error checking.
// It registers the Prometheus metrics handler at the specified path and starts
// an HTTP server listening on the specified address in a background goroutine.
//
// The handler uses prometheus.DefaultGatherer to collect all registered metrics.
// See: https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/promhttp?tab=doc#HandlerOpts
func initPromHandler(promPath string, promListen string) {
	fmt.Fprintf(os.Stderr, "Prometheus metrics listening on %s%s\n", promListen, promPath)
	http.Handle(promPath, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics:   promEnableOpenMetrics,
			MaxRequestsInFlight: promMaxRequestsInFlight,
		},
	))
	go func() {
		err := http.ListenAndServe(promListen, nil)
		if err != nil {
			log.Fatal("prometheus error: ", err)
		}
	}()
}

// validateListenAddress validates that the address is in the correct format
// for network listening. Supports both IPv4 (e.g., "127.0.0.1:9000") and
// IPv6 (e.g., "[::1]:9000" or ":9000") addresses.
func validateListenAddress(addr string) bool {
	if addr == "" {
		return false
	}

	// Try to split host and port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	// Port must be present
	if port == "" {
		return false
	}

	// If host is empty, it means listen on all interfaces (valid)
	if host == "" {
		return true
	}

	// Validate host is a valid IP address (IPv4 or IPv6)
	// For IPv6, the brackets are removed by SplitHostPort
	if ip := net.ParseIP(host); ip != nil {
		return true
	}

	// If it's not a valid IP, it might be a hostname - we'll allow it
	// but log a warning. The actual listen will fail if it's invalid.
	return true
}

// validateMetricsPath validates that the path is a valid HTTP path.
// It must start with a forward slash, not contain invalid characters,
// and be no longer than 50 characters.
func validateMetricsPath(path string) bool {
	if path == "" {
		return false
	}

	// Must start with forward slash
	if !strings.HasPrefix(path, "/") {
		return false
	}

	// Length limit
	if len(path) > 50 {
		return false
	}

	// Should not contain spaces or control characters
	if strings.ContainsAny(path, " \t\r\n") {
		return false
	}

	return true
}

// environmentOverrideProm returns the Prometheus listen address and path,
// using the default constants and overriding them if the corresponding
// environment variables exist and pass validation.
//
// Environment variables:
//   - PROM_LISTEN: Override the listen address (e.g., "127.0.0.1:9000", "[::1]:9000", ":9000")
//   - PROM_PATH: Override the metrics path (e.g., "/prometheus/metrics")
//
// If validation fails, the default values are used and a warning is logged.
//
// Returns:
//   - promListen: The listen address (default or from PROM_LISTEN env var if valid)
//   - promPath: The metrics path (default or from PROM_PATH env var if valid)
func environmentOverrideProm() (promListen, promPath string) {
	promListen = promListenDefault
	promPath = promPathDefault

	key := "PROM_LISTEN"
	if value, exists := os.LookupEnv(key); exists {
		if validateListenAddress(value) {
			promListen = value
		} else {
			log.Printf("prometheus: invalid PROM_LISTEN value '%s', using default '%s'", value, promListenDefault)
		}
	}

	key = "PROM_PATH"
	if value, exists := os.LookupEnv(key); exists {
		if validateMetricsPath(value) {
			promPath = value
		} else {
			log.Printf("prometheus: invalid PROM_PATH value '%s', using default '%s'", value, promPathDefault)
		}
	}

	return promListen, promPath
}
