package security

import (
	"crypto/tls"
	"net/http"
	"time"
)

const (
	// DefaultHTTPTimeout is the default timeout for HTTP requests
	DefaultHTTPTimeout = 30 * time.Second

	// DefaultTLSHandshakeTimeout is the default timeout for TLS handshakes
	DefaultTLSHandshakeTimeout = 10 * time.Second

	// DefaultIdleConnTimeout is the default timeout for idle connections
	DefaultIdleConnTimeout = 90 * time.Second

	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns = 100

	// MaxIdleConnsPerHost is the maximum number of idle connections per host
	MaxIdleConnsPerHost = 10
)

// SecureHTTPClient returns a configured HTTP client with proper timeouts and TLS verification
func SecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Verify certificates by default - can be overridden for specific use cases
				InsecureSkipVerify: false,
			},
			TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
			IdleConnTimeout:       DefaultIdleConnTimeout,
			MaxIdleConns:          MaxIdleConns,
			MaxIdleConnsPerHost:   MaxIdleConnsPerHost,
			DisableCompression:    false,
			ResponseHeaderTimeout: DefaultHTTPTimeout,
		},
	}
}

// InsecureHTTPClient returns an HTTP client that skips TLS verification
// WARNING: Only use for trusted internal services or development
func InsecureHTTPClient() *http.Client {
	client := SecureHTTPClient()
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	return client
}

// LongRunningHTTPClient returns an HTTP client optimized for long-running operations like LLM inference
// It separates response header timeout (short) from total operation timeout (long)
func LongRunningHTTPClient(timeout time.Duration) *http.Client {
	// For large models (70B on CPU), response can take 2-3+ minutes
	// Set header timeout to 90% of total timeout to avoid premature timeouts
	headerTimeout := timeout * 9 / 10
	if headerTimeout < 1*time.Minute {
		headerTimeout = 1 * time.Minute // Minimum 1 minute
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			},
			TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
			IdleConnTimeout:       DefaultIdleConnTimeout,
			MaxIdleConns:          MaxIdleConns,
			MaxIdleConnsPerHost:   MaxIdleConnsPerHost,
			DisableCompression:    false,
			ResponseHeaderTimeout: headerTimeout, // Separate short timeout for headers to arrive
		},
	}
}

// CustomHTTPClient returns an HTTP client with custom timeout
func CustomHTTPClient(timeout time.Duration) *http.Client {
	client := SecureHTTPClient()
	client.Timeout = timeout
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.ResponseHeaderTimeout = timeout
	}
	return client
}
