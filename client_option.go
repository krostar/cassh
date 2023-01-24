package cassh

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/krostar/httpclient"
)

// ClientOption defines the signature of all options usable on NewClient.
type ClientOption func(o *clientOptions)

type clientOptions struct {
	serverTimezone           *time.Location
	httpDoer                 httpclient.Doer
	httpDefaultHeaders       http.Header
	tolerateInsecureProtocol bool
}

func clientOptionsDefaults() *clientOptions {
	clientVersion := fmt.Sprintf("krostar/cassh-v1_" + runtime.Version())

	defaultHeaders := make(http.Header)
	defaultHeaders.Set("User-Agent", "CASSH-CLIENT "+clientVersion)
	defaultHeaders.Set("CLIENT_VERSION", clientVersion)

	return &clientOptions{
		httpDoer:                 http.DefaultClient,
		httpDefaultHeaders:       defaultHeaders,
		serverTimezone:           time.UTC,
		tolerateInsecureProtocol: false,
	}
}

// ClientOptionServerTimezone sets the timezone of the CASSH server for time response to be received correctly.
func ClientOptionServerTimezone(serverTimezone *time.Location) ClientOption {
	return func(o *clientOptions) {
		o.serverTimezone = serverTimezone
	}
}

// ClientOptionHTTPClient sets the http client used on each request made to the CASSH server.
func ClientOptionHTTPClient(httpDoer httpclient.Doer) ClientOption {
	return func(o *clientOptions) {
		o.httpDoer = httpDoer
	}
}

// ClientOptionHTTPHeader sets some headers used by default on all http requests.
func ClientOptionHTTPHeader(httpDefaultHeaders http.Header) ClientOption {
	return func(o *clientOptions) {
		o.httpDefaultHeaders = httpDefaultHeaders
	}
}

// ClientOptionTolerateInsecureProtocols allows the CASSH server to be join using http instead of https.
func ClientOptionTolerateInsecureProtocols() ClientOption {
	return func(o *clientOptions) {
		o.tolerateInsecureProtocol = true
	}
}
