package cassh

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/krostar/httpclient"
)

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

func ClientOptionServerTimezone(serverTimezone *time.Location) ClientOption {
	return func(o *clientOptions) {
		o.serverTimezone = serverTimezone
	}
}

func ClientOptionHTTPDoer(httpDoer httpclient.Doer) ClientOption {
	return func(o *clientOptions) {
		o.httpDoer = httpDoer
	}
}

func ClientOptionHTTPHeader(httpDefaultHeaders http.Header) ClientOption {
	return func(o *clientOptions) {
		o.httpDefaultHeaders = httpDefaultHeaders
	}
}

func ClientOptionTolerateInsecureProtocols() ClientOption {
	return func(o *clientOptions) {
		o.tolerateInsecureProtocol = true
	}
}
