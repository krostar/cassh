package cassh

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

func Test_clientOptionsDefaults(t *testing.T) {
	opts := clientOptionsDefaults()
	assert.Check(t, strings.HasPrefix(opts.httpDefaultHeaders.Get("User-Agent"), "CASSH-CLIENT krostar/cassh"))
	assert.Check(t, strings.HasPrefix(opts.httpDefaultHeaders.Get("CLIENT_VERSION"), "krostar/cassh"))
	assert.Check(t, opts.httpDoer != nil)
	assert.Check(t, opts.serverTimezone != nil)
}

func Test_ClientOptionServerTimezone(t *testing.T) {
	opts := clientOptionsDefaults()
	assert.Check(t, opts.serverTimezone != nil)
	opts.serverTimezone = nil
	ClientOptionServerTimezone(time.UTC)(opts)
	assert.Check(t, opts.serverTimezone != nil)
}

func Test_ClientOptionHTTPDoer(t *testing.T) {
	opts := clientOptionsDefaults()
	assert.Check(t, opts.httpDoer != nil)
	opts.httpDoer = nil
	ClientOptionHTTPDoer(http.DefaultClient)(opts)
	assert.Check(t, opts.httpDoer != nil)
}

func Test_ClientOptionHTTPHeader(t *testing.T) {
	opts := clientOptionsDefaults()
	assert.Check(t, opts.httpDefaultHeaders != nil)
	opts.httpDefaultHeaders = nil
	ClientOptionHTTPHeader(http.Header{"Hello": []string{"world"}})(opts)
	assert.Check(t, opts.httpDefaultHeaders != nil)
}

func Test_ClientOptionTolerateInsecureProtocols(t *testing.T) {
	opts := clientOptionsDefaults()
	assert.Check(t, !opts.tolerateInsecureProtocol)
	ClientOptionTolerateInsecureProtocols()(opts)
	assert.Check(t, opts.tolerateInsecureProtocol)
}
