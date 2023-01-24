package cassh

import (
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func Test_sessionAuthNoop_ExtendRequestParameters(t *testing.T) {
	values := make(url.Values)

	auth := new(sessionAuthNoop)
	auth.ExtendRequestParameters(values)

	assert.Check(t, cmp.Len(values, 0))
}
