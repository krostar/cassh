package cassh

import (
	"net/url"
	"strconv"
	"testing"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

type sessionAuthTesting struct{}

func (sessionAuthTesting) ExtendRequestParameters(values url.Values) {
	values.Set("testAuthPropagated", strconv.FormatBool(true))
}

func Test_sessionAuthNoop_ExtendRequestParameters(t *testing.T) {
	values := make(url.Values)

	auth := new(sessionAuthNoop)
	auth.ExtendRequestParameters(values)

	assert.Check(t, cmp.Len(values, 0))
}

func Test_sessionAuthLDAP_ExtendRequestParameters(t *testing.T) {
	values := make(url.Values)

	auth := &sessionAuthLDAP{
		name:     "ldapName",
		password: "ldapPwd",
	}
	auth.ExtendRequestParameters(values)

	assert.Check(t, cmp.DeepEqual(values, url.Values{
		"password": {"ldapPwd"},
		"realname": {"ldapName"},
	}))
}
