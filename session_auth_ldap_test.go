package cassh

import (
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

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
