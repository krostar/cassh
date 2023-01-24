package cassh

import (
	"testing"

	"gotest.tools/v3/assert"
)

func SessionAdminOptionAuthenticationMechanismForTesting() SessionAdminOption {
	return func(o *sessionAdminOptions) { o.authMechanism = new(sessionAuthTesting) }
}

func Test_SessionAdminOptionAuthenticationMechanismLDAP(t *testing.T) {
	opts := sessionAdminOptionsDefaults()
	assert.Check(t, opts.authMechanism != nil)
	opts.authMechanism = nil
	SessionAdminOptionAuthenticationMechanismLDAP("user", "pwd")(opts)
	assert.Check(t, opts.authMechanism != nil)
}
