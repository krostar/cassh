package cassh

import (
	"testing"

	"gotest.tools/v3/assert"
)

func SessionUserOptionAuthenticationMechanismForTesting() SessionUserOption {
	return func(o *sessionUserOptions) { o.authMechanism = new(sessionAuthTesting) }
}

func Test_SessionUserOptionAuthenticationMechanismLDAP(t *testing.T) {
	opts := sessionUserOptionsDefaults()
	assert.Check(t, opts.authMechanism != nil)
	opts.authMechanism = nil
	SessionUserOptionAuthenticationMechanismLDAP("user", "pwd")(opts)
	assert.Check(t, opts.authMechanism != nil)
}
