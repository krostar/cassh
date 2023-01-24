package cassh

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_SessionUserKeySignOptionForce(t *testing.T) {
	opts := sessionUserKeySignOptionsDefault()
	assert.Check(t, !opts.force)
	SessionUserKeySignOptionForce()(opts)
	assert.Check(t, opts.force)
}
