package cassh

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_Username_String(t *testing.T) {
	assert.Equal(t, Username("foo").String(), "foo")
}

func Test_UserStatus_String(t *testing.T) {
	assert.Equal(t, (UserStatus{
		Name:     "1",
		RealName: "2",
		KeyState: "3",
	}).String(), "[3] 1 (2)")
}

func Test_KeyState_String(t *testing.T) {
	assert.Equal(t, KeyState("foo").String(), "foo")
}

func Test_Principals_Has(t *testing.T) {
	principals := Principals{"a", "b", "c"}
	assert.NilError(t, principals.Has("a", "b", "c"))
	assert.NilError(t, principals.Has("a", "c"))
	assert.ErrorContains(t, principals.Has("c", "d"), "d not found in list of principals")
	assert.ErrorContains(t, principals.Has("d"), "d not found in list of principals")
}

func Test_Principal_String(t *testing.T) {
	assert.Equal(t, Principal("foo").String(), "foo")
}

func Test_sentinelError_Error(t *testing.T) {
	assert.Equal(t, sentinelError("foo").Error(), "foo")
}
