package cassh

import (
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

func Test_dtoUserStatusResponse(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)

	t.Run("ok", func(t *testing.T) {
		userStatus, err := dtoUserStatusResponse(apiUserStatusResponse{
			Expiration: now.Add(time.Hour).Format("2006-01-02 15:04:05"),
			Expiry:     "+6h",
			Principals: []string{"foo", "bar", "foobar"},
			RealName:   "foo.bar@foo.b-ar",
			SSHKeyHash: apiUserStatusResponseSSHKeyHash{
				AuthType: "RSA",
				Bits:     8192,
				Hash:     "SHA512:3423jhb",
				Rate:     "HIGH",
			},
			Status:   "ACTIVE",
			Username: "foobar",
		}, time.UTC)
		assert.NilError(t, err)

		assert.DeepEqual(t, userStatus, &UserStatus{
			Name:          "foobar",
			RealName:      "foo.bar@foo.b-ar",
			KeyState:      KeyStateActive,
			KeyExpiration: now.Add(time.Hour),
			KeyPrincipals: Principals{"foo", "bar", "foobar"},
		})
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("unable to parse expiration date", func(t *testing.T) {
			_, err := dtoUserStatusResponse(apiUserStatusResponse{
				Expiration: now.Add(time.Hour).Format(time.RFC822),
			}, time.UTC)
			assert.ErrorContains(t, err, "unable to parse expiration time")
		})
	})
}
