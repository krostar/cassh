package cassh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"

	"github.com/krostar/httpclient"
	httpclienttest "github.com/krostar/httpclient/test"
)

func Test_SessionAdminUser_Status(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPClient(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser")

		status, err := session.Status(context.Background())
		(checkCallback.(func(*UserStatus, error)))(status, err)

		return nil
	})

	now := time.Now().UTC().Round(time.Second)
	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"status":             {"true"},
		}, true)

	for name, test := range map[string]struct {
		form    url.Values
		matcher httpclienttest.RequestMatcher
		writer  func(http.ResponseWriter) error
		check   func(status *UserStatus, err error)
	}{
		"ok": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				return json.NewEncoder(rw).Encode(apiUserStatusResponse{
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
				})
			},
			check: func(status *UserStatus, err error) {
				assert.NilError(t, err)
				assert.DeepEqual(t, status, &UserStatus{
					Name:          "foobar",
					RealName:      "foo.bar@foo.b-ar",
					KeyState:      KeyStateActive,
					KeyExpiration: now.Add(time.Hour),
					KeyPrincipals: Principals{"foo", "bar", "foobar"},
				})
			},
		},
		"ko - unsuficient privileges": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusUnauthorized)
				return nil
			},
			check: func(_ *UserStatus, err error) { assert.Check(t, cmp.ErrorIs(err, ErrInsufficientPrivileges)) },
		},
		"ko - unhandled status": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			check: func(_ *UserStatus, err error) {
				assert.Check(t, cmp.ErrorContains(err, "failed with status 500: unhandled request status"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) { assert.Check(t, srv.AssertRequest(test.matcher, test.writer, test.check)) })
	}
}
