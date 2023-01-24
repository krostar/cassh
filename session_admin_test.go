package cassh

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"

	"github.com/krostar/httpclient"
	httpclienttest "github.com/krostar/httpclient/test"
)

func Test_SessionAdmin_CheckAuthentication(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting())
		err = session.CheckAuthentication(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/test_auth").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
		}, true)

	for name, test := range map[string]struct {
		form    url.Values
		matcher httpclienttest.RequestMatcher
		writer  func(http.ResponseWriter) error
		check   func(err error)
	}{
		"ok": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				return nil
			},
			check: func(err error) { assert.NilError(t, err) },
		},
		"ko - unsuficient privileges": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusUnauthorized)
				return nil
			},
			check: func(err error) { assert.Check(t, cmp.ErrorIs(err, ErrInsufficientPrivileges)) },
		},
		"ko - unhandled status": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			check: func(err error) {
				assert.Check(t, cmp.ErrorContains(err, "failed with status 500: unhandled request status"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) { assert.Check(t, srv.AssertRequest(test.matcher, test.writer, test.check)) })
	}
}
