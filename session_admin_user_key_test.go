package cassh

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"

	"github.com/krostar/httpclient"
	httpclienttest "github.com/krostar/httpclient/test"
)

func Test_SessionAdminUserKey_Activate(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Key()

		err = session.Activate(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser").
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

func Test_SessionAdminUserKey_Revoke(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Key()

		err = session.Revoke(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"revoke":             {"true"},
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

func Test_SessionAdminUserKey_SetExpiry(t *testing.T) {
	t.Run("valid expiry", func(t *testing.T) {
		srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
			client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
			assert.NilError(t, err)

			session := client.
				SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
				User("awesomeuser").
				Key()

			err = session.SetExpiry(context.Background(), time.Hour*49)
			(checkCallback.(func(error)))(err)

			return nil
		})

		reqMatcher := httpclienttest.
			NewRequestMatcherBuilder().
			Method(http.MethodPatch).
			URLPath("/admin/awesomeuser").
			BodyForm(url.Values{
				"testAuthPropagated": {"true"},
				"expiry":             {"49h"},
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
	})

	t.Run("invalid expiry", func(t *testing.T) {
		client, err := NewClient("https://foo")
		assert.NilError(t, err)

		session := client.SessionAdmin().User("awesomeuser").Key()

		assert.ErrorContains(t, session.SetExpiry(context.Background(), 0), "invalid expiry")
		assert.ErrorContains(t, session.SetExpiry(context.Background(), -1), "invalid expiry")
		assert.ErrorContains(t, session.SetExpiry(context.Background(), time.Hour-1), "invalid expiry")
	})
}

func Test_SessionAdminUserKey_Delete(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Key()

		err = session.Delete(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodDelete).
		URLPath("/admin/awesomeuser").
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
