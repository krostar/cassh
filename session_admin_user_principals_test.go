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

func Test_SessionAdminUserPrincipals_Add(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPClient(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Principals()

		err = session.Add(context.Background(), "p1", "p2", "p3")
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser/principals").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"add":                {"p1", "p2", "p3"},
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
			check: func(err error) { assert.Check(t, err == nil) },
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

func Test_SessionAdminUserPrincipals_Remove(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPClient(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Principals()

		err = session.Remove(context.Background(), "p1", "p2", "p3")
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser/principals").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"remove":             {"p1", "p2", "p3"},
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
			check: func(err error) { assert.Check(t, err == nil) },
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

func Test_SessionAdminUserPrincipals_Reset(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPClient(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Principals()

		err = session.Reset(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser/principals").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"purge":              {"true"},
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
			check: func(err error) { assert.Check(t, err == nil) },
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

func Test_SessionAdminUserPrincipals_Set(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPClient(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionAdmin(SessionAdminOptionAuthenticationMechanismForTesting()).
			User("awesomeuser").
			Principals()

		err = session.Set(context.Background(), "p1", "p2", "p3")
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/admin/awesomeuser/principals").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"update":             {"p1", "p2", "p3"},
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
