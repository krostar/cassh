package cassh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stripe/krl"
	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"

	"github.com/krostar/httpclient"
	httpclienttest "github.com/krostar/httpclient/test"
	"github.com/krostar/sshx"
)

func Test_NewClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusOK)
			assert.Check(t, strings.HasPrefix(r.Header.Get("CLIENT_VERSION"), "krostar/cassh"))
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, ClientOptionHTTPDoer(srv.Client()))
		assert.NilError(t, err)
		assert.Check(t, client != nil)
		assert.NilError(t, client.Ping(context.Background()))
	})

	t.Run("ko", func(t *testing.T) {
		t.Run("invalid server url", func(t *testing.T) {
			client, err := NewClient(":\\")
			assert.ErrorContains(t, err, "unable to parse server address")
			assert.Check(t, client == nil)
		})

		t.Run("insecure protocol used", func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { rw.WriteHeader(http.StatusOK) }))
			defer srv.Close()

			client, err := NewClient(srv.URL, ClientOptionHTTPDoer(srv.Client()))
			assert.ErrorContains(t, err, "insecure protocol used")
			assert.Check(t, client == nil)
		})
	})
}

func Test_Client_Ping(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		err = client.Ping(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.NewRequestMatcherBuilder().Method(http.MethodGet).URLPath("/ping")

	for name, test := range map[string]struct {
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

func Test_Client_Health(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		name, version, err := client.Health(context.Background())
		(checkCallback.(func(string, string, error)))(name, version, err)

		return nil
	})

	reqMatcher := httpclienttest.NewRequestMatcherBuilder().Method(http.MethodGet).URLPath("/health")

	for name, test := range map[string]struct {
		matcher httpclienttest.RequestMatcher
		writer  func(http.ResponseWriter) error
		check   func(name, version string, err error)
	}{
		"ok": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write([]byte(`{"name": "hello", "version": "v1.0"}`))
				return err
			},
			check: func(name, version string, err error) {
				assert.Check(t, cmp.Equal(name, "hello"))
				assert.Check(t, cmp.Equal(version, "v1.0"))
				assert.NilError(t, err)
			},
		},
		"ko - unsuficient privileges": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusUnauthorized)
				return nil
			},
			check: func(_, _ string, err error) { assert.Check(t, cmp.ErrorIs(err, ErrInsufficientPrivileges)) },
		},
		"ko - unhandled status": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			check: func(_, _ string, err error) {
				assert.Check(t, cmp.ErrorContains(err, "failed with status 500: unhandled request status"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) { assert.Check(t, srv.AssertRequest(test.matcher, test.writer, test.check)) })
	}
}

func Test_Client_KeyRevocationList(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		l, err := client.KeyRevocationList(context.Background())
		(checkCallback.(func(*krl.KRL, error)))(l, err)

		return nil
	})

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey, err := sshx.WrapPrivateKey(rsaPrivKey)
	assert.NilError(t, err)

	reqMatcher := httpclienttest.NewRequestMatcherBuilder().Method(http.MethodGet).URLPath("/krl")

	for name, test := range map[string]struct {
		matcher httpclienttest.RequestMatcher
		writer  func(http.ResponseWriter) error
		check   func(l *krl.KRL, err error)
	}{
		"ok": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				body, err := new(krl.KRL).Marshal(rand.Reader, privKey.Signer())
				if err != nil {
					return err
				}
				_, err = rw.Write(body)
				return err
			},
			check: func(l *krl.KRL, err error) {
				assert.Check(t, l != nil)
				assert.NilError(t, err)
			},
		},
		"ko - unparsable body": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write([]byte("abc"))
				return err
			}, check: func(_ *krl.KRL, err error) { assert.ErrorContains(t, err, "unable to parse body as krl") },
		},
		"ko - unsuficient privileges": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusUnauthorized)
				return nil
			},
			check: func(_ *krl.KRL, err error) { assert.Check(t, cmp.ErrorIs(err, ErrInsufficientPrivileges)) },
		},
		"ko - unhandled status": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			check: func(_ *krl.KRL, err error) {
				assert.Check(t, cmp.ErrorContains(err, "failed with status 500: unhandled request status"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) { assert.Check(t, srv.AssertRequest(test.matcher, test.writer, test.check)) })
	}
}

func Test_Client_AuthorityPublicKey(t *testing.T) {
	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		sshPublicKey, err := client.AuthorityPublicKey(context.Background())
		(checkCallback.(func(sshx.PublicKey, error)))(sshPublicKey, err)

		return nil
	})

	reqMatcher := httpclienttest.NewRequestMatcherBuilder().Method(http.MethodGet).URLPath("/ca")

	var (
		providedAuthorizedKey []byte
		expectedSSHPublicKey  sshx.PublicKey
	)
	{
		rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NilError(t, err)
		sshPubKey, err := ssh.NewPublicKey(rsaPrivKey.Public())
		assert.NilError(t, err)

		expectedSSHPublicKey = sshx.WrapSSHPublicKey(sshPubKey)
		providedAuthorizedKey = ssh.MarshalAuthorizedKey(expectedSSHPublicKey)
	}

	for name, test := range map[string]struct {
		matcher httpclienttest.RequestMatcher
		writer  func(http.ResponseWriter) error
		check   func(publicKey sshx.PublicKey, err error)
	}{
		"ok": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write(providedAuthorizedKey)
				return err
			},
			check: func(publicKey sshx.PublicKey, err error) {
				assert.NilError(t, expectedSSHPublicKey.Equal(publicKey))
				assert.NilError(t, err)
			},
		},
		"ko - unparsable body": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write([]byte("abc"))
				return err
			},
			check: func(_ sshx.PublicKey, err error) { assert.ErrorContains(t, err, "unable to parse body as ssh key") },
		},
		"ko - unsuficient privileges": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusUnauthorized)
				return nil
			},
			check: func(_ sshx.PublicKey, err error) { assert.Check(t, cmp.ErrorIs(err, ErrInsufficientPrivileges)) },
		},
		"ko - unhandled status": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			check: func(_ sshx.PublicKey, err error) {
				assert.Check(t, cmp.ErrorContains(err, "failed with status 500: unhandled request status"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) { assert.Check(t, srv.AssertRequest(test.matcher, test.writer, test.check)) })
	}
}
