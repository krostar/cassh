package cassh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"net/http"
	"net/url"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"

	"github.com/krostar/httpclient"
	httpclienttest "github.com/krostar/httpclient/test"
	"github.com/krostar/sshx"
)

func Test_SessionUserKey_Set(t *testing.T) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey, err := sshx.WrapPrivateKey(rsaPrivKey)
	assert.NilError(t, err)

	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionUser("awesomeuser", SessionUserOptionAuthenticationMechanismForTesting()).
			Key(privKey.PublicKey())

		err = session.Set(context.Background())
		(checkCallback.(func(error)))(err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPut).
		URLPath("/client").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"username":           {"awesomeuser"},
			"pubkey":             {string(ssh.MarshalAuthorizedKey(privKey.PublicKey()))},
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

func Test_SessionUserKey_Sign(t *testing.T) {
	createCert := func(t *testing.T, privKey sshx.PrivateKey, signer ssh.Signer, setups ...func(cert *ssh.Certificate)) *ssh.Certificate {
		cert := &ssh.Certificate{
			Nonce:           []byte{}, // To pass reflect.DeepEqual after marshal & parse, this must be non-nil.
			Key:             privKey.PublicKey(),
			CertType:        ssh.HostCert,
			ValidPrincipals: []string{"foo", "bar"},
			Permissions: ssh.Permissions{ // To pass reflect.DeepEqual after marshal & parse, this must be non-nil.
				CriticalOptions: make(map[string]string),
				Extensions:      make(map[string]string),
			},
			Reserved:     []byte{}, // To pass reflect.DeepEqual after marshal & parse, this must be non-nil.
			SignatureKey: privKey.PublicKey(),
		}
		for _, setup := range setups {
			setup(cert)
		}
		assert.NilError(t, cert.SignCert(rand.Reader, signer))
		return cert
	}

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	privKey, err := sshx.WrapPrivateKey(rsaPrivKey)
	assert.NilError(t, err)
	caCert := createCert(t, privKey, privKey.Signer())

	srv := httpclienttest.NewServer(func(u url.URL, httpDoer httpclient.Doer, checkCallback any) error {
		client, err := NewClient(u.String(), ClientOptionHTTPDoer(httpDoer), ClientOptionTolerateInsecureProtocols())
		if err != nil {
			return err
		}

		session := client.
			SessionUser("awesomeuser", SessionUserOptionAuthenticationMechanismForTesting()).
			Key(privKey.PublicKey())

		certificate, err := session.Sign(context.Background(), SessionUserKeySignOptionForce())
		(checkCallback.(func(*ssh.Certificate, error)))(certificate, err)

		return nil
	})

	reqMatcher := httpclienttest.
		NewRequestMatcherBuilder().
		Method(http.MethodPost).
		URLPath("/client").
		BodyForm(url.Values{
			"testAuthPropagated": {"true"},
			"username":           {"awesomeuser"},
			"pubkey":             {string(ssh.MarshalAuthorizedKey(privKey.PublicKey()))},
			"admin_force":        {"true"},
		}, true)

	for name, test := range map[string]struct {
		form    url.Values
		matcher httpclienttest.RequestMatcher
		writer  func(http.ResponseWriter) error
		check   func(cert *ssh.Certificate, err error)
	}{
		"ok": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write(ssh.MarshalAuthorizedKey(caCert))
				return err
			},
			check: func(cert *ssh.Certificate, err error) {
				assert.Check(t, err == nil)
				assert.Check(t, sshx.WrapSSHPublicKey(cert.Key).Equal(sshx.WrapSSHPublicKey(caCert.Key)))
				assert.Check(t, cmp.DeepEqual(cert, caCert,
					gocmp.AllowUnexported(big.Int{}),
					gocmp.FilterPath(func(path gocmp.Path) bool { return path.String() == "Key" }, gocmp.Ignore()),
				))
			},
		},
		"ko - unable to parse authorized key": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write([]byte("hello"))
				return err
			},
			check: func(cert *ssh.Certificate, err error) {
				assert.Check(t, cmp.ErrorContains(err, "unable to parse ssh certificate"))
			},
		},
		"ko - authorized key is not a certificate": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusOK)
				_, err := rw.Write(ssh.MarshalAuthorizedKey(privKey.PublicKey()))
				return err
			},
			check: func(cert *ssh.Certificate, err error) {
				assert.Check(t, cmp.ErrorContains(err, "authorized key is not a certificate"))
			},
		},
		"ko - unsuficient privileges": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusUnauthorized)
				return nil
			},
			check: func(cert *ssh.Certificate, err error) { assert.Check(t, cmp.ErrorIs(err, ErrInsufficientPrivileges)) },
		},
		"ko - unhandled status": {
			matcher: reqMatcher,
			writer: func(rw http.ResponseWriter) error {
				rw.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			check: func(cert *ssh.Certificate, err error) {
				assert.Check(t, cmp.ErrorContains(err, "failed with status 500: unhandled request status"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) { assert.Check(t, srv.AssertRequest(test.matcher, test.writer, test.check)) })
	}
}
