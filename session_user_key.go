package cassh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/krostar/httpclient"
)

// Key allows the manipulation of the user key.
func (s *SessionUser) Key(key ssh.PublicKey) *SessionUserKey {
	return &SessionUserKey{
		api:                           s.api.Clone(),
		key:                           key,
		parentCreateRequestParameters: s.createRequestParameters,
	}
}

// SessionUserKey stores attributes useful to make requests related to user's keys, to the CASSH server.
type SessionUserKey struct {
	api *httpclient.API
	key ssh.PublicKey

	parentCreateRequestParameters func() url.Values
}

func (s *SessionUserKey) createRequestParameters() url.Values {
	requestParameters := s.parentCreateRequestParameters()
	requestParameters.Set("pubkey", string(ssh.MarshalAuthorizedKey(s.key)))
	return requestParameters
}

// Set sets the user key.
func (s *SessionUserKey) Set(ctx context.Context) error {
	return s.api.Execute(ctx, s.api.Put("/client").SendForm(s.createRequestParameters()))
}

// Sign returns a certificate signed by the CASSH server.
func (s *SessionUserKey) Sign(ctx context.Context, opts ...SessionUserKeySignOption) (*ssh.Certificate, error) {
	o := sessionUserKeySignOptionsDefault()
	for _, opt := range opts {
		opt(o)
	}

	requestParameters := s.createRequestParameters()

	if o.force {
		requestParameters.Set("admin_force", strconv.FormatBool(true))
	}

	var certificate ssh.Certificate

	if err := s.api.
		Do(ctx, s.api.Post("/client").SendForm(requestParameters)).
		OnStatus(http.StatusOK, s.signParseSuccessResponse(&certificate)).
		Error(); err != nil {
		return nil, err
	}

	return &certificate, nil
}

func (*SessionUserKey) signParseSuccessResponse(certificate *ssh.Certificate) httpclient.ResponseHandler {
	return func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("unable to read body: %v", err)
		}

		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(body)
		if err != nil {
			return fmt.Errorf("unable to parse ssh certificate from raw openssh certificate: %v", err)
		}

		if responseCertificate, ok := publicKey.(*ssh.Certificate); ok {
			*certificate = *responseCertificate
			return nil
		}

		return errors.New("authorized key is not a certificate")
	}
}
