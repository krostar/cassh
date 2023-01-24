package cassh

import (
	"context"
	"net/url"
	"time"

	"github.com/krostar/httpclient"
)

// SessionAdmin exposes all admin related methods.
func (c *Client) SessionAdmin(opts ...SessionAdminOption) *SessionAdmin {
	o := sessionAdminOptionsDefaults()
	for _, opt := range opts {
		opt(o)
	}
	return &SessionAdmin{
		api:            c.api.Clone(),
		serverTimezone: c.serverTimezone,
		authMechanism:  o.authMechanism,
	}
}

// SessionAdmin stores attributes useful to make admin related requests to the CASSH server.
type SessionAdmin struct {
	api            *httpclient.API
	serverTimezone *time.Location
	authMechanism  SessionAuth
}

func (s *SessionAdmin) createRequestParameters() url.Values {
	parameters := make(url.Values)
	s.authMechanism.ExtendRequestParameters(parameters)
	return parameters
}

// CheckAuthentication checks whenever the provided admin authentication mechanism is valid and authorized.
func (s *SessionAdmin) CheckAuthentication(ctx context.Context) error {
	return s.api.Execute(ctx, s.api.Post("/test_auth").SendForm(s.createRequestParameters()))
}
