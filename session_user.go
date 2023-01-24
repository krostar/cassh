package cassh

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/krostar/httpclient"
)

// SessionUser exposes all user related methods.
func (c *Client) SessionUser(username Username, opts ...SessionUserOption) *SessionUser {
	o := sessionUserOptionsDefaults()
	for _, opt := range opts {
		opt(o)
	}
	return &SessionUser{
		api:            c.api.Clone(),
		serverTimezone: c.serverTimezone,
		username:       username,
		authMechanism:  o.authMechanism,
	}
}

// SessionUser stores attributes useful to make user related requests to the CASSH server.
type SessionUser struct {
	api            *httpclient.API
	serverTimezone *time.Location
	authMechanism  SessionAuth

	username Username
}

func (s *SessionUser) createRequestParameters() url.Values {
	parameters := make(url.Values)
	parameters.Set("username", s.username.String())

	s.authMechanism.ExtendRequestParameters(parameters)

	return parameters
}

// Status returns the current user status.
func (s *SessionUser) Status(ctx context.Context) (*UserStatus, error) {
	var response apiUserStatusResponse

	if err := s.api.
		Do(ctx, s.api.Post("/client/status").SendForm(s.createRequestParameters())).
		ReceiveJSON(http.StatusOK, &response).
		Error(); err != nil {
		return nil, err
	}

	return dtoUserStatusResponse(response, s.serverTimezone)
}
