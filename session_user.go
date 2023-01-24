package cassh

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/krostar/httpclient"
)

func (c *Client) SessionUser(username Username, opts ...SessionUserOption) *SessionUser {
	o := sessionUserOptionsDefaults()
	for _, opt := range opts {
		opt(o)
	}
	return &SessionUser{
		api:            c.api,
		serverTimezone: c.serverTimezone,
		username:       username,
		authMechanism:  o.authMechanism,
	}
}

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
