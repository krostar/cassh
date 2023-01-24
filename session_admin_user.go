package cassh

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/krostar/httpclient"
)

// User sets the user on which further commands will be applied.
func (s *SessionAdmin) User(username Username) *SessionAdminUser {
	return &SessionAdminUser{
		api:                           s.api.Clone(),
		serverTimezone:                s.serverTimezone,
		parentCreateRequestParameters: s.createRequestParameters,

		username: username,
	}
}

// SessionAdminUser stores attributes useful to make admin requests related to a specific user, to the CASSH server.
type SessionAdminUser struct {
	api                           *httpclient.API
	serverTimezone                *time.Location
	parentCreateRequestParameters func() url.Values

	username Username
}

func (s *SessionAdminUser) createRequestParameters() url.Values {
	return s.parentCreateRequestParameters()
}

// Status returns the current user status.
func (s *SessionAdminUser) Status(ctx context.Context) (*UserStatus, error) {
	requestParameters := s.createRequestParameters()
	requestParameters.Set("status", strconv.FormatBool(true))

	var response apiUserStatusResponse

	if err := s.api.
		Do(ctx, s.api.
			Post("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(requestParameters)).
		ReceiveJSON(http.StatusOK, &response).
		Error(); err != nil {
		return nil, err
	}

	return dtoUserStatusResponse(response, s.serverTimezone)
}
