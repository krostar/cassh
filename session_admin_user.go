package cassh

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/krostar/httpclient"
)

func (s *SessionAdmin) User(username Username) *SessionAdminUser {
	return &SessionAdminUser{
		api:                           s.api,
		serverTimezone:                s.serverTimezone,
		parentCreateRequestParameters: s.createRequestParameters,

		username: username,
	}
}

type SessionAdminUser struct {
	api                           *httpclient.API
	serverTimezone                *time.Location
	parentCreateRequestParameters func() url.Values

	username Username
}

func (s *SessionAdminUser) createRequestParameters() url.Values {
	return s.parentCreateRequestParameters()
}

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
