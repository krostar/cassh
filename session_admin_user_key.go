package cassh

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/krostar/httpclient"
)

func (s *SessionAdminUser) Key() *SessionAdminUserKey {
	return &SessionAdminUserKey{
		api:                           s.api,
		username:                      s.username,
		parentCreateRequestParameters: s.createRequestParameters,
	}
}

type SessionAdminUserKey struct {
	api                           *httpclient.API
	username                      Username
	parentCreateRequestParameters func() url.Values
}

func (s *SessionAdminUserKey) createRequestParameters() url.Values {
	return s.parentCreateRequestParameters()
}

func (s *SessionAdminUserKey) Activate(ctx context.Context) error {
	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(s.createRequestParameters()))
}

func (s *SessionAdminUserKey) Revoke(ctx context.Context) error {
	requestParameters := s.createRequestParameters()
	requestParameters.Set("revoke", strconv.FormatBool(true))

	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(requestParameters))
}

func (s *SessionAdminUserKey) SetExpiry(ctx context.Context, expiry time.Duration) error {
	if expiry < time.Hour {
		return fmt.Errorf("invalid expiry %s, smallest is 1h", expiry.String())
	}

	requestParameters := s.createRequestParameters()
	requestParameters.Set("expiry", strconv.FormatUint(uint64(expiry.Hours()), 10)+"h")

	return s.api.
		Execute(ctx, s.api.
			Patch("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(requestParameters))
}

func (s *SessionAdminUserKey) Delete(ctx context.Context) error {
	return s.api.
		Execute(ctx, s.api.
			Delete("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(s.createRequestParameters()))
}
