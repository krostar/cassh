package cassh

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/krostar/httpclient"
)

// Key allows the manipulation of the user key as admin.
func (s *SessionAdminUser) Key() *SessionAdminUserKey {
	return &SessionAdminUserKey{
		api:                           s.api.Clone(),
		username:                      s.username,
		parentCreateRequestParameters: s.createRequestParameters,
	}
}

// SessionAdminUserKey stores attributes useful to make admin requests related to keys for a specific user, to the CASSH server.
type SessionAdminUserKey struct {
	api                           *httpclient.API
	username                      Username
	parentCreateRequestParameters func() url.Values
}

func (s *SessionAdminUserKey) createRequestParameters() url.Values {
	return s.parentCreateRequestParameters()
}

// Activate activates the user's key.
func (s *SessionAdminUserKey) Activate(ctx context.Context) error {
	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(s.createRequestParameters()))
}

// Revoke revokes the user's key.
func (s *SessionAdminUserKey) Revoke(ctx context.Context) error {
	requestParameters := s.createRequestParameters()
	requestParameters.Set("revoke", strconv.FormatBool(true))

	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(requestParameters))
}

// SetExpiry sets the provided expiry for the user's key.
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

// Delete deletes the user's key (but it does not revoke it).
func (s *SessionAdminUserKey) Delete(ctx context.Context) error {
	return s.api.
		Execute(ctx, s.api.
			Delete("/admin/{username}").
			PathReplacer("{username}", s.username.String()).
			SendForm(s.createRequestParameters()))
}
