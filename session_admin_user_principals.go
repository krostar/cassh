package cassh

import (
	"context"
	"net/url"
	"strconv"

	"github.com/krostar/httpclient"
)

func (s *SessionAdminUser) Principals() *SessionAdminUserPrincipals {
	return &SessionAdminUserPrincipals{
		api:                           s.api,
		username:                      s.username,
		parentCreateRequestParameters: s.createRequestParameters,
	}
}

type SessionAdminUserPrincipals struct {
	api                           *httpclient.API
	username                      Username
	parentCreateRequestParameters func() url.Values
}

func (s *SessionAdminUserPrincipals) createRequestParameters() url.Values {
	return s.parentCreateRequestParameters()
}

func (s *SessionAdminUserPrincipals) Add(ctx context.Context, principal Principal, principals ...Principal) error {
	principals = append([]Principal{principal}, principals...)

	request := s.createRequestParameters()
	for _, principal := range principals {
		request.Add("add", principal.String())
	}

	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}/principals").
			PathReplacer("{username}", s.username.String()).
			SendForm(request))
}

func (s *SessionAdminUserPrincipals) Remove(ctx context.Context, principal Principal, principals ...Principal) error {
	principals = append([]Principal{principal}, principals...)

	request := s.createRequestParameters()
	for _, principal := range principals {
		request.Add("remove", principal.String())
	}

	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}/principals").
			PathReplacer("{username}", s.username.String()).
			SendForm(request))
}

func (s *SessionAdminUserPrincipals) Set(ctx context.Context, principal Principal, principals ...Principal) error {
	principals = append([]Principal{principal}, principals...)

	request := s.createRequestParameters()
	for _, principal := range principals {
		request.Add("update", principal.String())
	}

	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}/principals").
			PathReplacer("{username}", s.username.String()).
			SendForm(request))
}

func (s *SessionAdminUserPrincipals) Reset(ctx context.Context) error {
	request := s.createRequestParameters()
	request.Set("purge", strconv.FormatBool(true))

	return s.api.
		Execute(ctx, s.api.
			Post("/admin/{username}/principals").
			PathReplacer("{username}", s.username.String()).
			SendForm(request))
}
