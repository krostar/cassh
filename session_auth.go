package cassh

import (
	"net/url"
)

// SessionAuth defines a way to authenticate a request.
type SessionAuth interface {
	ExtendRequestParameters(url.Values)
}

type sessionAuthNoop struct{}

func (sessionAuthNoop) ExtendRequestParameters(url.Values) {}

type sessionAuthLDAP struct {
	name     string
	password string
}

func (auth sessionAuthLDAP) ExtendRequestParameters(values url.Values) {
	values.Set("realname", auth.name)
	values.Set("password", auth.password)
}
