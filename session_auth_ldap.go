package cassh

import (
	"net/url"
)

type sessionAuthLDAP struct {
	name     string
	password string
}

func (auth sessionAuthLDAP) ExtendRequestParameters(values url.Values) {
	values.Set("realname", auth.name)
	values.Set("password", auth.password)
}
