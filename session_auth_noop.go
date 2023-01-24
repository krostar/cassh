package cassh

import (
	"net/url"
)

type sessionAuthNoop struct{}

func (sessionAuthNoop) ExtendRequestParameters(url.Values) {}
