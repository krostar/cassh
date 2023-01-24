package cassh

import (
	"net/url"
)

type SessionAuth interface {
	ExtendRequestParameters(url.Values)
}
