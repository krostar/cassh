package cassh

import (
	"net/url"
	"strconv"
)

type sessionAuthTesting struct{}

func (sessionAuthTesting) ExtendRequestParameters(values url.Values) {
	values.Set("testAuthPropagated", strconv.FormatBool(true))
}
