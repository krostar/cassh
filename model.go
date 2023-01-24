package cassh

import (
	"fmt"
	"time"
)

type Username string

func (u Username) String() string { return string(u) }

type UserStatus struct {
	Name          Username
	RealName      string
	KeyState      KeyState
	KeyExpiration time.Time
	KeyPrincipals Principals
}

func (us UserStatus) String() string {
	return fmt.Sprintf("[%s] %s (%s)", us.KeyState.String(), us.Name.String(), us.RealName)
}

type KeyState string

const (
	KeyStateActive  KeyState = "ACTIVE"
	KeyStateRevoked KeyState = "REVOKED"
	KeyStatePending KeyState = "PENDING"
)

func (ks KeyState) String() string { return string(ks) }

type Principals []Principal

func (principals Principals) Has(requiredPrincipal Principal, requiredPrincipals ...Principal) error {
	requiredPrincipals = append([]Principal{requiredPrincipal}, requiredPrincipals...)

	for _, requiredPrincipal := range requiredPrincipals {
		var found bool

		for _, principal := range principals {
			if principal == requiredPrincipal {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("%s not found in list of principals", requiredPrincipal)
		}
	}

	return nil
}

type Principal string

func (principal Principal) String() string { return string(principal) }

type sentinelError string

func (err sentinelError) Error() string { return string(err) }

const ErrInsufficientPrivileges = sentinelError("insufficient privileges")
