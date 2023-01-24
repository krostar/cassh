package cassh

import (
	"fmt"
	"time"
)

// Username of the CASSH user.
type Username string

// String implements stringer for Username.
func (u Username) String() string { return string(u) }

// UserStatus stores the status attributes of a CASSH user.
type UserStatus struct {
	Name          Username
	RealName      string
	KeyState      KeyState
	KeyExpiration time.Time
	KeyPrincipals Principals
}

// String implements stringer for UserStatus.
func (us UserStatus) String() string {
	return fmt.Sprintf("[%s] %s (%s)", us.KeyState.String(), us.Name.String(), us.RealName)
}

// KeyState defines the different states a user key can be in.
type KeyState string

const (
	// KeyStateActive means the key is usable on the CASSH server.
	KeyStateActive KeyState = "ACTIVE"
	// KeyStateRevoked means the key has been revoked by the CASSH server and cannot be used anymore.
	KeyStateRevoked KeyState = "REVOKED"
	// KeyStatePending means the key has not been signed yet by a CASSH server admin and cannot be used yet.
	KeyStatePending KeyState = "PENDING"
)

// String implements stringer for KeyState.
func (ks KeyState) String() string { return string(ks) }

// Principals aliases []Principal to add useful methods.
type Principals []Principal

// Has returns whenever provided principals exists all in the list of principals.
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

// Principal stores a single principal.
type Principal string

// String implements stringer for Principal.
func (principal Principal) String() string { return string(principal) }

type sentinelError string

func (err sentinelError) Error() string { return string(err) }

// ErrInsufficientPrivileges is returned when the privileges provided to the CASSH server are not sufficient to execute the request successfully.
const ErrInsufficientPrivileges = sentinelError("insufficient privileges")
