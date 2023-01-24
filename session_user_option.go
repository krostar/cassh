package cassh

// SessionUserOption defines the signature of all options usable on SessionUser.
type SessionUserOption func(o *sessionUserOptions)

func sessionUserOptionsDefaults() *sessionUserOptions {
	return &sessionUserOptions{
		authMechanism: new(sessionAuthNoop),
	}
}

type sessionUserOptions struct {
	authMechanism SessionAuth
}

// SessionUserOptionAuthenticationMechanismLDAP sets the authentication mechanism to LDAP for the entire session.
func SessionUserOptionAuthenticationMechanismLDAP(ldapName, ldapPassword string) SessionUserOption {
	return func(o *sessionUserOptions) {
		o.authMechanism = &sessionAuthLDAP{
			name:     ldapName,
			password: ldapPassword,
		}
	}
}
