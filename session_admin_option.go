package cassh

// SessionAdminOption defines the signature of all options usable on SessionAdmin.
type SessionAdminOption func(o *sessionAdminOptions)

func sessionAdminOptionsDefaults() *sessionAdminOptions {
	return &sessionAdminOptions{
		authMechanism: new(sessionAuthNoop),
	}
}

type sessionAdminOptions struct {
	authMechanism SessionAuth
}

// SessionAdminOptionAuthenticationMechanismLDAP sets the authentication mechanism to LDAP for the entire session.
func SessionAdminOptionAuthenticationMechanismLDAP(ldapName, ldapPassword string) SessionAdminOption {
	return func(o *sessionAdminOptions) {
		o.authMechanism = &sessionAuthLDAP{
			name:     ldapName,
			password: ldapPassword,
		}
	}
}
