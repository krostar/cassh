package cassh

type SessionAdminOption func(o *sessionAdminOptions)

func sessionAdminOptionsDefaults() *sessionAdminOptions {
	return &sessionAdminOptions{
		authMechanism: new(sessionAuthNoop),
	}
}

type sessionAdminOptions struct {
	authMechanism SessionAuth
}

func SessionAdminOptionAuthenticationMechanismLDAP(ldapName, ldapPassword string) SessionAdminOption {
	return func(o *sessionAdminOptions) {
		o.authMechanism = &sessionAuthLDAP{
			name:     ldapName,
			password: ldapPassword,
		}
	}
}
