package cassh

type SessionUserOption func(o *sessionUserOptions)

func sessionUserOptionsDefaults() *sessionUserOptions {
	return &sessionUserOptions{
		authMechanism: new(sessionAuthNoop),
	}
}

type sessionUserOptions struct {
	authMechanism SessionAuth
}

func SessionUserOptionAuthenticationMechanismLDAP(ldapName, ldapPassword string) SessionUserOption {
	return func(o *sessionUserOptions) {
		o.authMechanism = &sessionAuthLDAP{
			name:     ldapName,
			password: ldapPassword,
		}
	}
}
