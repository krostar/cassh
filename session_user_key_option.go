package cassh

// SessionUserKeySignOption defines the signature of all options usable on SessionUserKeySign.
type SessionUserKeySignOption func(o *sessionUserKeySignOptions)

func sessionUserKeySignOptionsDefault() *sessionUserKeySignOptions {
	return &sessionUserKeySignOptions{
		force: false,
	}
}

type sessionUserKeySignOptions struct {
	force bool
}

// SessionUserKeySignOptionForce sets the force attribute to the sign request.
func SessionUserKeySignOptionForce() SessionUserKeySignOption {
	return func(o *sessionUserKeySignOptions) {
		o.force = true
	}
}
