package cassh

type SessionUserKeySignOption func(o *sessionUserKeySignOptions)

func sessionUserKeySignOptionsDefault() *sessionUserKeySignOptions {
	return &sessionUserKeySignOptions{
		force: false,
	}
}

type sessionUserKeySignOptions struct {
	force bool
}

func SessionUserKeySignOptionForce() SessionUserKeySignOption {
	return func(o *sessionUserKeySignOptions) {
		o.force = true
	}
}
