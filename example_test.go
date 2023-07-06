package cassh_test

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/krostar/cassh"
	"github.com/krostar/sshx"
)

func SignUserKeyOnlyIfNeeded(ctx context.Context) error {
	// create the cassh client object
	client, err := cassh.NewClient("https://cassh-server.address")
	if err != nil {
		return fmt.Errorf("unable to create cassh client: %v", err)
	}

	// is the server reachable ?
	if err = client.Ping(ctx); err != nil {
		return fmt.Errorf("unable to ping cassh server: %v", err)
	}

	// setup the user session, useful for later calls
	userSession := client.SessionUser("john.doe", cassh.SessionUserOptionAuthenticationMechanismLDAP("john.doe@company.corp", "awesome42password"))

	// get current user status
	status, err := userSession.Status(ctx)
	if err != nil {
		return fmt.Errorf("unable to create cassh client: %v", err)
	}

	// check whenever user key is valid for at least 10 more minutes
	if status.KeyState == cassh.KeyStateActive && time.Now().Add(10*time.Minute).Before(status.KeyExpiration) {
		return nil
	}

	// otherwise, sign a new key
	// first get the user public key from file
	userPublicKey, err := sshx.NewPublicKeyFromOpenSSHAuthorizedKeyFile("~/.ssh/id_rsa.pub")
	if err != nil {
		return fmt.Errorf("unable to open user ssh public key: %v", err)
	}

	// sign it
	userSignedCertificate, err := userSession.Key(userPublicKey).Sign(ctx)
	if err != nil {
		return fmt.Errorf("unable to sign user key: %v", err)
	}

	// write the signed certificate
	if err := os.WriteFile("~/.ssh/id_rsa-cert.pub", ssh.MarshalAuthorizedKey(userSignedCertificate), 0o600); err != nil {
		return fmt.Errorf("unable to write signed certificate: %v", err)
	}

	return nil
}
