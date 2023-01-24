[![License](https://img.shields.io/badge/license-MIT-blue)](https://choosealicense.com/licenses/mit/)
![go.mod Go version](https://img.shields.io/github/go-mod/go-version/krostar/cassh?label=go)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/krostar/cassh)
[![Latest tag](https://img.shields.io/github/v/tag/krostar/cassh)](https://github.com/krostar/cassh/tags)
[![Go Report](https://goreportcard.com/badge/github.com/krostar/cassh)](https://goreportcard.com/report/github.com/krostar/cassh)

# CASSH client

The cassh package expose - through the `Client` struct - methods to talk the [CASSH server](https://github.com/nbeguier/cassh/tree/master/src/server).

Usage example; see godoc for full package documentation.

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/krostar/cassh"
	"github.com/krostar/sshx"
	"golang.org/x/crypto/ssh"
)

func signUserKeyOnlyIfNeeded(ctx context.Context) error {
	// create the cassh client object
	client, err := cassh.NewClient("https://cassh-server.address")
	if err != nil {
		return fmt.Errorf("unable to create cassh client: %v", err)
	}

	// is the server reachable ?
	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("unable to ping cassh server: %v", err)
	}

	// setup the user session
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

	// otherwise, considering the user already has a key validated by an admin, sign the key

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
	if err := os.WriteFile("~/.ssh/id_rsa-cert.pub", ssh.MarshalAuthorizedKey(userSignedCertificate), 0644); err != nil {
		return fmt.Errorf("unable to write signed certificate: %v", err)
	}

	return nil
}
```