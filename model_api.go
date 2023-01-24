package cassh

import (
	"fmt"
	"time"
)

type apiHealthResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type apiUserStatusResponse struct {
	Expiration string   `json:"expiration"`
	Expiry     string   `json:"expiry"`
	Principals []string `json:"principals"`
	RealName   string   `json:"realname"`
	SSHKeyHash struct {
		AuthType string `json:"auth_type"`
		Bits     int    `json:"bits"`
		Hash     string `json:"hash"`
		Rate     string `json:"rate"`
	} `json:"ssh_key_hash"`
	Status   string `json:"status"`
	Username string `json:"username"`
}

func dtoUserStatusResponse(response apiUserStatusResponse, timeZone *time.Location) (*UserStatus, error) {
	expiration, err := time.ParseInLocation("2006-01-02 15:04:05", response.Expiration, timeZone)
	if err != nil {
		return nil, fmt.Errorf("unable to parse expiration time: %v", err)
	}

	keyStatus := &UserStatus{
		Name:          Username(response.Username),
		RealName:      response.RealName,
		KeyState:      KeyState(response.Status),
		KeyExpiration: expiration,
		KeyPrincipals: make(Principals, len(response.Principals)),
	}

	for i := range response.Principals {
		keyStatus.KeyPrincipals[i] = Principal(response.Principals[i])
	}

	return keyStatus, nil
}
