package cassh

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/stripe/krl"

	"github.com/krostar/httpclient"
	"github.com/krostar/sshx"
)

type Client struct {
	api            *httpclient.API
	serverTimezone *time.Location
}

// NewClient ...
// Warning: server send time without timezone so some tweaking may be needed to interpret the right time if server and client timezone are not configured the same.
// By default, time is interpreted with UTC timezone, to change it provided the appropriate timezone using ClientOptionServerTimezone.
func NewClient(serverAddress string, opts ...ClientOption) (*Client, error) {
	o := clientOptionsDefaults()
	for _, opt := range opts {
		opt(o)
	}

	serverAddressURL, err := url.Parse(serverAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to parse server address: %v", err)
	}

	if serverAddressURL.Scheme != "https" && !o.tolerateInsecureProtocol {
		return nil, fmt.Errorf("insecure protocol used: %s", serverAddress)
	}

	api := httpclient.
		NewAPI(o.httpDoer, *serverAddressURL).
		WithRequestHeaders(o.httpDefaultHeaders).
		WithResponseHandler(http.StatusOK, func(*http.Response) error { return nil }).
		WithResponseHandler(http.StatusUnauthorized, func(*http.Response) error { return ErrInsufficientPrivileges })

	return &Client{
		api:            api,
		serverTimezone: o.serverTimezone,
	}, nil
}

func (c *Client) Ping(ctx context.Context) error {
	return c.api.Execute(ctx, c.api.Get("/ping"))
}

func (c *Client) Health(ctx context.Context) (string, string, error) {
	var response apiHealthResponse

	if err := c.api.
		Do(ctx, c.api.Get("/health")).
		ReceiveJSON(http.StatusOK, &response).
		Error(); err != nil {
		return "", "", err
	}

	return response.Name, response.Version, nil
}

func (c *Client) KeyRevocationList(ctx context.Context) (*krl.KRL, error) {
	var list *krl.KRL

	if err := c.api.
		Do(ctx, c.api.Get("/krl")).
		OnStatus(http.StatusOK,
			func(resp *http.Response) error {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return fmt.Errorf("unable to read body: %v", err)
				}

				list, err = krl.ParseKRL(body)
				if err != nil {
					return fmt.Errorf("unable to parse body as krl: %v", err)
				}

				return nil
			},
		).Error(); err != nil {
		return nil, err
	}

	return list, nil
}

func (c *Client) AuthorityPublicKey(ctx context.Context) (sshx.PublicKey, error) {
	var authorityPublicKey sshx.PublicKey

	if err := c.api.
		Do(ctx, c.api.Get("/ca")).
		OnStatus(http.StatusOK,
			func(resp *http.Response) error {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return fmt.Errorf("unable to read body: %v", err)
				}

				parsedBody, err := sshx.NewPublicKeyFromOpenSSHAuthorizedKeyBytes(body)
				if err != nil {
					return fmt.Errorf("unable to parse body as ssh key: %v", err)
				}

				authorityPublicKey = parsedBody
				return nil
			},
		).Error(); err != nil {
		return nil, err
	}

	return authorityPublicKey, nil
}
