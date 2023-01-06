package botdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const urlPattern = "https://research.forta.network/database/%s/%s"

var ErrNotFound = errors.New("not found")

type Client interface {
	Get(scope Scope, objID string) ([]byte, error)
	Put(scope Scope, objID string, payload []byte) error
	Del(scope Scope, objID string) error
}

type Scope string

var ScopeBot Scope = "bot"
var ScopeScanner Scope = "scanner"

type client struct {
	jwtProviderUrl string
}

func (c *client) Put(scope Scope, objID string, payload []byte) error {
	req, err := http.NewRequest("PUT", fmt.Sprintf(urlPattern, scope, objID), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if err := c.addAuth(req); err != nil {
		return err
	}

	hc := &http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == 404 {
		return ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("response %d", resp.StatusCode)
	}
	return nil
}

func (c *client) Del(scope Scope, objID string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf(urlPattern, scope, objID), nil)
	if err != nil {
		return err
	}
	if err := c.addAuth(req); err != nil {
		return err
	}

	hc := &http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == 404 {
		return ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("response %d", resp.StatusCode)
	}
	return nil
}

func (c *client) Get(scope Scope, objID string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(urlPattern, scope, objID), nil)
	if err != nil {
		return nil, err
	}
	if err := c.addAuth(req); err != nil {
		return nil, err
	}

	hc := &http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("response %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *client) addAuth(r *http.Request) error {
	token, err := c.token()
	if err != nil {
		return err
	}
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	return nil
}

func (c *client) token() (string, error) {
	// negotiate token
	res, err := http.Post(c.jwtProviderUrl, "", nil)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	var jwtResp CreateJWTResponse
	if err := json.NewDecoder(res.Body).Decode(&jwtResp); err != nil {
		return "", err
	}
	return jwtResp.Token, nil
}

func NewClient(jwtProviderHost, jwtProviderPort string) (Client, error) {
	return &client{
		jwtProviderUrl: fmt.Sprintf("http://%s:%s/create", jwtProviderHost, jwtProviderPort),
	}, nil
}
