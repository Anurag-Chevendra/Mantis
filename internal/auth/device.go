// Package auth implements `mantis login`: the OAuth 2.0 Device Authorization
// Grant (RFC 8628), the same flow `gh auth login`, the Azure CLI and AWS SSO
// use.
//
// Why this flow, for people who have to justify a tool to a security team:
//
//   - Mantis never sees a password, a Google session or a browser cookie.
//     The user signs in on the console's own page, in their own browser.
//   - Nothing listens on a local port. There is no loopback redirect for
//     another process on the machine to race or intercept.
//   - The user approves on a page that shows the same short code the
//     terminal shows, so approving a request someone else started requires
//     typing a code they cannot see.
//   - The result is an ordinary, revocable API key named after the machine,
//     visible on the console's Keys page. `mantis logout` revokes it there
//     (RFC 7009), not just locally.
//   - The verification URL is checked against the configured console host
//     before it is shown, so a misbehaving server cannot send the user to a
//     look-alike domain.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientID identifies Mantis to the console. Public clients have no secret.
const ClientID = "mantis-cli"

// DefaultScope is what Mantis asks for: read verdicts and, only when the user
// passes --analyze, queue deep analyses.
const DefaultScope = "read queue"

// DeviceCode is the console's answer to a device authorization request.
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token is the console's answer once the user approves.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Flow runs the device grant against one console.
type Flow struct {
	Console    *url.URL
	HTTP       *http.Client
	UserAgent  string
	DeviceName string
	Scope      string
	// Sleep is replaceable for tests.
	Sleep func(context.Context, time.Duration) error
}

// Errors the caller reports in plain words.
var (
	ErrDenied  = errors.New("the request was denied in the browser")
	ErrExpired = errors.New("the code expired before it was approved; run `mantis login` again")
)

type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *oauthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// Start requests a device and user code.
func (f *Flow) Start(ctx context.Context) (*DeviceCode, error) {
	form := url.Values{"client_id": {ClientID}, "scope": {f.scope()}}
	if f.DeviceName != "" {
		form.Set("device_name", f.DeviceName)
	}
	var dc DeviceCode
	if err := f.post(ctx, "/oauth/device/code", form, &dc); err != nil {
		return nil, err
	}
	if dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" {
		return nil, errors.New("the console returned an incomplete device code response")
	}
	if err := f.checkVerificationURL(dc.VerificationURI); err != nil {
		return nil, err
	}
	if dc.VerificationURIComplete != "" {
		if err := f.checkVerificationURL(dc.VerificationURIComplete); err != nil {
			dc.VerificationURIComplete = "" // fall back to the plain URL plus typed code
		}
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	if dc.ExpiresIn <= 0 {
		dc.ExpiresIn = 600
	}
	return &dc, nil
}

// Wait polls until the user approves, denies, or the code expires.
func (f *Flow) Wait(ctx context.Context, dc *DeviceCode) (*Token, error) {
	interval := time.Duration(dc.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {dc.DeviceCode},
		"client_id":   {ClientID},
	}
	transient := 0
	for {
		if time.Now().After(deadline) {
			return nil, ErrExpired
		}
		if err := f.sleep(ctx, interval); err != nil {
			return nil, err
		}
		var tok Token
		err := f.post(ctx, "/oauth/token", form, &tok)
		var oe *oauthError
		if err != nil && !errors.As(err, &oe) && ctx.Err() == nil {
			// A dropped connection or a brief outage while the user is
			// still in the browser must not end the login. Give up only
			// after several failures in a row.
			if transient++; transient < 4 {
				continue
			}
		} else {
			transient = 0
		}
		switch {
		case err == nil:
			if tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "bearer") {
				return nil, errors.New("the console returned an unusable token")
			}
			if len(tok.AccessToken) > 512 || strings.ContainsAny(tok.AccessToken, " \r\n\t") {
				return nil, errors.New("the console returned a malformed token")
			}
			return &tok, nil
		case errors.As(err, &oe):
			switch oe.Code {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5 * time.Second // RFC 8628 section 3.5
				continue
			case "access_denied":
				return nil, ErrDenied
			case "expired_token":
				return nil, ErrExpired
			default:
				return nil, fmt.Errorf("login failed: %w", oe)
			}
		default:
			return nil, err
		}
	}
}

// Revoke tells the console to delete the key (RFC 7009). The console answers
// 200 even for unknown tokens, so this only fails on transport errors.
func (f *Flow) Revoke(ctx context.Context, token string) error {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}, "client_id": {ClientID}}
	return f.post(ctx, "/oauth/revoke", form, nil)
}

func (f *Flow) scope() string {
	if f.Scope != "" {
		return f.Scope
	}
	return DefaultScope
}

func (f *Flow) sleep(ctx context.Context, d time.Duration) error {
	if f.Sleep != nil {
		return f.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// checkVerificationURL refuses any URL that is not https on the console's
// own host (http is allowed only when the console itself is loopback).
func (f *Flow) checkVerificationURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the console sent an invalid verification URL")
	}
	if !strings.EqualFold(u.Hostname(), f.Console.Hostname()) || u.User != nil {
		return fmt.Errorf("refusing verification URL on %q: it is not the console host %q", u.Hostname(), f.Console.Hostname())
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && f.Console.Scheme == "http") {
		return fmt.Errorf("refusing non https verification URL %q", raw)
	}
	return nil
}

func (f *Flow) post(ctx context.Context, path string, form url.Values, out any) error {
	u := *f.Console
	u.Path = strings.TrimRight(f.Console.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	// Each OAuth call uses a fresh connection. Polls are seconds apart, the
	// same order as many servers' keep alive timeout, so a reused connection
	// can be closed by the server just as the request is written.
	req.Close = true
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", f.UserAgent)
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("unexpected response from %s: %w", u.Host, err)
		}
		return nil
	}
	var oe oauthError
	if json.Unmarshal(data, &oe) == nil && oe.Code != "" {
		return &oe
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s does not support device login yet (HTTP 404 on %s)", u.Host, path)
	}
	return fmt.Errorf("%s answered HTTP %d on %s", u.Host, resp.StatusCode, path)
}
