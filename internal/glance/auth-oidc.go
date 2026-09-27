package glance

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const AUTH_OIDC_FLOW_COOKIE_NAME = "oidc_flow"

// How long the user has to complete the login at the identity provider
const AUTH_OIDC_FLOW_VALID_PERIOD = 10 * time.Minute
const AUTH_OIDC_HTTP_TIMEOUT = 15 * time.Second

const AUTH_OIDC_LOGIN_PATH = "/auth/oidc/login"
const AUTH_OIDC_CALLBACK_PATH = "/auth/oidc/callback"

const AUTH_OIDC_DEFAULT_SESSION_FILE = "glance-oidc-sessions.dat"
const AUTH_OIDC_DEFAULT_RECHECK_INTERVAL = 5 * time.Minute
const AUTH_OIDC_DEFAULT_SESSION_MAX_AGE = AUTH_TOKEN_VALID_PERIOD

// How long a session is kept alive when it can't be rechecked because the provider is unreachable
const AUTH_OIDC_RECHECK_GRACE_PERIOD = 1 * time.Hour

// How long to wait before retrying a recheck that failed because the provider was unreachable
const AUTH_OIDC_RECHECK_RETRY_DELAY = 30 * time.Second

// How long a session lasts when the provider doesn't issue a refresh token and the access token has no expiry
const AUTH_OIDC_DEFAULT_UNREFRESHABLE_SESSION_AGE = 1 * time.Hour

const AUTH_OIDC_LOGOUT_TIMEOUT = 5 * time.Second

// Parameters that glance sets itself and which therefore can't be overridden through auth-params
var oidcReservedAuthParams = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method",
}

type oidcConfig struct {
	IssuerURL          string            `yaml:"issuer-url"`
	ClientID           string            `yaml:"client-id"`
	ClientSecret       string            `yaml:"client-secret"`
	RedirectURL        string            `yaml:"redirect-url"`
	Scopes             []string          `yaml:"scopes"`
	AuthParams         map[string]string `yaml:"auth-params"`
	UsernameClaim      string            `yaml:"username-claim"`
	GroupsClaim        string            `yaml:"groups-claim"`
	AllowedEmails      []string          `yaml:"allowed-emails"`
	AllowedUsernames   []string          `yaml:"allowed-usernames"`
	AllowedGroups      []string          `yaml:"allowed-groups"`
	AllowAll           bool              `yaml:"allow-all"`
	RecheckInterval    durationField     `yaml:"recheck-interval"`
	SessionMaxAge      durationField     `yaml:"session-max-age"`
	SessionFile        string            `yaml:"session-file"`
	LogoutFromProvider bool              `yaml:"logout-from-provider"`
	ButtonLabel        string            `yaml:"button-label"`
}

func (c *oidcConfig) applyDefaults(configDir string) {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	} else if !slices.Contains(c.Scopes, oidc.ScopeOpenID) {
		c.Scopes = append([]string{oidc.ScopeOpenID}, c.Scopes...)
	}

	if c.UsernameClaim == "" {
		c.UsernameClaim = "preferred_username"
	}

	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}

	if c.ButtonLabel == "" {
		c.ButtonLabel = "SSO"
	}

	if c.RecheckInterval == 0 {
		c.RecheckInterval = durationField(AUTH_OIDC_DEFAULT_RECHECK_INTERVAL)
	}

	if c.SessionMaxAge == 0 {
		c.SessionMaxAge = durationField(AUTH_OIDC_DEFAULT_SESSION_MAX_AGE)
	}

	if c.SessionFile == "" {
		c.SessionFile = AUTH_OIDC_DEFAULT_SESSION_FILE
	}

	if !filepath.IsAbs(c.SessionFile) {
		c.SessionFile = filepath.Join(configDir, c.SessionFile)
	}

	for i := range c.AllowedEmails {
		c.AllowedEmails[i] = strings.ToLower(strings.TrimSpace(c.AllowedEmails[i]))
	}

	for i := range c.AllowedUsernames {
		c.AllowedUsernames[i] = strings.TrimSpace(c.AllowedUsernames[i])
	}
}

func (c *oidcConfig) validate() error {
	if c.IssuerURL == "" {
		return errors.New("oidc: issuer-url must be set")
	}

	if u, err := url.Parse(c.IssuerURL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("oidc: issuer-url is not a valid URL: %s", c.IssuerURL)
	}

	if c.ClientID == "" {
		return errors.New("oidc: client-id must be set")
	}

	if c.RedirectURL == "" {
		return errors.New("oidc: redirect-url must be set")
	}

	u, err := url.Parse(c.RedirectURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("oidc: redirect-url is not a valid URL: %s", c.RedirectURL)
	}

	if !strings.HasSuffix(u.Path, AUTH_OIDC_CALLBACK_PATH) {
		return fmt.Errorf("oidc: redirect-url path must end with %s", AUTH_OIDC_CALLBACK_PATH)
	}

	hasAllowList := len(c.AllowedEmails) > 0 || len(c.AllowedUsernames) > 0 || len(c.AllowedGroups) > 0

	if c.AllowAll && hasAllowList {
		return errors.New("oidc: allow-all can't be combined with allowed-emails, allowed-usernames or allowed-groups")
	}

	if !c.AllowAll && !hasAllowList {
		return errors.New("oidc: at least one of allowed-emails, allowed-usernames or allowed-groups must be set, or allow-all must be set to true to let in every user of the identity provider")
	}

	for param := range c.AuthParams {
		if slices.Contains(oidcReservedAuthParams, param) {
			return fmt.Errorf("oidc: auth-params can't override %s", param)
		}
	}

	if c.RecheckInterval != 0 && time.Duration(c.RecheckInterval) < time.Minute {
		return errors.New("oidc: recheck-interval must be at least 1m")
	}

	return nil
}

// The URL the provider sends the user back to after logging out, which is the login page
func (c *oidcConfig) postLogoutRedirectURL() string {
	return strings.TrimSuffix(c.RedirectURL, AUTH_OIDC_CALLBACK_PATH) + "/login"
}

// Updates the identity of the session with the claims that are present, claims that are
// missing leave the current value untouched since userinfo responses may only have a subset
func (c *oidcConfig) applyClaims(s *oidcSession, claims map[string]any) {
	if username, ok := claims[c.UsernameClaim].(string); ok {
		s.Username = strings.TrimSpace(username)
	}

	if email, ok := claims["email"].(string); ok {
		s.Email = strings.ToLower(strings.TrimSpace(email))
		// Unverified emails can be set to anything by the user at some providers
		s.EmailVerified, _ = claims["email_verified"].(bool)
	}

	if groups, ok := claims[c.GroupsClaim]; ok {
		s.Groups = claimAsStrings(groups)
	}
}

// Checks the identity of a session against the configured allow lists
func (c *oidcConfig) allows(s *oidcSession) bool {
	if c.AllowAll {
		return true
	}

	if s.Email != "" && s.EmailVerified && slices.Contains(c.AllowedEmails, s.Email) {
		return true
	}

	if s.Username != "" && slices.Contains(c.AllowedUsernames, s.Username) {
		return true
	}

	for _, group := range s.Groups {
		if slices.Contains(c.AllowedGroups, group) {
			return true
		}
	}

	return false
}

type oidcFlowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

type oidcAuthenticator struct {
	config   *oidcConfig
	client   *http.Client
	sessions *oidcSessionStore

	mu                 sync.Mutex
	provider           *oidc.Provider
	verifier           *oidc.IDTokenVerifier
	oauth              *oauth2.Config
	revocationEndpoint string
	endSessionEndpoint string
}

func newOIDCAuthenticator(c *oidcConfig, sessions *oidcSessionStore) *oidcAuthenticator {
	return &oidcAuthenticator{
		config:   c,
		client:   &http.Client{Timeout: AUTH_OIDC_HTTP_TIMEOUT},
		sessions: sessions,
	}
}

func (o *oidcAuthenticator) clientContext(ctx context.Context) context.Context {
	return context.WithValue(oidc.ClientContext(ctx, o.client), oauth2.HTTPClient, o.client)
}

// Discovery is done lazily so that glance can still start if the identity provider is
// temporarily unreachable. A failed discovery is retried on the next attempt.
func (o *oidcAuthenticator) init(ctx context.Context) (*oidc.IDTokenVerifier, *oauth2.Config, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.provider != nil {
		return o.verifier, o.oauth, nil
	}

	provider, err := oidc.NewProvider(o.clientContext(ctx), o.config.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("discovering OIDC provider: %w", err)
	}

	var endpoints struct {
		Revocation string `json:"revocation_endpoint"`
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&endpoints); err != nil {
		return nil, nil, fmt.Errorf("decoding OIDC provider metadata: %w", err)
	}

	o.provider = provider
	o.revocationEndpoint = endpoints.Revocation
	o.endSessionEndpoint = endpoints.EndSession
	// The context here is used for fetching signing keys later on, so it must not be request scoped
	o.verifier = provider.VerifierContext(o.clientContext(context.Background()), &oidc.Config{
		ClientID: o.config.ClientID,
	})
	o.oauth = &oauth2.Config{
		ClientID:     o.config.ClientID,
		ClientSecret: o.config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  o.config.RedirectURL,
		Scopes:       o.config.Scopes,
	}

	return o.verifier, o.oauth, nil
}

var errOIDCSessionRevoked = errors.New("session was revoked by the identity provider")

// Checks whether an OIDC session is still valid. Sessions are checked against the current
// allow lists on every request and rechecked with the identity provider using their refresh
// token once every recheck-interval, which is what catches accounts that have been disabled
// or removed from a group at the provider.
func (o *oidcAuthenticator) authorizeSession(id string) bool {
	session := o.sessions.get(id)
	if session == nil {
		return false
	}

	if !time.Now().Before(session.Expires) {
		o.sessions.delete(id)
		return false
	}

	if !o.config.allows(session) {
		log.Printf("Ending OIDC session of '%s' since they are no longer allowed in", session.displayName())
		o.sessions.delete(id)
		return false
	}

	interval := time.Duration(o.config.RecheckInterval)

	// Sessions without a refresh token can't be rechecked, their lifetime was capped when created
	if session.RefreshToken == "" || time.Since(session.LastChecked) < interval {
		return true
	}

	unlock := o.sessions.lock(id)
	defer unlock()

	// Another request may have rechecked the session while this one was waiting for the lock
	session = o.sessions.get(id)
	if session == nil {
		return false
	}

	if time.Since(session.LastChecked) < interval {
		return true
	}

	withinGracePeriod := time.Since(session.LastChecked) < interval+AUTH_OIDC_RECHECK_GRACE_PERIOD

	if time.Since(session.lastFailedCheck) < AUTH_OIDC_RECHECK_RETRY_DELAY {
		return withinGracePeriod
	}

	err := o.recheckSession(session)

	if errors.Is(err, errOIDCSessionRevoked) {
		log.Printf("Ending OIDC session of '%s': %v", session.displayName(), err)
		o.sessions.delete(id)
		return false
	}

	if err != nil {
		log.Printf("Could not recheck OIDC session of '%s' with the identity provider: %v", session.displayName(), err)
		session.lastFailedCheck = time.Now()
		o.sessions.replace(id, session, false)
		return withinGracePeriod
	}

	if !o.config.allows(session) {
		log.Printf("Ending OIDC session of '%s' since they are no longer allowed in", session.displayName())
		o.sessions.delete(id)
		return false
	}

	return o.sessions.replace(id, session, true)
}

// Uses the refresh token of the session to confirm with the provider that the user still has
// access and updates the identity of the session with the latest claims. Errors that aren't
// errOIDCSessionRevoked mean that the provider could not be reached.
func (o *oidcAuthenticator) recheckSession(session *oidcSession) error {
	ctx, cancel := context.WithTimeout(context.Background(), AUTH_OIDC_HTTP_TIMEOUT)
	defer cancel()

	verifier, oauthConfig, err := o.init(ctx)
	if err != nil {
		return err
	}

	ctx = o.clientContext(ctx)

	token, err := oauthConfig.TokenSource(ctx, &oauth2.Token{RefreshToken: session.RefreshToken}).Token()
	if err != nil {
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr.Response != nil &&
			retrieveErr.Response.StatusCode >= 400 && retrieveErr.Response.StatusCode < 500 {
			return fmt.Errorf("%w: %v", errOIDCSessionRevoked, err)
		}

		return fmt.Errorf("refreshing token: %w", err)
	}

	if token.RefreshToken != "" {
		session.RefreshToken = token.RefreshToken
	}

	var claims map[string]any
	var subject string

	if rawIDToken, ok := token.Extra("id_token").(string); ok && rawIDToken != "" {
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return fmt.Errorf("%w: refreshed id_token is invalid: %v", errOIDCSessionRevoked, err)
		}

		if err := idToken.Claims(&claims); err != nil {
			return fmt.Errorf("%w: decoding refreshed id_token claims: %v", errOIDCSessionRevoked, err)
		}

		subject = idToken.Subject
		session.IDToken = rawIDToken
	} else if o.provider.UserInfoEndpoint() != "" {
		// Providers aren't required to issue a new ID token on refresh
		userInfo, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return fmt.Errorf("fetching userinfo: %w", err)
		}

		if err := userInfo.Claims(&claims); err != nil {
			return fmt.Errorf("%w: decoding userinfo claims: %v", errOIDCSessionRevoked, err)
		}

		subject = userInfo.Subject
	}

	if claims != nil {
		if subject != session.Subject {
			return fmt.Errorf("%w: subject changed from %q to %q", errOIDCSessionRevoked, session.Subject, subject)
		}

		o.config.applyClaims(session, claims)
	}

	session.LastChecked = time.Now()
	session.lastFailedCheck = time.Time{}

	return nil
}

// Ends the session and returns the URL of the identity provider's logout page if the user
// should also be logged out there, otherwise an empty string
func (o *oidcAuthenticator) logout(id string) string {
	session := o.sessions.get(id)
	if session == nil {
		return ""
	}

	o.sessions.delete(id)
	log.Printf("User '%s' logged out", session.displayName())

	if session.RefreshToken == "" && !o.config.LogoutFromProvider {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), AUTH_OIDC_LOGOUT_TIMEOUT)
	defer cancel()

	if _, _, err := o.init(ctx); err != nil {
		log.Printf("Could not revoke OIDC session of '%s': %v", session.displayName(), err)
		return ""
	}

	if session.RefreshToken != "" && o.revocationEndpoint != "" {
		if err := o.revokeToken(ctx, session.RefreshToken); err != nil {
			log.Printf("Could not revoke refresh token of '%s': %v", session.displayName(), err)
		}
	}

	if !o.config.LogoutFromProvider || o.endSessionEndpoint == "" {
		return ""
	}

	endSessionURL, err := url.Parse(o.endSessionEndpoint)
	if err != nil {
		log.Printf("Invalid end_session_endpoint %q: %v", o.endSessionEndpoint, err)
		return ""
	}

	query := endSessionURL.Query()
	query.Set("client_id", o.config.ClientID)
	query.Set("post_logout_redirect_uri", o.config.postLogoutRedirectURL())
	if session.IDToken != "" {
		query.Set("id_token_hint", session.IDToken)
	}
	endSessionURL.RawQuery = query.Encode()

	return endSessionURL.String()
}

// Revokes a token as described in RFC 7009
func (o *oidcAuthenticator) revokeToken(ctx context.Context, token string) error {
	form := url.Values{
		"token":           {token},
		"token_type_hint": {"refresh_token"},
	}

	if o.config.ClientSecret == "" {
		form.Set("client_id", o.config.ClientID)
	}

	request, err := http.NewRequestWithContext(ctx, "POST", o.revocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if o.config.ClientSecret != "" {
		request.SetBasicAuth(url.QueryEscape(o.config.ClientID), url.QueryEscape(o.config.ClientSecret))
	}

	response, err := o.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation endpoint returned status %d", response.StatusCode)
	}

	return nil
}

func randomURLSafeString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func oidcFlowMAC(payload []byte, secret []byte) []byte {
	h := hmac.New(sha256.New, secret[0:AUTH_TOKEN_SECRET_LENGTH])
	// Domain separation from session tokens which are signed with the same key
	h.Write([]byte("oidc-flow\x00"))
	h.Write(payload)
	return h.Sum(nil)
}

func encodeOIDCFlowState(s *oidcFlowState, secret []byte) (string, error) {
	if len(secret) != AUTH_SECRET_KEY_LENGTH {
		return "", fmt.Errorf("secret key length is not %d bytes", AUTH_SECRET_KEY_LENGTH)
	}

	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(oidcFlowMAC(payload, secret)), nil
}

func decodeOIDCFlowState(value string, secret []byte, now time.Time) (*oidcFlowState, error) {
	if len(secret) != AUTH_SECRET_KEY_LENGTH {
		return nil, fmt.Errorf("secret key length is not %d bytes", AUTH_SECRET_KEY_LENGTH)
	}

	encodedPayload, encodedMAC, found := strings.Cut(value, ".")
	if !found {
		return nil, errors.New("malformed flow state")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}

	mac, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(mac, oidcFlowMAC(payload, secret)) {
		return nil, errors.New("flow state signature does not match")
	}

	var s oidcFlowState
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, err
	}

	if now.Unix() > s.Expires {
		return nil, errors.New("flow state has expired")
	}

	if s.State == "" || s.Nonce == "" || s.Verifier == "" {
		return nil, errors.New("flow state is incomplete")
	}

	return &s, nil
}

func (a *application) setOIDCFlowCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:    AUTH_OIDC_FLOW_COOKIE_NAME,
		Value:   value,
		Expires: expires,
		Secure:  strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https",
		Path:    a.Config.Server.BaseURL + "/auth/oidc/",
		// Lax is required since the callback is a cross site top level navigation from the identity provider
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})
}

func (a *application) redirectToLoginWithError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error="+url.QueryEscape(code), http.StatusSeeOther)
}

func (a *application) handleOIDCLoginRequest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), AUTH_OIDC_HTTP_TIMEOUT)
	defer cancel()

	_, oauthConfig, err := a.oidc.init(ctx)
	if err != nil {
		log.Printf("OIDC login failed: %v", err)
		a.redirectToLoginWithError(w, r, "sso-unavailable")
		return
	}

	state, err1 := randomURLSafeString(32)
	nonce, err2 := randomURLSafeString(32)
	if err := errors.Join(err1, err2); err != nil {
		log.Printf("OIDC login failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	flow := &oidcFlowState{
		State:    state,
		Nonce:    nonce,
		Verifier: oauth2.GenerateVerifier(),
		Expires:  time.Now().Add(AUTH_OIDC_FLOW_VALID_PERIOD).Unix(),
	}

	cookieValue, err := encodeOIDCFlowState(flow, a.authSecretKey)
	if err != nil {
		log.Printf("OIDC login failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	a.setOIDCFlowCookie(w, r, cookieValue, time.Unix(flow.Expires, 0))

	options := []oauth2.AuthCodeOption{
		oidc.Nonce(flow.Nonce),
		oauth2.S256ChallengeOption(flow.Verifier),
	}
	for key, value := range a.oidc.config.AuthParams {
		options = append(options, oauth2.SetAuthURLParam(key, value))
	}

	http.Redirect(w, r, oauthConfig.AuthCodeURL(flow.State, options...), http.StatusFound)
}

func (a *application) handleOIDCCallbackRequest(w http.ResponseWriter, r *http.Request) {
	ip := a.addressOfRequest(r)

	fail := func(code string, format string, args ...any) {
		log.Printf("Failed OIDC login from %s: %s", ip, fmt.Sprintf(format, args...))
		a.redirectToLoginWithError(w, r, code)
	}

	// The flow cookie is single use regardless of the outcome
	a.setOIDCFlowCookie(w, r, "", time.Now().Add(-1*time.Hour))

	query := r.URL.Query()

	if providerError := query.Get("error"); providerError != "" {
		// Don't reflect provider supplied text, only log it
		fail("sso-denied", "identity provider returned error %q", providerError)
		return
	}

	cookie, err := r.Cookie(AUTH_OIDC_FLOW_COOKIE_NAME)
	if err != nil || cookie.Value == "" {
		fail("sso-expired", "missing flow cookie")
		return
	}

	flow, err := decodeOIDCFlowState(cookie.Value, a.authSecretKey, time.Now())
	if err != nil {
		fail("sso-expired", "invalid flow cookie: %v", err)
		return
	}

	if !hmac.Equal([]byte(query.Get("state")), []byte(flow.State)) {
		fail("sso-failed", "state mismatch")
		return
	}

	code := query.Get("code")
	if code == "" {
		fail("sso-failed", "missing authorization code")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), AUTH_OIDC_HTTP_TIMEOUT)
	defer cancel()

	verifier, oauthConfig, err := a.oidc.init(ctx)
	if err != nil {
		fail("sso-unavailable", "%v", err)
		return
	}

	token, err := oauthConfig.Exchange(
		context.WithValue(ctx, oauth2.HTTPClient, a.oidc.client),
		code,
		oauth2.VerifierOption(flow.Verifier),
	)
	if err != nil {
		fail("sso-failed", "exchanging code: %v", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		fail("sso-failed", "token response did not contain an id_token")
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fail("sso-failed", "verifying id_token: %v", err)
		return
	}

	if !hmac.Equal([]byte(idToken.Nonce), []byte(flow.Nonce)) {
		fail("sso-failed", "nonce mismatch")
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		fail("sso-failed", "decoding claims: %v", err)
		return
	}

	now := time.Now()
	session := &oidcSession{
		Subject:     idToken.Subject,
		IDToken:     rawIDToken,
		Created:     now,
		LastChecked: now,
	}
	a.oidc.config.applyClaims(session, claims)

	if !a.oidc.config.allows(session) {
		fail("sso-forbidden", "user '%s' (subject %q) is not in allowed-emails, allowed-usernames or allowed-groups", session.displayName(), idToken.Subject)
		return
	}

	maxAge := time.Duration(a.oidc.config.SessionMaxAge)
	session.Expires = now.Add(maxAge)
	session.RefreshToken = token.RefreshToken

	// Without a refresh token there's no way to recheck the session, so it only lasts for as
	// long as the provider said the access token is valid for
	if session.RefreshToken == "" {
		lifetime := AUTH_OIDC_DEFAULT_UNREFRESHABLE_SESSION_AGE
		if !token.Expiry.IsZero() {
			lifetime = token.Expiry.Sub(now)
		}

		if lifetime < maxAge {
			session.Expires = now.Add(lifetime)
		}
	}

	sessionID, err := a.oidc.sessions.create(session)
	if err != nil {
		fail("sso-failed", "creating session: %v", err)
		return
	}

	log.Printf("User '%s' logged in via OIDC from %s", session.displayName(), ip)
	a.setAuthSessionCookie(w, r, AUTH_OIDC_SESSION_PREFIX+sessionID, session.Expires)
	http.Redirect(w, r, a.Config.Server.BaseURL+"/", http.StatusSeeOther)
}

func claimAsStrings(claim any) []string {
	switch v := claim.(type) {
	case string:
		return []string{v}
	case []any:
		values := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
		return values
	}

	return nil
}

var oidcLoginErrorMessages = map[string]string{
	"sso-unavailable": "The identity provider could not be reached, please try again later",
	"sso-denied":      "Login was cancelled or denied by the identity provider",
	"sso-expired":     "The login session expired, please try again",
	"sso-failed":      "Login failed, please try again",
	"sso-forbidden":   "Your account is not allowed to access this dashboard",
}
