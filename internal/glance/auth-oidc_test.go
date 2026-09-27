package glance

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type fakeOIDCProvider struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu sync.Mutex
	// Set by the test once the authorization request is known
	code          string
	codeChallenge string
	nonce         string
	claims        map[string]any
	audience      string
	subject       string

	// Refresh token issued on code exchange, none if empty
	refreshToken string
	// Status code returned for refresh requests, 0 for success
	refreshStatus int
	// Whether a new refresh token is issued on every refresh
	rotateRefreshTokens bool
	// Whether refresh responses include a new ID token, userinfo is used otherwise
	idTokenOnRefresh bool
	refreshCalls     int
	revokedTokens    []string
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	p := &fakeOIDCProvider{t: t, key: key, audience: "glance", subject: "user-1", idTokenOnRefresh: true}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/authorize",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/jwks",
			"userinfo_endpoint":                     p.server.URL + "/userinfo",
			"revocation_endpoint":                   p.server.URL + "/revoke",
			"end_session_endpoint":                  p.server.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
		}}})
	})

	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := map[string]any{
			"access_token": "access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}

		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			if r.PostForm.Get("code") != p.code {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}

			verifierHash := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(verifierHash[:]) != p.codeChallenge {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"pkce"}`))
				return
			}

			response["id_token"] = p.signIDToken()
			if p.refreshToken != "" {
				response["refresh_token"] = p.refreshToken
			}
		case "refresh_token":
			p.refreshCalls++

			if p.refreshStatus != 0 {
				w.WriteHeader(p.refreshStatus)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}

			if r.PostForm.Get("refresh_token") != p.refreshToken {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}

			if p.rotateRefreshTokens {
				p.refreshToken = fmt.Sprintf("refresh-%d", p.refreshCalls)
				response["refresh_token"] = p.refreshToken
			}

			if p.idTokenOnRefresh {
				p.nonce = ""
				response["id_token"] = p.signIDToken()
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()

		claims := map[string]any{"sub": p.subject}
		for k, v := range p.claims {
			claims[k] = v
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claims)
	})

	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()

		if user, pass, ok := r.BasicAuth(); !ok || user != "glance" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		r.ParseForm()
		p.revokedTokens = append(p.revokedTokens, r.PostForm.Get("token"))
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	return p
}

func (p *fakeOIDCProvider) update(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

func (p *fakeOIDCProvider) signIDToken() string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"),
	)
	if err != nil {
		p.t.Fatalf("creating signer: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   p.server.URL,
		"aud":   p.audience,
		"sub":   p.subject,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": p.nonce,
	}
	for k, v := range p.claims {
		claims[k] = v
	}

	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		p.t.Fatalf("signing: %v", err)
	}

	serialized, err := signed.CompactSerialize()
	if err != nil {
		p.t.Fatalf("serializing: %v", err)
	}

	return serialized
}

type oidcTestEnv struct {
	secret    string
	configDir string
}

func newOIDCTestEnv(t *testing.T) *oidcTestEnv {
	secret, err := makeAuthSecretKey(AUTH_SECRET_KEY_LENGTH)
	if err != nil {
		t.Fatal(err)
	}

	env := &oidcTestEnv{secret: secret, configDir: t.TempDir()}
	t.Cleanup(env.forgetStore)

	return env
}

// Simulates a restart by dropping the in memory session store so that it's loaded from disk again
func (env *oidcTestEnv) forgetStore() {
	oidcSessionStoresMu.Lock()
	defer oidcSessionStoresMu.Unlock()

	for path := range oidcSessionStores {
		if strings.HasPrefix(path, env.configDir) {
			delete(oidcSessionStores, path)
		}
	}
}

func (env *oidcTestEnv) app(t *testing.T, c *oidcConfig) *application {
	cfg := &config{mainConfigDir: env.configDir}
	cfg.Auth.SecretKey = env.secret
	cfg.Auth.OIDC = c
	cfg.Pages = []page{{Title: "Home"}}

	if err := c.validate(); err != nil {
		t.Fatalf("config should be valid: %v", err)
	}

	app, err := newApplication(cfg)
	if err != nil {
		t.Fatalf("creating application: %v", err)
	}

	return app
}

func newOIDCTestApp(t *testing.T, c *oidcConfig) *application {
	return newOIDCTestEnv(t).app(t, c)
}

func sessionIDFromCookie(cookie *http.Cookie) string {
	return strings.TrimPrefix(cookie.Value, AUTH_OIDC_SESSION_PREFIX)
}

// Makes the session due for a recheck with the provider
func backdateOIDCSession(t *testing.T, app *application, cookie *http.Cookie, by time.Duration) {
	t.Helper()
	id := sessionIDFromCookie(cookie)
	session := app.oidc.sessions.get(id)
	if session == nil {
		t.Fatal("session does not exist")
	}

	session.LastChecked = session.LastChecked.Add(-by)
	session.lastFailedCheck = time.Time{}
	app.oidc.sessions.replace(id, session, false)
}

type oidcLoginResult struct {
	location string
	session  *http.Cookie
}

// Runs the full flow against the fake provider. tamper can modify the callback query.
func runOIDCLogin(t *testing.T, app *application, p *fakeOIDCProvider, tamper func(q url.Values)) oidcLoginResult {
	rec := httptest.NewRecorder()
	app.handleOIDCLoginRequest(rec, httptest.NewRequest("GET", AUTH_OIDC_LOGIN_PATH, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect to provider, got %d", rec.Code)
	}

	authURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(authURL.String(), p.server.URL+"/authorize") {
		t.Fatalf("unexpected authorization URL: %s", rec.Header().Get("Location"))
	}

	aq := authURL.Query()
	if aq.Get("code_challenge_method") != "S256" || aq.Get("code_challenge") == "" {
		t.Fatal("authorization request is missing PKCE parameters")
	}
	if aq.Get("state") == "" || aq.Get("nonce") == "" {
		t.Fatal("authorization request is missing state or nonce")
	}

	p.update(func() {
		p.code = "the-code"
		p.codeChallenge = aq.Get("code_challenge")
		p.nonce = aq.Get("nonce")
	})

	var flowCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == AUTH_OIDC_FLOW_COOKIE_NAME {
			flowCookie = c
		}
	}
	if flowCookie == nil || !flowCookie.HttpOnly {
		t.Fatal("expected an HttpOnly flow cookie")
	}

	cq := url.Values{"code": {"the-code"}, "state": {aq.Get("state")}}
	if tamper != nil {
		tamper(cq)
	}

	req := httptest.NewRequest("GET", AUTH_OIDC_CALLBACK_PATH+"?"+cq.Encode(), nil)
	req.AddCookie(flowCookie)
	rec = httptest.NewRecorder()
	app.handleOIDCCallbackRequest(rec, req)

	result := oidcLoginResult{location: rec.Header().Get("Location")}
	for _, c := range rec.Result().Cookies() {
		if c.Name == AUTH_SESSION_COOKIE_NAME && c.Value != "" {
			result.session = c
		}
	}

	return result
}

func testOIDCConfig(p *fakeOIDCProvider) *oidcConfig {
	return &oidcConfig{
		IssuerURL:    p.server.URL,
		ClientID:     "glance",
		ClientSecret: "secret",
		RedirectURL:  "https://glance.example.com/auth/oidc/callback",
		AllowAll:     true,
	}
}

func assertAuthorized(t *testing.T, app *application, session *http.Cookie, want bool) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	if session != nil {
		req.AddCookie(session)
	}

	if got := app.isAuthorized(httptest.NewRecorder(), req); got != want {
		t.Fatalf("isAuthorized = %v, want %v", got, want)
	}
}

func TestOIDCLoginSuccess(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.refreshToken = "refresh-0"
	p.claims = map[string]any{"preferred_username": "alice", "groups": []string{"admins"}}

	env := newOIDCTestEnv(t)
	c := testOIDCConfig(p)
	c.AllowAll, c.AllowedGroups = false, []string{"admins"}
	app := env.app(t, c)

	result := runOIDCLogin(t, app, p, nil)
	if result.session == nil {
		t.Fatalf("expected a session cookie, redirected to %s", result.location)
	}
	if result.location != "/" {
		t.Fatalf("expected redirect to /, got %s", result.location)
	}
	if !strings.HasPrefix(result.session.Value, AUTH_OIDC_SESSION_PREFIX) {
		t.Fatalf("expected an OIDC session cookie, got %q", result.session.Value)
	}

	assertAuthorized(t, app, result.session, true)

	// The session file must not leak the refresh token, identity or session ID
	data, err := os.ReadFile(filepath.Join(env.configDir, AUTH_OIDC_DEFAULT_SESSION_FILE))
	if err != nil {
		t.Fatalf("reading session file: %v", err)
	}
	for _, secret := range []string{"refresh-0", "alice", sessionIDFromCookie(result.session)} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("session file contains %q in plain text", secret)
		}
	}

	// Sessions survive a restart
	env.forgetStore()
	assertAuthorized(t, env.app(t, testOIDCConfigWithGroups(p, "admins")), result.session, true)

	// But not a change of secret-key
	env.forgetStore()
	env.secret, _ = makeAuthSecretKey(AUTH_SECRET_KEY_LENGTH)
	assertAuthorized(t, env.app(t, testOIDCConfigWithGroups(p, "admins")), result.session, false)
}

func testOIDCConfigWithGroups(p *fakeOIDCProvider, groups ...string) *oidcConfig {
	c := testOIDCConfig(p)
	c.AllowAll, c.AllowedGroups = false, groups
	return c
}

func TestOIDCAllowListChangesOnlyAffectThatUser(t *testing.T) {
	p := newFakeOIDCProvider(t)
	env := newOIDCTestEnv(t)

	c := testOIDCConfig(p)
	c.AllowAll = false
	c.AllowedEmails = []string{"alice@example.com"}
	c.AllowedUsernames = []string{"bob"}
	c.AllowedGroups = []string{"admins"}
	app := env.app(t, c)

	logins := map[string]map[string]any{
		"alice": {"email": "alice@example.com", "email_verified": true},
		"bob":   {"preferred_username": "bob"},
		"carol": {"groups": []any{"admins"}},
	}

	sessions := map[string]*http.Cookie{}
	for name, claims := range logins {
		p.update(func() { p.subject, p.claims = name, claims })
		result := runOIDCLogin(t, app, p, nil)
		if result.session == nil {
			t.Fatalf("%s could not log in, redirected to %s", name, result.location)
		}
		sessions[name] = result.session
	}

	// Reloading the config with bob removed from the allow list
	c2 := testOIDCConfig(p)
	c2.AllowAll = false
	c2.AllowedEmails = []string{"alice@example.com"}
	c2.AllowedGroups = []string{"admins"}
	app2 := env.app(t, c2)

	assertAuthorized(t, app2, sessions["alice"], true)
	assertAuthorized(t, app2, sessions["bob"], false)
	assertAuthorized(t, app2, sessions["carol"], true)

	// Bob's session is gone for good, adding him back requires logging in again
	assertAuthorized(t, app, sessions["bob"], false)
}

func TestOIDCSessionRecheck(t *testing.T) {
	setup := func(t *testing.T) (*fakeOIDCProvider, *application, *http.Cookie) {
		p := newFakeOIDCProvider(t)
		p.refreshToken = "refresh-0"
		p.claims = map[string]any{"preferred_username": "alice", "groups": []any{"admins"}}

		app := newOIDCTestApp(t, testOIDCConfigWithGroups(p, "admins"))
		result := runOIDCLogin(t, app, p, nil)
		if result.session == nil {
			t.Fatalf("expected a session cookie, redirected to %s", result.location)
		}

		return p, app, result.session
	}

	t.Run("not due yet", func(t *testing.T) {
		p, app, session := setup(t)
		assertAuthorized(t, app, session, true)
		if p.refreshCalls != 0 {
			t.Fatalf("expected no refresh, got %d", p.refreshCalls)
		}
	})

	t.Run("still allowed", func(t *testing.T) {
		p, app, session := setup(t)
		backdateOIDCSession(t, app, session, 10*time.Minute)
		assertAuthorized(t, app, session, true)
		if p.refreshCalls != 1 {
			t.Fatalf("expected 1 refresh, got %d", p.refreshCalls)
		}

		// Rechecked sessions aren't rechecked again until the interval has passed
		assertAuthorized(t, app, session, true)
		if p.refreshCalls != 1 {
			t.Fatalf("expected 1 refresh, got %d", p.refreshCalls)
		}
	})

	t.Run("removed from group at provider", func(t *testing.T) {
		p, app, session := setup(t)
		p.update(func() { p.claims["groups"] = []any{"users"} })
		backdateOIDCSession(t, app, session, 10*time.Minute)
		assertAuthorized(t, app, session, false)
		if app.oidc.sessions.get(sessionIDFromCookie(session)) != nil {
			t.Fatal("session should have been deleted")
		}
	})

	t.Run("removed from group at provider, via userinfo", func(t *testing.T) {
		p, app, session := setup(t)
		p.update(func() { p.claims["groups"] = []any{"users"}; p.idTokenOnRefresh = false })
		backdateOIDCSession(t, app, session, 10*time.Minute)
		assertAuthorized(t, app, session, false)
	})

	t.Run("account disabled at provider", func(t *testing.T) {
		p, app, session := setup(t)
		p.update(func() { p.refreshStatus = http.StatusBadRequest })
		backdateOIDCSession(t, app, session, 10*time.Minute)
		assertAuthorized(t, app, session, false)
		if app.oidc.sessions.get(sessionIDFromCookie(session)) != nil {
			t.Fatal("session should have been deleted")
		}
	})

	t.Run("provider unavailable", func(t *testing.T) {
		p, app, session := setup(t)
		p.update(func() { p.refreshStatus = http.StatusServiceUnavailable })

		backdateOIDCSession(t, app, session, 10*time.Minute)
		assertAuthorized(t, app, session, true)

		// Failed rechecks aren't retried on every request
		assertAuthorized(t, app, session, true)
		if p.refreshCalls != 1 {
			t.Fatalf("expected 1 refresh, got %d", p.refreshCalls)
		}

		// Past the grace period the session is no longer accepted, but kept for when the provider is back
		backdateOIDCSession(t, app, session, AUTH_OIDC_RECHECK_GRACE_PERIOD)
		assertAuthorized(t, app, session, false)

		p.update(func() { p.refreshStatus = 0 })
		backdateOIDCSession(t, app, session, 0)
		assertAuthorized(t, app, session, true)
	})

	t.Run("concurrent requests refresh once", func(t *testing.T) {
		p, app, session := setup(t)
		p.update(func() { p.rotateRefreshTokens = true })
		backdateOIDCSession(t, app, session, 10*time.Minute)

		var wg sync.WaitGroup
		results := make([]bool, 10)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/", nil)
				req.AddCookie(session)
				results[i] = app.isAuthorized(httptest.NewRecorder(), req)
			}()
		}
		wg.Wait()

		for i, ok := range results {
			if !ok {
				t.Fatalf("request %d was not authorized", i)
			}
		}

		if p.refreshCalls != 1 {
			t.Fatalf("expected 1 refresh, got %d", p.refreshCalls)
		}

		if got := app.oidc.sessions.get(sessionIDFromCookie(session)).RefreshToken; got != "refresh-1" {
			t.Fatalf("rotated refresh token was not stored, got %q", got)
		}
	})
}

func TestOIDCSessionWithoutRefreshToken(t *testing.T) {
	p := newFakeOIDCProvider(t)
	app := newOIDCTestApp(t, testOIDCConfig(p))

	result := runOIDCLogin(t, app, p, nil)
	if result.session == nil {
		t.Fatalf("expected a session cookie, redirected to %s", result.location)
	}

	// Capped to the access token lifetime of an hour instead of session-max-age
	if lifetime := time.Until(result.session.Expires); lifetime > time.Hour || lifetime < 59*time.Minute {
		t.Fatalf("unexpected session lifetime %s", lifetime)
	}
}

func TestOIDCLogout(t *testing.T) {
	for _, fromProvider := range []bool{false, true} {
		t.Run(fmt.Sprintf("logout-from-provider=%v", fromProvider), func(t *testing.T) {
			p := newFakeOIDCProvider(t)
			p.refreshToken = "refresh-0"
			c := testOIDCConfig(p)
			c.LogoutFromProvider = fromProvider
			app := newOIDCTestApp(t, c)

			result := runOIDCLogin(t, app, p, nil)
			if result.session == nil {
				t.Fatalf("expected a session cookie, redirected to %s", result.location)
			}

			req := httptest.NewRequest("GET", "/logout", nil)
			req.AddCookie(result.session)
			rec := httptest.NewRecorder()
			app.handleLogoutRequest(rec, req)

			assertAuthorized(t, app, result.session, false)

			if len(p.revokedTokens) != 1 || p.revokedTokens[0] != "refresh-0" {
				t.Fatalf("refresh token was not revoked: %v", p.revokedTokens)
			}

			location, _ := url.Parse(rec.Header().Get("Location"))
			if !fromProvider {
				if location.String() != "/login" {
					t.Fatalf("expected redirect to /login, got %s", location)
				}
				return
			}

			if !strings.HasPrefix(location.String(), p.server.URL+"/logout?") {
				t.Fatalf("expected redirect to the provider, got %s", location)
			}

			q := location.Query()
			if q.Get("id_token_hint") == "" || q.Get("client_id") != "glance" ||
				q.Get("post_logout_redirect_uri") != "https://glance.example.com/login" {
				t.Fatalf("unexpected end session parameters: %v", q)
			}
		})
	}
}

func TestOIDCAuthParams(t *testing.T) {
	p := newFakeOIDCProvider(t)
	c := testOIDCConfig(p)
	c.AuthParams = map[string]string{"access_type": "offline", "prompt": "consent"}
	app := newOIDCTestApp(t, c)

	rec := httptest.NewRecorder()
	app.handleOIDCLoginRequest(rec, httptest.NewRequest("GET", AUTH_OIDC_LOGIN_PATH, nil))

	location, _ := url.Parse(rec.Header().Get("Location"))
	if q := location.Query(); q.Get("access_type") != "offline" || q.Get("prompt") != "consent" {
		t.Fatalf("auth-params missing from authorization URL: %s", location)
	}
}

func TestOIDCLoginRejections(t *testing.T) {
	cases := []struct {
		name      string
		claims    map[string]any
		audience  string
		config    func(c *oidcConfig)
		tamper    func(q url.Values)
		wantError string
	}{
		{
			name:      "state mismatch",
			tamper:    func(q url.Values) { q.Set("state", "wrong") },
			wantError: "sso-failed",
		},
		{
			name:      "wrong code",
			tamper:    func(q url.Values) { q.Set("code", "wrong") },
			wantError: "sso-failed",
		},
		{
			name:      "provider error",
			tamper:    func(q url.Values) { q.Set("error", "access_denied") },
			wantError: "sso-denied",
		},
		{
			name:      "wrong audience",
			audience:  "someone-else",
			wantError: "sso-failed",
		},
		{
			name:      "nonce mismatch",
			claims:    map[string]any{"nonce": "wrong"},
			wantError: "sso-failed",
		},
		{
			name:      "group not allowed",
			claims:    map[string]any{"groups": []string{"users"}},
			config:    func(c *oidcConfig) { c.AllowAll, c.AllowedGroups = false, []string{"admins"} },
			wantError: "sso-forbidden",
		},
		{
			name:      "unverified email",
			claims:    map[string]any{"email": "alice@example.com", "email_verified": false},
			config:    func(c *oidcConfig) { c.AllowAll, c.AllowedEmails = false, []string{"alice@example.com"} },
			wantError: "sso-forbidden",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeOIDCProvider(t)
			p.claims = tc.claims
			if tc.audience != "" {
				p.audience = tc.audience
			}

			c := testOIDCConfig(p)
			if tc.config != nil {
				tc.config(c)
			}
			app := newOIDCTestApp(t, c)

			result := runOIDCLogin(t, app, p, tc.tamper)
			if result.session != nil {
				t.Fatal("expected no session cookie")
			}
			if result.location != "/login?error="+tc.wantError {
				t.Fatalf("expected redirect with %s, got %s", tc.wantError, result.location)
			}
		})
	}
}

func TestOIDCCallbackWithoutFlowCookie(t *testing.T) {
	p := newFakeOIDCProvider(t)
	app := newOIDCTestApp(t, testOIDCConfig(p))

	rec := httptest.NewRecorder()
	app.handleOIDCCallbackRequest(rec, httptest.NewRequest("GET", AUTH_OIDC_CALLBACK_PATH+"?code=x&state=y", nil))

	if loc := rec.Header().Get("Location"); loc != "/login?error=sso-expired" {
		t.Fatalf("unexpected redirect: %s", loc)
	}
}

func TestOIDCFlowStateTamperingAndExpiry(t *testing.T) {
	secret, _ := makeAuthSecretKey(AUTH_SECRET_KEY_LENGTH)
	secretBytes, _ := base64.StdEncoding.DecodeString(secret)
	now := time.Now()

	encoded, err := encodeOIDCFlowState(&oidcFlowState{
		State: "s", Nonce: "n", Verifier: "v", Expires: now.Add(time.Minute).Unix(),
	}, secretBytes)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeOIDCFlowState(encoded, secretBytes, now); err != nil {
		t.Fatalf("valid flow state rejected: %v", err)
	}

	if _, err := decodeOIDCFlowState(encoded, secretBytes, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired flow state accepted")
	}

	payload, mac, _ := strings.Cut(encoded, ".")
	decoded, _ := base64.RawURLEncoding.DecodeString(payload)
	tampered := strings.Replace(string(decoded), `"s":"s"`, `"s":"x"`, 1)
	if _, err := decodeOIDCFlowState(base64.RawURLEncoding.EncodeToString([]byte(tampered))+"."+mac, secretBytes, now); err == nil {
		t.Fatal("tampered flow state accepted")
	}
}

func TestOIDCAllowLists(t *testing.T) {
	c := &oidcConfig{
		AllowedEmails:    []string{" Alice@Example.com "},
		AllowedUsernames: []string{"bob"},
		AllowedGroups:    []string{"admins"},
	}
	c.applyDefaults("")

	cases := []struct {
		name     string
		claims   map[string]any
		wantUser string
		wantOK   bool
	}{
		{"verified email", map[string]any{"email": "ALICE@example.com", "email_verified": true}, "alice@example.com", true},
		{"missing email_verified", map[string]any{"email": "alice@example.com"}, "alice@example.com", false},
		{"username", map[string]any{"preferred_username": "bob"}, "bob", true},
		{"username is case sensitive", map[string]any{"preferred_username": "Bob"}, "Bob", false},
		{"username is not matched against email", map[string]any{"email": "bob", "email_verified": true}, "bob", false},
		{"group list", map[string]any{"preferred_username": "dave", "groups": []any{"users", "admins"}}, "dave", true},
		{"group string", map[string]any{"preferred_username": "dave", "groups": "admins"}, "dave", true},
		{"no match", map[string]any{"groups": []any{"users"}}, "xyz", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &oidcSession{Subject: "xyz"}
			c.applyClaims(s, tc.claims)

			if got := c.allows(s); got != tc.wantOK {
				t.Fatalf("allows = %v, want %v", got, tc.wantOK)
			}
			if s.displayName() != tc.wantUser {
				t.Fatalf("user = %q, want %q", s.displayName(), tc.wantUser)
			}
		})
	}

	// Claims missing from a userinfo response keep their previous value
	s := &oidcSession{Subject: "xyz", Groups: []string{"admins"}}
	c.applyClaims(s, map[string]any{"preferred_username": "dave"})
	if !c.allows(s) {
		t.Fatal("groups should have been kept")
	}
}

func TestOIDCConfigValidation(t *testing.T) {
	valid := func() *oidcConfig {
		return &oidcConfig{
			IssuerURL:   "https://auth.example.com",
			ClientID:    "glance",
			RedirectURL: "https://glance.example.com/dash/auth/oidc/callback",
			AllowAll:    true,
		}
	}

	if err := valid().validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]func(c *oidcConfig){
		"missing issuer":        func(c *oidcConfig) { c.IssuerURL = "" },
		"relative issuer":       func(c *oidcConfig) { c.IssuerURL = "auth.example.com" },
		"missing client id":     func(c *oidcConfig) { c.ClientID = "" },
		"missing redirect":      func(c *oidcConfig) { c.RedirectURL = "" },
		"wrong redirect path":   func(c *oidcConfig) { c.RedirectURL = "https://glance.example.com/callback" },
		"relative redirect url": func(c *oidcConfig) { c.RedirectURL = "/auth/oidc/callback" },
		"no allow list":         func(c *oidcConfig) { c.AllowAll = false },
		"allow-all with list":   func(c *oidcConfig) { c.AllowedGroups = []string{"admins"} },
		"reserved auth param":   func(c *oidcConfig) { c.AuthParams = map[string]string{"redirect_uri": "x"} },
		"short recheck":         func(c *oidcConfig) { c.RecheckInterval = durationField(10 * time.Second) },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(c)
			if err := c.validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	cfg := &config{}
	cfg.Pages = []page{{Title: "Home"}}
	cfg.Auth.OIDC = valid()
	if err := isConfigStateValid(cfg); err == nil || !strings.Contains(err.Error(), "secret-key") {
		t.Fatalf("expected secret-key error, got %v", err)
	}

	c := &oidcConfig{Scopes: []string{"email"}, SessionFile: "sessions.dat"}
	c.applyDefaults("/config")
	if c.Scopes[0] != "openid" {
		t.Fatalf("openid scope should be added, got %v", c.Scopes)
	}
	if c.SessionFile != filepath.Join("/config", "sessions.dat") {
		t.Fatalf("session-file should be relative to the config, got %s", c.SessionFile)
	}
}

func TestLoginPageRendersSSOButton(t *testing.T) {
	p := newFakeOIDCProvider(t)
	c := testOIDCConfig(p)
	c.ButtonLabel = "Authentik"
	app := newOIDCTestApp(t, c)

	rec := httptest.NewRecorder()
	app.handleLoginPageRequest(rec, httptest.NewRequest("GET", "/login?error=sso-forbidden", nil))
	body := rec.Body.String()

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rec.Code, body)
	}

	for _, want := range []string{"SIGN IN WITH Authentik", `href="/auth/oidc/login"`, oidcLoginErrorMessages["sso-forbidden"]} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page is missing %q", want)
		}
	}

	// Without local users the password form and its script are not rendered
	if strings.Contains(body, `id="password"`) || strings.Contains(body, "js/login.js") {
		t.Fatal("password form should not be rendered for OIDC only setups")
	}
}
