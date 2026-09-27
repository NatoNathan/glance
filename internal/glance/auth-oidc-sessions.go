package glance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Session cookies issued via OIDC are prefixed so that they can be told apart from the
// tokens issued for password logins, which are standard base64 and never contain a dot
const AUTH_OIDC_SESSION_PREFIX = "oidc."
const AUTH_OIDC_SESSION_ID_LENGTH = 32

const oidcSessionFileVersion = 1

var oidcSessionFileAAD = []byte("glance-oidc-sessions-v1")

type oidcSession struct {
	Subject       string    `json:"sub"`
	Username      string    `json:"username,omitempty"`
	Email         string    `json:"email,omitempty"`
	EmailVerified bool      `json:"email_verified,omitempty"`
	Groups        []string  `json:"groups,omitempty"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	IDToken       string    `json:"id_token,omitempty"`
	Created       time.Time `json:"created"`
	Expires       time.Time `json:"expires"`
	LastChecked   time.Time `json:"last_checked"`

	// When the last failed attempt to recheck the session with the provider happened, not persisted
	lastFailedCheck time.Time
}

// The name used to identify the user in the logs
func (s *oidcSession) displayName() string {
	if s.Username != "" {
		return s.Username
	}
	if s.Email != "" {
		return s.Email
	}
	return s.Subject
}

type oidcSessionFile struct {
	Version  int                     `json:"version"`
	Sessions map[string]*oidcSession `json:"sessions"`
}

// Sessions are kept in memory and written to an encrypted file on every change so that
// they survive restarts. Sessions are keyed by a hash of their ID so that the ID itself,
// which is what the cookie holds, is never stored.
type oidcSessionStore struct {
	path  string
	keyID string
	aead  cipher.AEAD

	mu       sync.Mutex
	sessions map[string]*oidcSession
	locks    map[string]*sync.Mutex
}

// Stores are shared between config reloads so that in flight requests of the previous
// application instance and the new one see the same sessions
var oidcSessionStoresMu sync.Mutex
var oidcSessionStores = map[string]*oidcSessionStore{}

func openOIDCSessionStore(path string, secret []byte) (*oidcSessionStore, error) {
	if len(secret) != AUTH_SECRET_KEY_LENGTH {
		return nil, fmt.Errorf("secret key length is not %d bytes", AUTH_SECRET_KEY_LENGTH)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha256.New, secret[0:AUTH_TOKEN_SECRET_LENGTH])
	h.Write([]byte("oidc-session-store\x00"))
	key := h.Sum(nil)
	keyHash := sha256.Sum256(key)
	keyID := hex.EncodeToString(keyHash[:])

	oidcSessionStoresMu.Lock()
	defer oidcSessionStoresMu.Unlock()

	if existing, ok := oidcSessionStores[absPath]; ok && existing.keyID == keyID {
		return existing, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	store := &oidcSessionStore{
		path:     absPath,
		keyID:    keyID,
		aead:     aead,
		sessions: make(map[string]*oidcSession),
		locks:    make(map[string]*sync.Mutex),
	}

	if err := store.load(); err != nil {
		// Most likely the secret-key changed, which is meant to log everyone out anyway
		log.Printf("Could not load OIDC sessions from %s, starting with no sessions: %v", absPath, err)
	}

	oidcSessionStores[absPath] = store
	return store, nil
}

func hashOIDCSessionID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

func (s *oidcSessionStore) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	nonceSize := s.aead.NonceSize()
	if len(data) < nonceSize {
		return errors.New("session file is too short")
	}

	plaintext, err := s.aead.Open(nil, data[:nonceSize], data[nonceSize:], oidcSessionFileAAD)
	if err != nil {
		return fmt.Errorf("decrypting session file: %w", err)
	}

	var file oidcSessionFile
	if err := json.Unmarshal(plaintext, &file); err != nil {
		return fmt.Errorf("decoding session file: %w", err)
	}

	if file.Version != oidcSessionFileVersion {
		return fmt.Errorf("unsupported session file version %d", file.Version)
	}

	now := time.Now()
	for key, session := range file.Sessions {
		if session != nil && now.Before(session.Expires) {
			s.sessions[key] = session
		}
	}

	return nil
}

// Must be called with s.mu held
func (s *oidcSessionStore) save() {
	now := time.Now()
	for key, session := range s.sessions {
		if !now.Before(session.Expires) {
			delete(s.sessions, key)
			delete(s.locks, key)
		}
	}

	if err := s.write(); err != nil {
		log.Printf("Could not save OIDC sessions to %s, sessions will be lost on restart: %v", s.path, err)
	}
}

func (s *oidcSessionStore) write() error {
	plaintext, err := json.Marshal(&oidcSessionFile{
		Version:  oidcSessionFileVersion,
		Sessions: s.sessions,
	})
	if err != nil {
		return err
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	data := s.aead.Seal(nonce, nonce, plaintext, oidcSessionFileAAD)

	// Written to a temporary file first so that a crash can't leave behind a truncated file
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".glance-oidc-sessions-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), s.path)
}

// Stores a new session and returns its ID
func (s *oidcSessionStore) create(session *oidcSession) (string, error) {
	id, err := randomURLSafeString(AUTH_OIDC_SESSION_ID_LENGTH)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[hashOIDCSessionID(id)] = session
	s.save()

	return id, nil
}

// Returns a copy of the session, or nil if it doesn't exist
func (s *oidcSessionStore) get(id string) *oidcSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[hashOIDCSessionID(id)]
	if !ok {
		return nil
	}

	copied := *session
	return &copied
}

// Replaces an existing session, returns false if it has been deleted in the meantime
func (s *oidcSessionStore) replace(id string, session *oidcSession, persist bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashOIDCSessionID(id)
	if _, ok := s.sessions[key]; !ok {
		return false
	}

	s.sessions[key] = session
	if persist {
		s.save()
	}

	return true
}

func (s *oidcSessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashOIDCSessionID(id)
	if _, ok := s.sessions[key]; !ok {
		return
	}

	delete(s.sessions, key)
	delete(s.locks, key)
	s.save()
}

// Serializes rechecks of a single session. Some providers rotate refresh tokens and
// reject reuse of an old one, so concurrent refreshes would end up revoking the session.
func (s *oidcSessionStore) lock(id string) func() {
	s.mu.Lock()
	key := hashOIDCSessionID(id)
	l, ok := s.locks[key]
	if !ok {
		l = &sync.Mutex{}
		s.locks[key] = l
	}
	s.mu.Unlock()

	l.Lock()
	return l.Unlock
}
