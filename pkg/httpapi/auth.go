package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

// tokenStore keeps an in-memory map of issued bearer tokens to user IDs.
type tokenStore struct {
	mu     sync.Mutex
	tokens map[string]int64
}

func newTokenStore() *tokenStore {
	return &tokenStore{tokens: make(map[string]int64)}
}

// issue creates a new random bearer token for the given user.
func (ts *tokenStore) issue(userID int64) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tokens[token] = userID
	return token, nil
}

func (ts *tokenStore) lookup(token string) (int64, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	userID, ok := ts.tokens[token]
	return userID, ok
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	return token, token != ""
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
