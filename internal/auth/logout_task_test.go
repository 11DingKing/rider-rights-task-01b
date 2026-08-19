package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestLogoutRevocationSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	st, err := Open(path, testUsers()...)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	_, token, _, err := st.Login("prosecutor", "test-prosecutor-password", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Logout(token, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Resolve(token, now.Add(2*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected persisted revocation, got %v", err)
	}
}
