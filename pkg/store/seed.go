package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
)

const defaultAdminUsername = "admin"

// seedAdmin creates the default admin user with a randomly generated password
// the first time the database is initialised. The password is written to the
// provided output so it can be shown in the console.
func (d *DB) seedAdmin(ctx context.Context, out io.Writer) error {
	var count int
	err := d.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE username = ?`, defaultAdminUsername,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check default admin: %w", err)
	}
	if count > 0 {
		return nil
	}

	password, err := RandomPassword(16)
	if err != nil {
		return fmt.Errorf("generate admin password: %w", err)
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	if _, err := d.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)`,
		defaultAdminUsername, passwordHash, now(),
	); err != nil {
		return fmt.Errorf("create default admin: %w", err)
	}

	fmt.Fprintf(out, "Initialized database, created default admin user:\n")
	fmt.Fprintf(out, "  username: %s\n", defaultAdminUsername)
	fmt.Fprintf(out, "  password: %s\n", password)
	fmt.Fprintf(out, "  (please store it safely; it will not be shown again)\n")
	return nil
}

// RandomPassword generates a cryptographically random alphanumeric password.
func RandomPassword(length int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = alphabet[int(bytes[i])%len(alphabet)]
	}
	return string(bytes), nil
}
