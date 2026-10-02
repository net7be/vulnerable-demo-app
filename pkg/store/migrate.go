package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migration is a single versioned schema change.
type migration struct {
	version int
	name    string
	sql     string
}

// initialVersion is the version of the "initial" migration that bootstraps
// the database and its default admin user.
const initialVersion = 1

// loadMigrations returns the embedded migrations sorted by version.
func loadMigrations() ([]migration, error) {
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("glob migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		base := filepath.Base(entry)
		name := strings.TrimSuffix(base, ".sql")

		versionPart := name
		if i := strings.IndexByte(name, '_'); i >= 0 {
			versionPart = name[:i]
		}
		version, err := strconv.Atoi(versionPart)
		if err != nil {
			return nil, fmt.Errorf("migration %q: invalid version prefix: %w", base, err)
		}

		content, err := migrationFiles.ReadFile(entry)
		if err != nil {
			return nil, fmt.Errorf("migration %q: %w", base, err)
		}

		migrations = append(migrations, migration{
			version: version,
			name:    name,
			sql:     string(content),
		})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	return migrations, nil
}

// migrate creates the version tracking table if needed and applies all
// migrations more recent than the current database version. It returns true
// if the initial migration was applied during this call.
func (d *DB) migrate(ctx context.Context) (bool, error) {
	if _, err := d.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`); err != nil {
		return false, fmt.Errorf("create schema_migrations table: %w", err)
	}

	current, err := d.appliedVersion(ctx)
	if err != nil {
		return false, err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return false, err
	}

	initialApplied := false
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := d.applyMigration(ctx, m); err != nil {
			return false, fmt.Errorf("apply migration %d (%s): %w", m.version, m.name, err)
		}
		if m.version == initialVersion {
			initialApplied = true
		}
	}
	return initialApplied, nil
}

// appliedVersion returns the highest currently applied migration version, or
// 0 when the database has no applied migrations yet.
func (d *DB) appliedVersion(ctx context.Context) (int, error) {
	var version int
	err := d.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("read applied migrations: %w", err)
	}
	return version, nil
}

// applyMigration executes a migration and records its version atomically.
func (d *DB) applyMigration(ctx context.Context, m migration) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
