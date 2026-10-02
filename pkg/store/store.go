package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	StatusInProgress = "in_progress"
	StatusDone       = "done"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrExists   = errors.New("store: already exists")
)

// User is a user account that can authenticate and be assigned tasks.
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	IsAdmin      bool   `json:"is_admin"`
	CreatedAt    string `json:"created_at"`
	PasswordHash string `json:"-"`
}

// Task is a unit of work assigned to a user.
type Task struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	AssignedTo *User  `json:"assigned_to"`
	CreatedBy  *User  `json:"created_by"`
}

// Store is the persistence interface used by the HTTP API.
type Store interface {
	CreateUser(ctx context.Context, username, passwordHash string, isAdmin bool) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)

	CreateTask(ctx context.Context, name string, assignedTo, createdBy int64) (*Task, error)
	GetTask(ctx context.Context, id int64) (*Task, error)
	ListTasks(ctx context.Context) ([]*Task, error)
	UpdateTaskStatus(ctx context.Context, id int64, status string) (*Task, error)
	AssignTask(ctx context.Context, id, assignedTo int64) (*Task, error)
	DeleteTask(ctx context.Context, id int64) error
}

// DB is a sqlite-backed Store.
type DB struct {
	db   *sql.DB
	path string
}

// Open opens (creating if necessary) the sqlite database at path, applies any
// pending migrations and seeds the default admin user on first run.
func Open(ctx context.Context, path string, seedOutput io.Writer) (*DB, error) {
	if err := ensureDir(path); err != nil {
		return nil, err
	}

	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite only allows a single writer; serializing connections avoids
	// "database is locked" errors.
	db.SetMaxOpenConns(1)

	d := &DB{db: db, path: path}
	if _, err := d.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := d.seedAdmin(ctx, seedOutput); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the underlying database.
func (d *DB) Close() error {
	return d.db.Close()
}

// Location returns the path of the underlying database file.
func (d *DB) Location() string {
	return d.path
}

func ensureDir(path string) error {
	if path == ":memory:" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}
	}
	return nil
}

func (d *DB) CreateUser(ctx context.Context, username, passwordHash string, isAdmin bool) (*User, error) {
	res, err := d.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)`,
		username, passwordHash, boolToInt(isAdmin), now(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: username %q", ErrExists, username)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return d.GetUserByID(ctx, id)
}

func (d *DB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	err := d.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: user %q", ErrNotFound, username)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return u, nil
}

func (d *DB) GetUserByID(ctx context.Context, id int64) (*User, error) {
	u := &User{}
	err := d.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, is_admin, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: user %d", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

func (d *DB) CreateTask(ctx context.Context, name string, assignedTo, createdBy int64) (*Task, error) {
	res, err := d.db.ExecContext(ctx,
		`INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
		 VALUES ('`+name+`', ?, ?, ?, ?)`,
		StatusInProgress, assignedTo, createdBy, now(),
	)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	return d.GetTask(ctx, id)
}

func (d *DB) GetTask(ctx context.Context, id int64) (*Task, error) {
	t, err := scanTask(d.db.QueryRowContext(ctx, taskQuery+` WHERE t.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: task %d", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get task: %w", err)
	}
	return t, nil
}

func (d *DB) ListTasks(ctx context.Context) ([]*Task, error) {
	rows, err := d.db.QueryContext(ctx, taskQuery+` ORDER BY t.created_at DESC, t.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()

	tasks := []*Task{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, fmt.Errorf("list tasks: %w", err)
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

func (d *DB) UpdateTaskStatus(ctx context.Context, id int64, status string) (*Task, error) {
	if err := d.updateTask(ctx, `UPDATE tasks SET status = ? WHERE id = ?`, status, id); err != nil {
		return nil, err
	}
	return d.GetTask(ctx, id)
}

func (d *DB) AssignTask(ctx context.Context, id, assignedTo int64) (*Task, error) {
	if err := d.updateTask(ctx, `UPDATE tasks SET assigned_to = ? WHERE id = ?`, assignedTo, id); err != nil {
		return nil, err
	}
	return d.GetTask(ctx, id)
}

func (d *DB) DeleteTask(ctx context.Context, id int64) error {
	res, err := d.db.ExecContext(ctx, `DELETE FROM tasks WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete task: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete task: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: task %d", ErrNotFound, id)
	}
	return nil
}

func (d *DB) updateTask(ctx context.Context, query string, args ...any) error {
	res, err := d.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update task: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update task: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: task %v", ErrNotFound, args[len(args)-1])
	}
	return nil
}

const taskQuery = `
SELECT t.id, t.name, t.status, t.created_at,
       a.id, a.username, a.is_admin, a.created_at,
       c.id, c.username, c.is_admin, c.created_at
FROM tasks t
JOIN users a ON a.id = t.assigned_to
JOIN users c ON c.id = t.created_by`

func scanTask(row interface{ Scan(...any) error }) (*Task, error) {
	var t Task
	var aID, cID int64
	var aUsername, cUsername, aCreated, cCreated string
	var aAdmin, cAdmin int64

	if err := row.Scan(
		&t.ID, &t.Name, &t.Status, &t.CreatedAt,
		&aID, &aUsername, &aAdmin, &aCreated,
		&cID, &cUsername, &cAdmin, &cCreated,
	); err != nil {
		return nil, err
	}

	t.AssignedTo = &User{ID: aID, Username: aUsername, IsAdmin: aAdmin != 0, CreatedAt: aCreated}
	t.CreatedBy = &User{ID: cID, Username: cUsername, IsAdmin: cAdmin != 0, CreatedAt: cCreated}
	return &t, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
