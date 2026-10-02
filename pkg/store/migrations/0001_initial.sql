CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	is_admin      INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT NOT NULL
);

CREATE TABLE tasks (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'in_progress',
	assigned_to INTEGER NOT NULL REFERENCES users(id),
	created_by  INTEGER NOT NULL REFERENCES users(id),
	created_at  TEXT NOT NULL
);

CREATE INDEX idx_tasks_assigned_to ON tasks(assigned_to);
CREATE INDEX idx_tasks_created_by ON tasks(created_by);