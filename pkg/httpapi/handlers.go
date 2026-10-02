package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tasks-demo/pkg/store"
)

// handleLogin authenticates a user by username and password and returns a
// bearer token to be used on subsequent requests.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), body.Username)
	if err != nil || !store.CheckPassword(user.PasswordHash, body.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := s.tokens.issue(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
	})
}

// handleCreateUser creates a new user with a randomly generated password that
// is returned in the response. Admins only.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if user == nil || !user.IsAdmin {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	var body struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	password, err := store.RandomPassword(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate password")
		return
	}
	passwordHash, err := store.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}

	created, err := s.store.CreateUser(r.Context(), body.Username, passwordHash, body.IsAdmin)
	if errors.Is(err, store.ErrExists) {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"user":     created,
		"password": password,
	})
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.store.ListTasks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list tasks")
		return
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "task name is required")
		return
	}

	user := userFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	task, err := s.store.CreateTask(r.Context(), body.Name, user.ID, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create task")
		return
	}
	writeJSON(w, http.StatusCreated, task)
}

func (s *Server) handleMarkTaskDone(w http.ResponseWriter, r *http.Request) {
	id, err := taskID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid task id")
		return
	}

	task, err := s.store.UpdateTaskStatus(r.Context(), id, store.StatusDone)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update task")
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// handleAssignTask reassigns a task to another user. Admins only.
func (s *Server) handleAssignTask(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	id, err := taskID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid task id")
		return
	}

	var body struct {
		AssignedTo string `json:"assigned_to"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.AssignedTo = strings.TrimSpace(body.AssignedTo)
	if body.AssignedTo == "" {
		writeError(w, http.StatusBadRequest, "assigned_to is required")
		return
	}

	target, err := s.store.GetUserByUsername(r.Context(), body.AssignedTo)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	task, err := s.store.AssignTask(r.Context(), id, target.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not assign task")
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// handleDeleteTask removes a task. Admins only.
func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if user == nil || !user.IsAdmin {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	id, err := taskID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid task id")
		return
	}

	if err := s.store.DeleteTask(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "task not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete task")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReportsList lists the report files in s.reportsPath/{category} where
// category is provided in the JSON request body.
func (s *Server) handleReportsList(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Category string `json:"category"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Category = strings.TrimSpace(body.Category)
	if body.Category == "" {
		writeError(w, http.StatusBadRequest, "category is required")
		return
	}

	entries, err := os.ReadDir(filepath.Join(s.reportsPath, body.Category))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "category not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list reports")
		return
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

// taskID parses the task id path parameter.
func taskID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

// decodeBody decodes a JSON request body, rejecting oversized payloads.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}
