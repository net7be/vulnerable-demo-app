package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"tasks-demo/pkg/store"
)

// Server implements the tasks JSON API on top of a store.Store.
type Server struct {
	store       store.Store
	tokens      *tokenStore
	mux         *http.ServeMux
	reportsPath string
}

// New builds the HTTP handler exposing the tasks API.
func New(st store.Store, reportsPath string) http.Handler {
	s := &Server{
		store:       st,
		tokens:      newTokenStore(),
		mux:         http.NewServeMux(),
		reportsPath: reportsPath,
	}

	// Public routes.
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.Handle("GET /api/tasks", http.HandlerFunc(s.handleListTasks))
	s.mux.Handle("GET /reports", http.HandlerFunc(s.handleReportsList))

	// Authenticated routes.
	s.mux.Handle("POST /api/tasks", s.requireAuth(http.HandlerFunc(s.handleCreateTask)))
	s.mux.Handle("POST /api/users", s.requireAuth(http.HandlerFunc(s.handleCreateUser)))
	s.mux.Handle("POST /api/tasks/{id}/done", s.requireAuth(http.HandlerFunc(s.handleMarkTaskDone)))
	s.mux.Handle("POST /api/tasks/{id}/assign", s.requireAuth(http.HandlerFunc(s.handleAssignTask)))
	s.mux.Handle("DELETE /api/tasks/{id}", s.requireAuth(http.HandlerFunc(s.handleDeleteTask)))

	return logRequests(s.mux)
}

// requireAuth authenticates the request and stores the current user in the
// request context; unauthenticated requests are rejected with 401.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := s.currentUser(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), userKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// currentUser resolves the user for a request from its Authorization header.
func (s *Server) currentUser(r *http.Request) (*store.User, error) {
	token, ok := bearerToken(r)
	if !ok {
		return nil, errors.New("missing bearer token")
	}
	userID, ok := s.tokens.lookup(token)
	if !ok {
		return nil, errors.New("invalid or expired token")
	}
	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// userFromContext returns the current user or nil.
func userFromContext(ctx context.Context) *store.User {
	if u, ok := ctx.Value(userKey{}).(*store.User); ok {
		return u
	}
	return nil
}

type userKey struct{}

type logResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *logResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *logResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lw := &logResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lw, r)
		log.Printf("%s %s - %d", r.Method, r.URL.Path, lw.status)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
