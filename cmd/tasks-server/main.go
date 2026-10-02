package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"tasks-demo/pkg/httpapi"
	"tasks-demo/pkg/store"
)

const (
	defaultAddr        = ":8080"
	defaultDBPath      = "db/tasks.db"
	defaultReportsPath = "reports"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := os.Getenv("TASKS_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	dbPath := os.Getenv("TASKS_DB_PATH")
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	reportsPath := os.Getenv("TASKS_REPORTS_PATH")
	if reportsPath == "" {
		reportsPath = defaultReportsPath
	}

	db, err := store.Open(context.Background(), dbPath, os.Stdout)
	if err != nil {
		return err
	}
	defer db.Close()

	log.Printf("tasks-server listening on %s (db: %s)", addr, db.Location())
	return http.ListenAndServe(addr, httpapi.New(db, reportsPath))
}
