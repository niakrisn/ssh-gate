package main

import (
	"embed"
	"encoding/json"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed ui/*
var uiFS embed.FS

// connectionsResponse is the body of GET /api/connections.
type connectionsResponse struct {
	Total    int        `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Items    []ConnView `json:"items"`
}

// handleConnections serves a page of connections: tab=active|history,
// q is a host substring, proto is an exact protocol filter, page,
// page_size (1..200).
func handleConnections(tracker *ConnTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		qp := r.URL.Query()
		tab := qp.Get("tab")
		if tab == "" {
			tab = "active"
		}
		page := 1
		if v := qp.Get("page"); v != "" {
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 {
				http.Error(w, "invalid page", http.StatusBadRequest)
				return
			}
			page = p
		}
		pageSize := 50
		if v := qp.Get("page_size"); v != "" {
			ps, err := strconv.Atoi(v)
			if err != nil || ps < 1 || ps > 200 {
				http.Error(w, "invalid page_size", http.StatusBadRequest)
				return
			}
			pageSize = ps
		}

		var items []ConnView
		var total int
		if tracker != nil {
			var err error
			items, total, err = tracker.List(tab, qp.Get("q"), qp.Get("proto"), page, pageSize)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if items == nil {
			items = []ConnView{} // keep "items" a JSON array, not null
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(connectionsResponse{
			Total:    total,
			Page:     page,
			PageSize: pageSize,
			Items:    items,
		}); err != nil {
			// client went away; nothing to report.
		}
	}
}

// handleUI serves the embedded UI: / is index.html, other paths are files
// from ui/ (app.js, style.css); unknown paths get 404. Path traversal is not
// a concern: embed.FS refuses names outside its root.
func handleUI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	name := strings.TrimPrefix(path, "/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	data, err := uiFS.ReadFile("ui/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Content type by extension: DetectContentType cannot tell css/js apart.
	if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Write(data)
}
