package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fatih/semgroup"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
	"github.com/zricethezav/gitleaks/v8/version"
)

// Request/response DTOs for /scan
type serverScanRequest struct {
	Path           string `json:"path"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
}

type serverScanResponse struct {
	Path     string           `json:"path"`
	Count    int              `json:"count"`
	Findings []report.Finding `json:"findings"`
	Error    string           `json:"error,omitempty"`
}

var (
	serverAddr string
)

// gitleaks server --addr :8080
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run gitleaks as a long-lived HTTP server",
	Long:  "Run gitleaks as a long-lived HTTP server that exposes /scan for path-based scans.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Reuse existing init logic from root.go
		initLog()

		// Important: treat this as a dev build so config doesn't try to parse "" as a semver
		if version.Version == "" {
			version.Version = version.DefaultMsg
		}

		initConfig(".")

		// Reuse existing config helper
		cfg := Config(cmd)

		// Build detector like other commands do
		// The 'source' string here is only used for config path resolution
		// detector := Detector(cmd, cfg, ".")

		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		})
		mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
			// Build detector like other commands do for each request
			det := Detector(cmd, cfg, ".")
			handleScan(w, r, det)
		})

		log.Printf("gitleaks server listening on %s", serverAddr)
		return http.ListenAndServe(serverAddr, mux)
	},
}

// init is automatically called and will register the command with rootCmd
func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVar(&serverAddr, "addr", ":8080", "HTTP listen address for server mode")
}

func handleScan(w http.ResponseWriter, r *http.Request, det *detect.Detector) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, serverScanResponse{
			Error: "only POST is allowed",
		})
		return
	}

	var req serverScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, serverScanResponse{
			Error: "invalid JSON body",
		})
		return
	}
	if req.Path == "" {
		writeJSON(w, http.StatusBadRequest, serverScanResponse{
			Error: "path is required",
		})
		return
	}

	// 👉 NEW: Check if path exists and is readable
	info, err := os.Stat(req.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, serverScanResponse{
			Path:  req.Path,
			Error: "path is not accessible: " + err.Error(),
		})
		return
	}

	// NEW: Check permissions / readability
	if file, err := os.Open(req.Path); err != nil {
		writeJSON(w, http.StatusForbidden, serverScanResponse{
			Path:  req.Path,
			Error: "permission denied or path not readable: " + err.Error(),
		})
		return
	} else {
		file.Close()
	}

	// NEW: Check type: must be file OR directory
	if !info.Mode().IsDir() && !info.Mode().IsRegular() {
		writeJSON(w, http.StatusBadRequest, serverScanResponse{
			Path:  req.Path,
			Error: "path must be a file or directory",
		})
		return
	}

	ctx := r.Context()
	if req.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	findings, err := scanFilesPath(ctx, det, req.Path)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, serverScanResponse{
				Path:  req.Path,
				Error: "scan timed out",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, serverScanResponse{
			Path:  req.Path,
			Error: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, serverScanResponse{
		Path:     req.Path,
		Count:    len(findings),
		Findings: findings,
	})
}

// Reuse Gitleaks engine against a directory or file path
func scanFilesPath(ctx context.Context, det *detect.Detector, path string) ([]report.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsDir() && !info.Mode().IsRegular() {
		return nil, errors.New("path must be a file or directory")
	}

	src := &sources.Files{
		Config:          &det.Config,
		Path:            path,
		FollowSymlinks:  det.FollowSymlinks,
		MaxFileSize:     det.MaxTargetMegaBytes,
		MaxArchiveDepth: det.MaxArchiveDepth,
		Sema:            semgroup.NewGroup(ctx, 8),
	}

	return det.DetectSource(ctx, src)
}

// small helper – you can reuse the one from your earlier server example
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
