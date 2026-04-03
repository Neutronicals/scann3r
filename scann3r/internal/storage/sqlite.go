// Package storage provides the SQLite persistence layer for scan results.
// It uses WAL mode for high‑concurrency read access while serializing writes
// through a single dedicated goroutine.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/venom-scanner/venom/internal/models"
)

// DB wraps the SQLite connection and provides typed CRUD operations.
type DB struct {
	conn *sql.DB
	mu   sync.Mutex // serialize writes
}

// Open creates or opens the SQLite database at the given path and runs migrations.
func Open(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Connection pool settings suitable for a scanner
	conn.SetMaxOpenConns(1)  // SQLite is single‑writer anyway
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(0) // keep connections alive

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return db, nil
}

// Close shuts down the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// RawDB returns the underlying *sql.DB for direct queries (read-only).
func (db *DB) RawDB() *sql.DB {
	return db.conn
}

// migrate creates the schema tables if they don't exist.
func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id          TEXT PRIMARY KEY,
		target      TEXT NOT NULL,
		started_at  DATETIME NOT NULL,
		finished_at DATETIME,
		config      TEXT,
		status      TEXT DEFAULT 'running',
		urls_found       INTEGER DEFAULT 0,
		js_files_found   INTEGER DEFAULT 0,
		forms_found      INTEGER DEFAULT 0,
		params_found     INTEGER DEFAULT 0,
		requests_sent    INTEGER DEFAULT 0,
		errors           INTEGER DEFAULT 0,
		waf_blocks       INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id       TEXT NOT NULL REFERENCES scans(id),
		url           TEXT NOT NULL,
		method        TEXT DEFAULT 'GET',
		status_code   INTEGER,
		content_type  TEXT,
		response_size INTEGER,
		depth         INTEGER,
		source        TEXT,
		discovered_at DATETIME,
		UNIQUE(scan_id, url, method)
	);

	CREATE TABLE IF NOT EXISTS parameters (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
		name        TEXT NOT NULL,
		location    TEXT NOT NULL,
		sample_value TEXT,
		UNIQUE(endpoint_id, name, location)
	);

	CREATE TABLE IF NOT EXISTS findings (
		id                 TEXT PRIMARY KEY,
		scan_id            TEXT NOT NULL REFERENCES scans(id),
		url                TEXT NOT NULL,
		method             TEXT,
		parameter          TEXT,
		parameter_location TEXT,
		type               TEXT NOT NULL,
		severity           TEXT NOT NULL,
		payload            TEXT,
		mutation_strategy  TEXT,
		evidence           TEXT,
		confidence         REAL,
		found_at           DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// ---------------------------------------------------------------------------
// Scan CRUD
// ---------------------------------------------------------------------------

// CreateScan inserts a new scan record.
func (db *DB) CreateScan(ctx context.Context, scanID, target string, cfgJSON []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.ExecContext(ctx,
		`INSERT INTO scans (id, target, started_at, config, status) VALUES (?, ?, ?, ?, 'running')`,
		scanID, target, time.Now(), string(cfgJSON),
	)
	return err
}

// FinishScan marks a scan as completed/interrupted and writes final stats.
func (db *DB) FinishScan(ctx context.Context, scanID string, stats *models.ScanStats) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	status := stats.Status
	if status == "" {
		status = "completed"
	}

	_, err := db.conn.ExecContext(ctx,
		`UPDATE scans SET 
			finished_at = ?, status = ?,
			urls_found = ?, js_files_found = ?, forms_found = ?,
			params_found = ?, requests_sent = ?, errors = ?, waf_blocks = ?
		WHERE id = ?`,
		time.Now(), status,
		stats.URLsFound.Load(), stats.JSFilesFound.Load(), stats.FormsFound.Load(),
		stats.ParametersFound.Load(), stats.RequestsSent.Load(),
		stats.Errors.Load(), stats.WAFBlocks.Load(),
		scanID,
	)
	return err
}

// ---------------------------------------------------------------------------
// Endpoint CRUD
// ---------------------------------------------------------------------------

// InsertEndpoint upserts a discovered endpoint.
func (db *DB) InsertEndpoint(ctx context.Context, scanID string, result *models.CrawlResult) (int64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	res, err := db.conn.ExecContext(ctx,
		`INSERT OR IGNORE INTO endpoints (scan_id, url, method, status_code, content_type, response_size, depth, source, discovered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, result.URL, result.Method, result.StatusCode,
		result.ContentType, len(result.Body), result.Depth,
		result.Source, result.DiscoveredAt,
	)
	if err != nil {
		return 0, err
	}

	id, _ := res.LastInsertId()
	if id == 0 {
		// Was a duplicate — look up existing ID
		row := db.conn.QueryRowContext(ctx,
			`SELECT id FROM endpoints WHERE scan_id = ? AND url = ? AND method = ?`,
			scanID, result.URL, result.Method,
		)
		row.Scan(&id)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Parameter CRUD
// ---------------------------------------------------------------------------

// InsertParameter upserts a discovered parameter.
func (db *DB) InsertParameter(ctx context.Context, endpointID int64, param models.Parameter) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.ExecContext(ctx,
		`INSERT OR IGNORE INTO parameters (endpoint_id, name, location, sample_value) VALUES (?, ?, ?, ?)`,
		endpointID, param.Name, param.Location, param.Value,
	)
	return err
}

// ---------------------------------------------------------------------------
// Finding CRUD
// ---------------------------------------------------------------------------

// InsertFinding persists a vulnerability finding.
func (db *DB) InsertFinding(ctx context.Context, scanID string, f *models.Finding) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.ExecContext(ctx,
		`INSERT OR IGNORE INTO findings 
			(id, scan_id, url, method, parameter, parameter_location, type, severity, payload, mutation_strategy, evidence, confidence, found_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, scanID, f.URL, f.Method, f.Parameter, f.ParameterLocation,
		f.Type, f.Severity, f.Payload, f.MutationStrategy,
		f.Evidence, f.Confidence, f.FoundAt,
	)
	return err
}

// GetFindings returns all findings for a scan, ordered by severity.
func (db *DB) GetFindings(ctx context.Context, scanID string) ([]*models.Finding, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT id, url, method, parameter, parameter_location, type, severity, payload, mutation_strategy, evidence, confidence, found_at
		 FROM findings WHERE scan_id = ?
		 ORDER BY CASE severity
			WHEN 'critical' THEN 1
			WHEN 'high'     THEN 2
			WHEN 'medium'   THEN 3
			WHEN 'low'      THEN 4
			ELSE 5
		 END, found_at DESC`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*models.Finding
	for rows.Next() {
		f := &models.Finding{ScanID: scanID}
		err := rows.Scan(&f.ID, &f.URL, &f.Method, &f.Parameter,
			&f.ParameterLocation, &f.Type, &f.Severity, &f.Payload,
			&f.MutationStrategy, &f.Evidence, &f.Confidence, &f.FoundAt)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// GetScanSummary returns a JSON-encodable summary of a scan.
func (db *DB) GetScanSummary(ctx context.Context, scanID string) (map[string]interface{}, error) {
	row := db.conn.QueryRowContext(ctx,
		`SELECT target, started_at, finished_at, status,
			urls_found, js_files_found, forms_found, params_found,
			requests_sent, errors, waf_blocks
		 FROM scans WHERE id = ?`, scanID,
	)

	var target, status string
	var startedAt time.Time
	var finishedAt sql.NullTime
	var urlsFound, jsFound, formsFound, paramsFound, reqSent, errors, wafBlocks int64

	err := row.Scan(&target, &startedAt, &finishedAt, &status,
		&urlsFound, &jsFound, &formsFound, &paramsFound,
		&reqSent, &errors, &wafBlocks)
	if err != nil {
		return nil, err
	}

	// Count findings by severity
	sevRows, err := db.conn.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity`, scanID)
	if err != nil {
		return nil, err
	}
	defer sevRows.Close()

	sevCounts := make(map[string]int64)
	for sevRows.Next() {
		var sev string
		var count int64
		sevRows.Scan(&sev, &count)
		sevCounts[sev] = count
	}

	summary := map[string]interface{}{
		"scan_id":        scanID,
		"target":         target,
		"started_at":     startedAt,
		"finished_at":    finishedAt.Time,
		"status":         status,
		"urls_found":     urlsFound,
		"js_files_found": jsFound,
		"forms_found":    formsFound,
		"params_found":   paramsFound,
		"requests_sent":  reqSent,
		"errors":         errors,
		"waf_blocks":     wafBlocks,
		"findings":       sevCounts,
	}

	return summary, nil
}

// ExportFindingsJSON returns all findings as a JSON byte slice.
func (db *DB) ExportFindingsJSON(ctx context.Context, scanID string) ([]byte, error) {
	summary, err := db.GetScanSummary(ctx, scanID)
	if err != nil {
		return nil, err
	}
	findings, err := db.GetFindings(ctx, scanID)
	if err != nil {
		return nil, err
	}

	export := map[string]interface{}{
		"scan":     summary,
		"findings": findings,
	}

	return json.MarshalIndent(export, "", "  ")
}
