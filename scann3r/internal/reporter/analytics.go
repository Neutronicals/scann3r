package reporter

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/venom-scanner/venom/internal/storage"
)

// AnalyticsDashboard generates a self-contained interactive HTML analytics
// dashboard with charts, heatmaps, and filterable tables.
type AnalyticsDashboard struct {
	db     *storage.DB
	scanID string // empty = all scans
}

// NewAnalyticsDashboard creates a dashboard generator.
func NewAnalyticsDashboard(db *storage.DB, scanID string) *AnalyticsDashboard {
	return &AnalyticsDashboard{db: db, scanID: scanID}
}

// analyticsData holds all the pre-computed data for the dashboard.
type analyticsData struct {
	GeneratedAt     string                   `json:"generated_at"`
	ScanID          string                   `json:"scan_id"`
	TotalFindings   int                      `json:"total_findings"`
	TotalEndpoints  int                      `json:"total_endpoints"`
	TotalParameters int                      `json:"total_parameters"`
	TotalScans      int                      `json:"total_scans"`
	SeverityCounts  map[string]int           `json:"severity_counts"`
	TypeCounts      map[string]int           `json:"type_counts"`
	TypeBySeverity  map[string]map[string]int `json:"type_by_severity"`
	TopEndpoints    []endpointStat           `json:"top_endpoints"`
	TopParameters   []paramStat              `json:"top_parameters"`
	MutationStats   []mutationStat           `json:"mutation_stats"`
	ConfidenceDist  []confBucket             `json:"confidence_distribution"`
	Timeline        []timePoint              `json:"timeline"`
	Findings        []findingRow             `json:"findings"`
	Scans           []scanSummary            `json:"scans"`
	RiskScore       float64                  `json:"risk_score"`
	RiskLabel       string                   `json:"risk_label"`
}

type endpointStat struct {
	URL      string `json:"url"`
	Count    int    `json:"count"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type paramStat struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Count    int    `json:"count"`
	Types    string `json:"types"`
}

type mutationStat struct {
	Strategy string  `json:"strategy"`
	Count    int     `json:"count"`
	Percent  float64 `json:"percent"`
}

type confBucket struct {
	Range string `json:"range"`
	Count int    `json:"count"`
}

type timePoint struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
}

type findingRow struct {
	ID        string  `json:"id"`
	URL       string  `json:"url"`
	Method    string  `json:"method"`
	Param     string  `json:"param"`
	ParamLoc  string  `json:"param_loc"`
	Type      string  `json:"type"`
	Severity  string  `json:"severity"`
	Payload   string  `json:"payload"`
	Mutation  string  `json:"mutation"`
	Evidence  string  `json:"evidence"`
	Confidence float64 `json:"confidence"`
	FoundAt   string  `json:"found_at"`
}

type scanSummary struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	StartedAt string `json:"started_at"`
	Status    string `json:"status"`
	URLsFound int    `json:"urls_found"`
	Requests  int    `json:"requests"`
	Findings  int    `json:"findings"`
}

// Generate builds the analytics dashboard and writes it to outputPath.
func (a *AnalyticsDashboard) Generate(ctx context.Context, outputPath string) error {
	data, err := a.collectData(ctx)
	if err != nil {
		return fmt.Errorf("collecting analytics data: %w", err)
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling data: %w", err)
	}

	html := buildAnalyticsDashboard(string(dataJSON))

	if outputPath == "" {
		outputPath = "scann3r_analysis.html"
	}

	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("writing dashboard: %w", err)
	}

	return nil
}

// collectData queries the database and builds the analytics dataset.
func (a *AnalyticsDashboard) collectData(ctx context.Context) (*analyticsData, error) {
	conn := a.db.RawDB()
	data := &analyticsData{
		GeneratedAt:    time.Now().Format("2006-01-02 15:04:05"),
		ScanID:         a.scanID,
		SeverityCounts: make(map[string]int),
		TypeCounts:     make(map[string]int),
		TypeBySeverity: make(map[string]map[string]int),
	}

	scanFilter := ""
	var args []interface{}
	if a.scanID != "" {
		scanFilter = " WHERE scan_id = ?"
		args = []interface{}{a.scanID}
	}

	// --- Scan summaries ---
	scanRows, err := conn.QueryContext(ctx,
		`SELECT s.id, s.target, s.started_at, s.status, s.urls_found, s.requests_sent,
		 (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as finding_count
		 FROM scans s ORDER BY s.started_at DESC`)
	if err == nil {
		defer scanRows.Close()
		for scanRows.Next() {
			var s scanSummary
			var startedAt time.Time
			scanRows.Scan(&s.ID, &s.Target, &startedAt, &s.Status, &s.URLsFound, &s.Requests, &s.Findings)
			s.StartedAt = startedAt.Format("2006-01-02 15:04")
			data.Scans = append(data.Scans, s)
		}
	}
	data.TotalScans = len(data.Scans)

	// --- Total counts ---
	conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings"+scanFilter, args...).Scan(&data.TotalFindings)
	conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM endpoints"+scanFilter, args...).Scan(&data.TotalEndpoints)

	paramQuery := "SELECT COUNT(*) FROM parameters"
	if a.scanID != "" {
		paramQuery = "SELECT COUNT(*) FROM parameters p JOIN endpoints e ON p.endpoint_id = e.id WHERE e.scan_id = ?"
	}
	conn.QueryRowContext(ctx, paramQuery, args...).Scan(&data.TotalParameters)

	// --- Severity counts ---
	sevRows, err := conn.QueryContext(ctx,
		"SELECT severity, COUNT(*) FROM findings"+scanFilter+" GROUP BY severity", args...)
	if err == nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var sev string
			var count int
			sevRows.Scan(&sev, &count)
			data.SeverityCounts[sev] = count
		}
	}

	// --- Type counts ---
	typeRows, err := conn.QueryContext(ctx,
		"SELECT type, COUNT(*) FROM findings"+scanFilter+" GROUP BY type ORDER BY COUNT(*) DESC", args...)
	if err == nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var typ string
			var count int
			typeRows.Scan(&typ, &count)
			data.TypeCounts[typ] = count
		}
	}

	// --- Type × Severity matrix ---
	matrixRows, err := conn.QueryContext(ctx,
		"SELECT type, severity, COUNT(*) FROM findings"+scanFilter+" GROUP BY type, severity", args...)
	if err == nil {
		defer matrixRows.Close()
		for matrixRows.Next() {
			var typ, sev string
			var count int
			matrixRows.Scan(&typ, &sev, &count)
			if data.TypeBySeverity[typ] == nil {
				data.TypeBySeverity[typ] = make(map[string]int)
			}
			data.TypeBySeverity[typ][sev] = count
		}
	}

	// --- Top 15 vulnerable endpoints ---
	epQuery := `SELECT url, COUNT(*) as cnt,
		SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),
		SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END)
		FROM findings` + scanFilter + ` GROUP BY url ORDER BY cnt DESC LIMIT 15`
	epRows, err := conn.QueryContext(ctx, epQuery, args...)
	if err == nil {
		defer epRows.Close()
		for epRows.Next() {
			var ep endpointStat
			epRows.Scan(&ep.URL, &ep.Count, &ep.Critical, &ep.High)
			data.TopEndpoints = append(data.TopEndpoints, ep)
		}
	}

	// --- Top 15 vulnerable parameters ---
	pmQuery := `SELECT parameter, parameter_location, COUNT(*) as cnt,
		GROUP_CONCAT(DISTINCT type) as types
		FROM findings` + scanFilter + ` WHERE parameter != ''
		GROUP BY parameter, parameter_location ORDER BY cnt DESC LIMIT 15`
	pmRows, err := conn.QueryContext(ctx, pmQuery, args...)
	if err == nil {
		defer pmRows.Close()
		for pmRows.Next() {
			var p paramStat
			var typesNull sql.NullString
			pmRows.Scan(&p.Name, &p.Location, &p.Count, &typesNull)
			if typesNull.Valid {
				p.Types = typesNull.String
			}
			data.TopParameters = append(data.TopParameters, p)
		}
	}

	// --- Mutation strategy effectiveness ---
	mutQuery := `SELECT mutation_strategy, COUNT(*) FROM findings` + scanFilter +
		` WHERE mutation_strategy != '' GROUP BY mutation_strategy ORDER BY COUNT(*) DESC`
	mutRows, err := conn.QueryContext(ctx, mutQuery, args...)
	if err == nil {
		defer mutRows.Close()
		for mutRows.Next() {
			var m mutationStat
			mutRows.Scan(&m.Strategy, &m.Count)
			data.MutationStats = append(data.MutationStats, m)
		}
	}
	// Calculate percentages
	totalMut := 0
	for _, m := range data.MutationStats {
		totalMut += m.Count
	}
	for i := range data.MutationStats {
		if totalMut > 0 {
			data.MutationStats[i].Percent = float64(data.MutationStats[i].Count) / float64(totalMut) * 100
		}
	}

	// --- Confidence distribution ---
	confBuckets := []struct{ low, high float64; label string }{
		{0.9, 1.01, "90-100%"}, {0.8, 0.9, "80-89%"}, {0.7, 0.8, "70-79%"},
		{0.6, 0.7, "60-69%"}, {0.5, 0.6, "50-59%"}, {0.0, 0.5, "0-49%"},
	}
	for _, b := range confBuckets {
		var count int
		q := "SELECT COUNT(*) FROM findings" + scanFilter
		if scanFilter != "" {
			q += " AND confidence >= ? AND confidence < ?"
		} else {
			q += " WHERE confidence >= ? AND confidence < ?"
		}
		bArgs := append(args, b.low, b.high)
		conn.QueryRowContext(ctx, q, bArgs...).Scan(&count)
		data.ConfidenceDist = append(data.ConfidenceDist, confBucket{Range: b.label, Count: count})
	}

	// --- Timeline (findings per 5-minute bucket) ---
	timeQuery := `SELECT strftime('%Y-%m-%d %H:%M', found_at, 'start of minute', 
		printf('-%d minutes', CAST(strftime('%M', found_at) AS INTEGER) % 5)) as bucket,
		COUNT(*) FROM findings` + scanFilter + ` GROUP BY bucket ORDER BY bucket LIMIT 100`
	timeRows, err := conn.QueryContext(ctx, timeQuery, args...)
	if err == nil {
		defer timeRows.Close()
		for timeRows.Next() {
			var tp timePoint
			timeRows.Scan(&tp.Time, &tp.Count)
			data.Timeline = append(data.Timeline, tp)
		}
	}

	// --- All findings (for the filterable table) ---
	findQuery := `SELECT id, url, method, parameter, parameter_location, type, severity,
		payload, mutation_strategy, evidence, confidence, found_at
		FROM findings` + scanFilter + ` ORDER BY CASE severity
			WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
		END, found_at DESC`
	findRows, err := conn.QueryContext(ctx, findQuery, args...)
	if err == nil {
		defer findRows.Close()
		for findRows.Next() {
			var f findingRow
			var foundAt time.Time
			findRows.Scan(&f.ID, &f.URL, &f.Method, &f.Param, &f.ParamLoc,
				&f.Type, &f.Severity, &f.Payload, &f.Mutation,
				&f.Evidence, &f.Confidence, &foundAt)
			f.FoundAt = foundAt.Format("15:04:05")
			data.Findings = append(data.Findings, f)
		}
	}

	// --- Risk Score ---
	data.RiskScore = calculateRiskScore(data.SeverityCounts)
	data.RiskLabel = riskLabel(data.RiskScore)

	return data, nil
}

func calculateRiskScore(sevCounts map[string]int) float64 {
	weights := map[string]float64{"critical": 10, "high": 5, "medium": 2, "low": 0.5}
	total := 0.0
	for sev, count := range sevCounts {
		total += weights[sev] * float64(count)
	}
	// Normalize to 0-100 scale (cap at 100)
	score := total / 10.0
	if score > 100 {
		score = 100
	}
	return score
}

func riskLabel(score float64) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
