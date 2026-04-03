// Package scanner implements the WAF bypass mutation engine and payload fuzzer.
package scanner

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Mutation strategy interface
// ---------------------------------------------------------------------------

// MutationStrategy transforms a raw payload into one or more WAF‑evading variants.
type MutationStrategy interface {
	Name() string
	Mutate(payload string) []string
}

// Mutator orchestrates multiple mutation strategies against a payload.
type Mutator struct {
	strategies []MutationStrategy
	rng        *rand.Rand
}

// NewMutator creates a Mutator loaded with every built‑in bypass strategy.
func NewMutator() *Mutator {
	return &Mutator{
		strategies: []MutationStrategy{
			&URLEncodeStrategy{},
			&DoubleURLEncodeStrategy{},
			&HTMLEntityStrategy{},
			&UnicodeStrategy{},
			&HexEncodeStrategy{},
			&Base64WrapStrategy{},
			&CaseRandomizeStrategy{},
			&SQLCommentStrategy{},
			&WhitespaceStrategy{},
			&ConcatStrategy{},
		},
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// MutateAll returns every mutation of the given payload across all strategies.
// The original payload is always included as the first entry.
func (m *Mutator) MutateAll(payload string) []MutatedPayload {
	results := []MutatedPayload{
		{Value: payload, Strategy: "original"},
	}
	for _, s := range m.strategies {
		for _, variant := range s.Mutate(payload) {
			results = append(results, MutatedPayload{
				Value:    variant,
				Strategy: s.Name(),
			})
		}
	}
	return results
}

// MutateRandom returns the original payload plus N random mutations.
func (m *Mutator) MutateRandom(payload string, n int) []MutatedPayload {
	all := m.MutateAll(payload)
	if len(all) <= n+1 {
		return all
	}
	// Always keep original
	result := []MutatedPayload{all[0]}
	// Shuffle remaining and take n
	rest := all[1:]
	m.rng.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	result = append(result, rest[:n]...)
	return result
}

// MutatedPayload pairs a transformed payload string with the strategy name.
type MutatedPayload struct {
	Value    string
	Strategy string
}

// ---------------------------------------------------------------------------
// Built‑in mutation strategies
// ---------------------------------------------------------------------------

// --- URL Encoding ---
type URLEncodeStrategy struct{}

func (s *URLEncodeStrategy) Name() string { return "url_encode" }
func (s *URLEncodeStrategy) Mutate(payload string) []string {
	return []string{url.QueryEscape(payload)}
}

// --- Double URL Encoding ---
type DoubleURLEncodeStrategy struct{}

func (s *DoubleURLEncodeStrategy) Name() string { return "double_url_encode" }
func (s *DoubleURLEncodeStrategy) Mutate(payload string) []string {
	return []string{url.QueryEscape(url.QueryEscape(payload))}
}

// --- HTML Entity Encoding ---
type HTMLEntityStrategy struct{}

func (s *HTMLEntityStrategy) Name() string { return "html_entity" }
func (s *HTMLEntityStrategy) Mutate(payload string) []string {
	var b strings.Builder
	for _, r := range payload {
		switch {
		case r == '<':
			b.WriteString("&#60;")
		case r == '>':
			b.WriteString("&#62;")
		case r == '"':
			b.WriteString("&#34;")
		case r == '\'':
			b.WriteString("&#39;")
		case r == '&':
			b.WriteString("&#38;")
		case r == '/':
			b.WriteString("&#47;")
		default:
			b.WriteRune(r)
		}
	}
	named := b.String()

	// Also produce full numeric encoding (every character)
	var full strings.Builder
	for _, r := range payload {
		fmt.Fprintf(&full, "&#%d;", r)
	}

	// Hex entity variant
	var hex strings.Builder
	for _, r := range payload {
		fmt.Fprintf(&hex, "&#x%x;", r)
	}

	return []string{named, full.String(), hex.String()}
}

// --- Unicode Encoding ---
type UnicodeStrategy struct{}

func (s *UnicodeStrategy) Name() string { return "unicode" }
func (s *UnicodeStrategy) Mutate(payload string) []string {
	// \uXXXX encoding
	var b strings.Builder
	for _, r := range payload {
		if r < 128 {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}

	// %uXXXX encoding (IIS style)
	var iis strings.Builder
	for _, r := range payload {
		if r < 128 {
			fmt.Fprintf(&iis, "%%u%04x", r)
		} else {
			iis.WriteRune(r)
		}
	}

	return []string{b.String(), iis.String()}
}

// --- Hex Encoding (for SQL) ---
type HexEncodeStrategy struct{}

func (s *HexEncodeStrategy) Name() string { return "hex_encode" }
func (s *HexEncodeStrategy) Mutate(payload string) []string {
	// 0xHEXHEX... format (MySQL)
	var b strings.Builder
	b.WriteString("0x")
	for _, c := range []byte(payload) {
		fmt.Fprintf(&b, "%02x", c)
	}
	return []string{b.String()}
}

// --- Base64 Wrapping ---
type Base64WrapStrategy struct{}

func (s *Base64WrapStrategy) Name() string { return "base64" }
func (s *Base64WrapStrategy) Mutate(payload string) []string {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	return []string{encoded}
}

// --- Case Randomization ---
type CaseRandomizeStrategy struct{}

func (s *CaseRandomizeStrategy) Name() string { return "case_random" }
func (s *CaseRandomizeStrategy) Mutate(payload string) []string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var variants []string

	// Generate 3 random case variants
	for i := 0; i < 3; i++ {
		var b strings.Builder
		for _, r := range payload {
			if rng.Intn(2) == 0 {
				b.WriteString(strings.ToUpper(string(r)))
			} else {
				b.WriteString(strings.ToLower(string(r)))
			}
		}
		variant := b.String()
		if variant != payload {
			variants = append(variants, variant)
		}
	}

	return variants
}

// --- SQL Comment Injection ---
type SQLCommentStrategy struct{}

func (s *SQLCommentStrategy) Name() string { return "sql_comment" }
func (s *SQLCommentStrategy) Mutate(payload string) []string {
	var variants []string

	// Replace spaces with /**/
	variants = append(variants, strings.ReplaceAll(payload, " ", "/**/"))

	// Replace spaces with %0a (newline)
	variants = append(variants, strings.ReplaceAll(payload, " ", "%0a"))

	// Replace spaces with %09 (tab)
	variants = append(variants, strings.ReplaceAll(payload, " ", "%09"))

	// Inline comment before keywords
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "INSERT", "UPDATE", "DELETE", "DROP"}
	commentedPayload := payload
	for _, kw := range keywords {
		commentedPayload = strings.ReplaceAll(commentedPayload, kw, "/*!"+kw+"*/")
		commentedPayload = strings.ReplaceAll(commentedPayload, strings.ToLower(kw), "/*!"+strings.ToLower(kw)+"*/")
	}
	if commentedPayload != payload {
		variants = append(variants, commentedPayload)
	}

	return variants
}

// --- Whitespace Variation ---
type WhitespaceStrategy struct{}

func (s *WhitespaceStrategy) Name() string { return "whitespace" }
func (s *WhitespaceStrategy) Mutate(payload string) []string {
	var variants []string

	// Null byte insertion between characters
	var nulled strings.Builder
	for i, r := range payload {
		nulled.WriteRune(r)
		if i < len([]rune(payload))-1 {
			nulled.WriteString("%00")
		}
	}
	variants = append(variants, nulled.String())

	// Double spaces
	variants = append(variants, strings.ReplaceAll(payload, " ", "  "))

	// Tab characters
	variants = append(variants, strings.ReplaceAll(payload, " ", "\t"))

	return variants
}

// --- String Concatenation ---
type ConcatStrategy struct{}

func (s *ConcatStrategy) Name() string { return "concat" }
func (s *ConcatStrategy) Mutate(payload string) []string {
	var variants []string

	// SQL-style concatenation: 'str' → 'st'||'r' or 'st'+'r'
	if len(payload) > 4 {
		mid := len(payload) / 2
		// Oracle/PostgreSQL style
		variants = append(variants, payload[:mid]+"'||'"+payload[mid:])
		// MSSQL style
		variants = append(variants, payload[:mid]+"'+'"+payload[mid:])
		// MySQL CONCAT
		variants = append(variants, fmt.Sprintf("CONCAT('%s','%s')", payload[:mid], payload[mid:]))
	}

	return variants
}
