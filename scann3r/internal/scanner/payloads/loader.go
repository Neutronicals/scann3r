// Package payloads embeds and loads the YAML payload template files at compile time.
package payloads

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/venom-scanner/venom/internal/models"
)

//go:embed *.yaml
var payloadFS embed.FS

// LoadAll reads every embedded .yaml file and returns a map of
// category → PayloadFile. For example: "sqli" → PayloadFile{...}.
func LoadAll() (map[string]*models.PayloadFile, error) {
	entries, err := payloadFS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("reading embedded payloads dir: %w", err)
	}

	result := make(map[string]*models.PayloadFile)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}

		data, err := payloadFS.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}

		var pf models.PayloadFile
		if err := yaml.Unmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", e.Name(), err)
		}

		// Use the filename (without extension) as the key if category is empty.
		key := pf.Category
		if key == "" {
			key = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		}

		result[key] = &pf
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no payload files found")
	}

	return result, nil
}

// LoadCategory loads a single category (e.g. "sqli") from the embedded files.
func LoadCategory(category string) (*models.PayloadFile, error) {
	all, err := LoadAll()
	if err != nil {
		return nil, err
	}
	pf, ok := all[category]
	if !ok {
		return nil, fmt.Errorf("payload category %q not found", category)
	}
	return pf, nil
}

// Categories returns the list of available payload category names.
func Categories() ([]string, error) {
	all, err := LoadAll()
	if err != nil {
		return nil, err
	}
	cats := make([]string, 0, len(all))
	for k := range all {
		cats = append(cats, k)
	}
	return cats, nil
}
