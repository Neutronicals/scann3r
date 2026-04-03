package crawler

import (
	"context"
	"encoding/xml"
	"log"
	"strings"

	"github.com/venom-scanner/venom/internal/config"
	"github.com/venom-scanner/venom/internal/netutil"
)

// SitemapParser fetches and parses robots.txt and sitemap.xml to discover
// additional URLs. Disallowed paths in robots.txt are particularly interesting
// for vulnerability scanning (they contain hidden/admin routes).
type SitemapParser struct {
	cfg     *config.Config
	client  *netutil.HTTPClient
	limiter *netutil.DomainRateLimiter
}

// NewSitemapParser creates a new SitemapParser.
func NewSitemapParser(cfg *config.Config, client *netutil.HTTPClient, limiter *netutil.DomainRateLimiter) *SitemapParser {
	return &SitemapParser{cfg: cfg, client: client, limiter: limiter}
}

// robotsResult holds parsed robots.txt data.
type robotsResult struct {
	Disallowed []string // paths from Disallow directives
	Sitemaps   []string // sitemap URLs from Sitemap directives
}

// sitemapIndex is the XML structure for a sitemap index.
type sitemapIndex struct {
	XMLName  xml.Name       `xml:"sitemapindex"`
	Sitemaps []sitemapEntry `xml:"sitemap"`
}

type sitemapEntry struct {
	Loc string `xml:"loc"`
}

// urlSet is the XML structure for a standard sitemap.
type urlSet struct {
	XMLName xml.Name  `xml:"urlset"`
	URLs    []urlItem `xml:"url"`
}

type urlItem struct {
	Loc string `xml:"loc"`
}

// Discover fetches robots.txt and sitemaps, returns all discovered URLs.
func (sp *SitemapParser) Discover(ctx context.Context) []string {
	var allURLs []string

	// --- robots.txt ---
	robotsURLs, sitemapURLs := sp.parseRobotsTxt(ctx)
	allURLs = append(allURLs, robotsURLs...)

	// --- Sitemaps ---
	// Start with sitemaps from robots.txt; also try default location.
	defaultSitemap := strings.TrimRight(sp.cfg.Target, "/") + "/sitemap.xml"
	sitemapURLs = appendUnique(sitemapURLs, defaultSitemap)

	for _, smURL := range sitemapURLs {
		urls := sp.parseSitemap(ctx, smURL, 0)
		allURLs = append(allURLs, urls...)
	}

	return allURLs
}

// parseRobotsTxt fetches and parses robots.txt.
func (sp *SitemapParser) parseRobotsTxt(ctx context.Context) (disallowedURLs []string, sitemapURLs []string) {
	robotsURL := strings.TrimRight(sp.cfg.Target, "/") + "/robots.txt"

	if err := sp.limiter.Wait(ctx, robotsURL); err != nil {
		return
	}

	_, body, err := sp.client.Get(ctx, robotsURL)
	if err != nil {
		if sp.cfg.Verbose {
			log.Printf("[sitemap] could not fetch robots.txt: %v", err)
		}
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Sitemap directive
		if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			smURL := strings.TrimSpace(line[len("sitemap:"):])
			if smURL != "" {
				sitemapURLs = append(sitemapURLs, smURL)
			}
			continue
		}

		// Disallow directive → interesting hidden paths
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" && path != "/" {
				fullURL := strings.TrimRight(sp.cfg.Target, "/") + path
				disallowedURLs = append(disallowedURLs, fullURL)
			}
		}
	}

	return
}

// parseSitemap recursively parses sitemap.xml and sitemap index files.
func (sp *SitemapParser) parseSitemap(ctx context.Context, sitemapURL string, depth int) []string {
	if depth > 3 { // prevent infinite recursion
		return nil
	}

	if err := sp.limiter.Wait(ctx, sitemapURL); err != nil {
		return nil
	}

	_, body, err := sp.client.Get(ctx, sitemapURL)
	if err != nil {
		if sp.cfg.Verbose {
			log.Printf("[sitemap] could not fetch %s: %v", sitemapURL, err)
		}
		return nil
	}

	var urls []string

	// Try parsing as sitemap index first
	var idx sitemapIndex
	if err := xml.Unmarshal(body, &idx); err == nil && len(idx.Sitemaps) > 0 {
		for _, sm := range idx.Sitemaps {
			if sm.Loc != "" {
				urls = append(urls, sp.parseSitemap(ctx, sm.Loc, depth+1)...)
			}
		}
		return urls
	}

	// Try parsing as URL set
	var us urlSet
	if err := xml.Unmarshal(body, &us); err == nil {
		for _, u := range us.URLs {
			if u.Loc != "" && sp.cfg.InScope(u.Loc) {
				urls = append(urls, u.Loc)
			}
		}
	}

	return urls
}

// appendUnique appends s to the slice only if it's not already present.
func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
