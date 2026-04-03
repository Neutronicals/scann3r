package crawler

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"github.com/venom-scanner/venom/internal/models"
)

// ExtractForms parses all <form> elements from an HTML document and
// returns structured FormData with resolved action URLs.
func ExtractForms(doc *goquery.Document, pageURL string) []models.FormData {
	var forms []models.FormData

	doc.Find("form").Each(func(_ int, sel *goquery.Selection) {
		form := models.FormData{
			FormURL: pageURL,
		}

		// Action
		action, exists := sel.Attr("action")
		if !exists || action == "" {
			action = pageURL // form posts to itself
		}
		form.Action = resolveURL(pageURL, action)

		// Method
		method, _ := sel.Attr("method")
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			method = "GET"
		}
		form.Method = method

		// Encoding type
		enctype, _ := sel.Attr("enctype")
		if enctype == "" {
			enctype = "application/x-www-form-urlencoded"
		}
		form.Enctype = enctype

		// --- Inputs ---
		sel.Find("input").Each(func(_ int, inp *goquery.Selection) {
			name, _ := inp.Attr("name")
			typ, _ := inp.Attr("type")
			value, _ := inp.Attr("value")
			if typ == "" {
				typ = "text"
			}
			form.Inputs = append(form.Inputs, models.InputField{
				Name:  name,
				Type:  strings.ToLower(typ),
				Value: value,
			})
		})

		// <select> elements
		sel.Find("select").Each(func(_ int, s *goquery.Selection) {
			name, _ := s.Attr("name")
			var value string
			s.Find("option[selected]").Each(func(_ int, opt *goquery.Selection) {
				value, _ = opt.Attr("value")
			})
			if value == "" {
				s.Find("option").First().Each(func(_ int, opt *goquery.Selection) {
					value, _ = opt.Attr("value")
				})
			}
			form.Inputs = append(form.Inputs, models.InputField{
				Name:  name,
				Type:  "select",
				Value: value,
			})
		})

		// <textarea> elements
		sel.Find("textarea").Each(func(_ int, ta *goquery.Selection) {
			name, _ := ta.Attr("name")
			form.Inputs = append(form.Inputs, models.InputField{
				Name:  name,
				Type:  "textarea",
				Value: ta.Text(),
			})
		})

		forms = append(forms, form)
	})

	return forms
}

// ExtractQueryParams pulls query-string parameters from a URL.
func ExtractQueryParams(rawURL string) []models.Parameter {
	var params []models.Parameter
	u, err := url.Parse(rawURL)
	if err != nil {
		return params
	}
	for key, values := range u.Query() {
		for _, v := range values {
			params = append(params, models.Parameter{
				Name:     key,
				Value:    v,
				Location: "query",
			})
		}
	}
	return params
}

// ExtractFormParams converts FormData inputs into Parameters suitable for fuzzing.
func ExtractFormParams(form models.FormData) []models.Parameter {
	var params []models.Parameter
	for _, inp := range form.Inputs {
		if inp.Name == "" {
			continue
		}
		params = append(params, models.Parameter{
			Name:     inp.Name,
			Value:    inp.Value,
			Location: "body",
		})
	}
	return params
}
