package report

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// maxReportHosts caps the endpoints one run can name (the headers are server-controlled).
const maxReportHosts = 32

var quoted = regexp.MustCompile(`"([^"]+)"`)

// reportEndpointHosts returns the hosts a response told Chrome to send Reporting API and
// Network Error Logging reports to (Report-To, Reporting-Endpoints). Chrome posts those reports
// in the background without a request the Network domain shows (found in P6 on a Cloudflare
// page: a.nel.cloudflare.com).
func reportEndpointHosts(headers map[string]any) []string {
	var hosts []string
	add := func(raw string) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err == nil && u.Scheme == "https" && u.Hostname() != "" {
			hosts = append(hosts, strings.ToLower(u.Hostname()))
		}
	}
	for name, v := range headers {
		val, ok := v.(string)
		if !ok || len(val) > 16<<10 {
			continue
		}
		switch strings.ToLower(name) {
		case "report-to": // JSON objects, comma-separated (one per line when folded by CDP)
			var groups []struct {
				Endpoints []struct {
					URL string `json:"url"`
				} `json:"endpoints"`
			}
			joined := "[" + strings.ReplaceAll(val, "\n", ",") + "]"
			if json.Unmarshal([]byte(joined), &groups) != nil {
				continue
			}
			for _, g := range groups {
				for _, e := range g.Endpoints {
					add(e.URL)
				}
			}
		case "reporting-endpoints": // structured dictionary: name="https://...", ...
			for _, m := range quoted.FindAllStringSubmatch(val, maxReportHosts) {
				add(m[1])
			}
		}
	}
	return hosts
}
