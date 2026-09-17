package nancy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/giantswarm/microerror"
)

const DefaultIgnorePeriodDays = 30

const (
	dateLayout  = "2006-01-02"
	untilPrefix = "until="
	sincePrefix = "since="
)

// ignoreEntry is a parsed .nancy-ignore line.
// CVE-2022-29153 until=2026-10-17 # github.com/foo/bar@v1.2.3 since=2026-03-04
type ignoreEntry struct {
	cve   string
	until string
	since string
}

func IgnoreVulnerabilities(
	vulnerabilities []Vulnerability,
	p VulnerablePackage,
	nancyIgnorePath string,
) error {
	file, err := os.ReadFile(filepath.Clean(nancyIgnorePath))
	if err != nil {
		if os.IsNotExist(err) {
			file = []byte{}
		} else {
			return microerror.Mask(err)
		}
	}
	lines := strings.Split(string(file), "\n")
	lines = lines[:len(lines)-1]

	lines = updateNancyIgnoreLines(lines, vulnerabilities, p)

	lines = append(lines, "")

	newFile := strings.Join(lines, "\n")
	// #nosec G306
	err = os.WriteFile(nancyIgnorePath, []byte(newFile), 0640)
	if err != nil {
		return microerror.Mask(err)
	}

	return nil
}

func updateNancyIgnoreLines(
	lines []string,
	vulnerabilities []Vulnerability,
	p VulnerablePackage,
) []string {

	// Map the vulnerabilities for easier access
	unhandledVulnerabilities := map[string]Vulnerability{}
	for _, v := range vulnerabilities {
		unhandledVulnerabilities[v.ID] = v
	}

	newLines := []string{}
	for _, line := range lines {

		entry, ok := parseIgnoreEntry(line)
		if !ok {
			// Remove lines that don't have an expiration date
			continue
		}

		// If vulnerability already exists
		if v, found := unhandledVulnerabilities[entry.cve]; found {
			// Renew ignore entry, keeping the date it was first ignored
			newLine := generateNancyIgnoreEntry(v, p, entry.since)
			newLines = append(newLines, newLine)

			// Delete entry from map
			delete(unhandledVulnerabilities, v.ID)
		} else {
			// If its not expired, keep it
			if !isExpired(entry.until) {
				newLines = append(newLines, line)
			}
		}
	}

	// Create entries for missing vulnerabilities
	for _, v := range unhandledVulnerabilities {
		newLine := generateNancyIgnoreEntry(v, p, "")
		newLines = append(newLines, newLine)
	}

	return newLines
}

// parseIgnoreEntry reports ok only for a line whose second field is the
// expiration date. An entry carries since= when it has already been renewed.
func parseIgnoreEntry(line string) (ignoreEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[1], untilPrefix) {
		return ignoreEntry{}, false
	}

	entry := ignoreEntry{
		cve:   fields[0],
		until: strings.TrimPrefix(fields[1], untilPrefix),
	}
	for _, field := range fields[2:] {
		if strings.HasPrefix(field, sincePrefix) {
			entry.since = strings.TrimPrefix(field, sincePrefix)
			break
		}
	}

	return entry, true
}

// CVE-2022-29153 until=2026-10-17 # github.com/foo/bar@v1.2.3 since=2026-03-04
func generateNancyIgnoreEntry(v Vulnerability, p VulnerablePackage, since string) string {
	today := time.Now()
	afterIgnorePeriod := today.AddDate(0, 0, DefaultIgnorePeriodDays)
	if _, err := time.Parse(dateLayout, since); err != nil {
		since = today.Format(dateLayout)
	}
	return fmt.Sprintf(
		"%s until=%s # %s@%s since=%s",
		v.ID,
		afterIgnorePeriod.Format(dateLayout),
		string(p.Name),
		string(p.Version),
		since,
	)
}

func isExpired(date string) bool {
	today := time.Now()
	expiryDate, error := time.Parse(dateLayout, date)

	if error != nil {
		return true
	}

	if today.After(expiryDate) {
		return true
	} else {
		return false
	}
}
