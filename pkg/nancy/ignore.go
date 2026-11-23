package nancy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultIgnorePeriodDays = 30

// DefaultMaxIgnoreAgeDays is the age above which a renewed entry is reported as
// overdue, when the policy is enabled.
const DefaultMaxIgnoreAgeDays = 90

const (
	dateLayout  = "2006-01-02"
	untilPrefix = "until="
	sincePrefix = "since="
)

// IgnorePolicy decides whether a renewed entry is reported as overdue. It is
// disabled by default and never changes the outcome of a run.
type IgnorePolicy struct {
	ReportOverdue bool
	MaxAgeDays    int
}

// OverdueIgnore is a renewed entry that has been ignored for longer than the
// policy allows.
type OverdueIgnore struct {
	CVE     string
	Package string
	Since   string
	AgeDays int
}

func (o OverdueIgnore) String() string {
	return fmt.Sprintf("%s in %s, ignored for %d days since %s", o.CVE, o.Package, o.AgeDays, o.Since)
}

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
	policy IgnorePolicy,
) ([]OverdueIgnore, error) {
	lines, err := readIgnoreLines(nancyIgnorePath)
	if err != nil {
		return nil, err
	}

	lines, overdue := updateNancyIgnoreLines(lines, vulnerabilities, p, policy)

	if err := writeIgnoreLines(nancyIgnorePath, lines); err != nil {
		return nil, err
	}

	return overdue, nil
}

func updateNancyIgnoreLines(
	lines []string,
	vulnerabilities []Vulnerability,
	p VulnerablePackage,
	policy IgnorePolicy,
) ([]string, []OverdueIgnore) {

	// Map the vulnerabilities for easier access
	unhandledVulnerabilities := map[string]Vulnerability{}
	for _, v := range vulnerabilities {
		unhandledVulnerabilities[v.ID] = v
	}

	newLines := []string{}
	overdue := []OverdueIgnore{}
	for _, line := range lines {

		if isComment(line) {
			newLines = append(newLines, line)
			continue
		}

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

			if overdueIgnore, found := checkOverdue(entry, p, policy); found {
				overdue = append(overdue, overdueIgnore)
			}

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

	return newLines, overdue
}

// PruneIgnores removes the entries of the ignore file at path that the scan
// did not match: expired entries, entries without an expiration date and
// entries whose vulnerability no scanned package has any more. Comment and
// blank lines are kept. A scan that audited no package matches nothing and
// leaves the file unchanged, as does a missing file. It returns the removed
// lines.
func PruneIgnores(path string, scan ScanResult) ([]string, error) {
	if scan.Audited == 0 {
		return nil, nil
	}

	lines, err := readIgnoreLines(path)
	if err != nil {
		return nil, err
	}

	kept, removed := pruneIgnoreLines(lines, scan.Matched)
	if len(removed) == 0 {
		return nil, nil
	}

	if err := writeIgnoreLines(path, kept); err != nil {
		return nil, err
	}

	return removed, nil
}

func pruneIgnoreLines(lines []string, matched map[string]bool) (kept []string, removed []string) {
	kept = []string{}
	for _, line := range lines {
		if isComment(line) {
			kept = append(kept, line)
			continue
		}

		entry, ok := parseIgnoreEntry(line)
		if !ok || isExpired(entry.until) || !matched[entry.cve] {
			removed = append(removed, line)
			continue
		}
		kept = append(kept, line)
	}

	return kept, removed
}

// isComment reports a line nancy reads no exclusion from: everything after
// '#' is a comment.
func isComment(line string) bool {
	content, _, _ := strings.Cut(line, "#")
	return strings.TrimSpace(content) == ""
}

// readIgnoreLines returns no lines for a missing file.
func readIgnoreLines(path string) ([]string, error) {
	file, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read nancy ignore file: %w", err)
	}

	content := strings.TrimSuffix(string(file), "\n")
	if content == "" {
		return []string{}, nil
	}

	return strings.Split(content, "\n"), nil
}

func writeIgnoreLines(path string, lines []string) error {
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}

	// #nosec G306
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		return fmt.Errorf("write nancy ignore file: %w", err)
	}

	return nil
}

// checkOverdue reports a renewed entry whose first ignore date is older than
// the policy allows. An entry without since= has no known age and is never
// overdue on its first renewal.
func checkOverdue(entry ignoreEntry, p VulnerablePackage, policy IgnorePolicy) (OverdueIgnore, bool) {
	if !policy.ReportOverdue {
		return OverdueIgnore{}, false
	}

	since, err := time.Parse(dateLayout, entry.since)
	if err != nil {
		return OverdueIgnore{}, false
	}

	ageDays := int(time.Since(since).Hours() / 24)
	if ageDays <= policy.MaxAgeDays {
		return OverdueIgnore{}, false
	}

	return OverdueIgnore{
		CVE:     entry.cve,
		Package: fmt.Sprintf("%s@%s", p.Name, p.Version),
		Since:   entry.since,
		AgeDays: ageDays,
	}, true
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
