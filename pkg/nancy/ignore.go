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
	file, err := os.ReadFile(filepath.Clean(nancyIgnorePath))
	if err != nil {
		if os.IsNotExist(err) {
			file = []byte{}
		} else {
			return nil, microerror.Mask(err)
		}
	}
	lines := strings.Split(string(file), "\n")
	lines = lines[:len(lines)-1]

	lines, overdue := updateNancyIgnoreLines(lines, vulnerabilities, p, policy)

	lines = append(lines, "")

	newFile := strings.Join(lines, "\n")
	// #nosec G306
	err = os.WriteFile(nancyIgnorePath, []byte(newFile), 0640)
	if err != nil {
		return nil, microerror.Mask(err)
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
