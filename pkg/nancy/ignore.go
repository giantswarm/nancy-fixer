package nancy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/giantswarm/microerror"
)

const DefaultIgnorePeriodDays = 30

func IgnoreVulnerabilities(
	vulnerabilities []Vulnerability,
	p VulnerablePackage,
	nancyIgnorePath string,
) error {
	file, err := os.ReadFile(nancyIgnorePath)
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
	err = os.WriteFile(nancyIgnorePath, []byte(newFile), 0644) //nolint:all
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

		if !strings.Contains(line, "until") {
			// Remove lines that don't have an expiration date
			continue
		}

		// Split line so we can get the CVE ID and date (CVE-2022-29153 until=2023-06-01)
		entry := strings.Split(line, " ")
		// Pick CVE ID
		cve := entry[0]
		// Pick right side of the until section
		date := strings.Split(entry[1], "=")[1]

		// If vulnerability already exists
		if v, found := unhandledVulnerabilities[cve]; found {
			// Renew ignore entry
			newLine := generateNancyIgnoreEntry(v, p)
			newLines = append(newLines, newLine)

			// Delete entry from map
			delete(unhandledVulnerabilities, v.ID)
		} else {
			// If its not expired, keep it
			if !isExpired(date) {
				newLines = append(newLines, line)
			}
		}
	}

	// Create entries for missing vulnerabilities
	for _, v := range unhandledVulnerabilities {
		newLine := generateNancyIgnoreEntry(v, p)
		newLines = append(newLines, newLine)
	}

	return newLines
}

// CVE-2022-29153 until=2023-06-01
func generateNancyIgnoreEntry(v Vulnerability, p VulnerablePackage) string {
	today := time.Now()
	afterIgnorePeriod := today.AddDate(0, 0, DefaultIgnorePeriodDays)
	return fmt.Sprintf(
		"%s until=%s # %s@%s",
		v.ID,
		afterIgnorePeriod.Format("2006-01-02"),
		string(p.Name),
		string(p.Version),
	)
}

func isExpired(date string) bool {
	today := time.Now()
	expiryDate, error := time.Parse("2006-01-02", date)

	if error != nil {
		return true
	}

	if today.After(expiryDate) {
		return true
	} else {
		return false
	}
}
