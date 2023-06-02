package nancy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/giantswarm/microerror"
)

const DefaultIgnorePeriodDays = 90

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
	err = os.WriteFile(nancyIgnorePath, []byte(newFile), 0644)
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
	unhandledVulnerabilities := map[string]Vulnerability{}
	for _, v := range vulnerabilities {
		unhandledVulnerabilities[v.ID] = v
	}

	for i, line := range lines {
		newlyHandledVulnerabilities := []string{}
		for _, v := range unhandledVulnerabilities {
			if strings.Contains(line, v.ID) {
				newLine := generateNancyIgnoreEntry(v, p)
				lines[i] = newLine
				newlyHandledVulnerabilities = append(newlyHandledVulnerabilities, v.ID)
			}
		}
		for _, v := range newlyHandledVulnerabilities {
			delete(unhandledVulnerabilities, v)
		}
	}
	for _, v := range unhandledVulnerabilities {
		newLine := generateNancyIgnoreEntry(v, p)
		lines = append(lines, newLine)
	}
	return lines
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
