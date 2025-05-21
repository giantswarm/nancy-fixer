package nancy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/giantswarm/microerror"

	"github.com/giantswarm/nancy-fixer/pkg/modules"
)

type VulnerablePackageJSON struct {
	Coordinates     string `json:"Coordinates"`
	Reference       string `json:"Reference"`
	Vulnerabilities []struct {
		ID          string `json:"ID"`
		Title       string `json:"Title"`
		Description string `json:"Description"`
		CvssScore   string `json:"CvssScore"`
		CvssVector  string `json:"CvssVector"`
		Cve         string `json:"Cve"`
		Reference   string `json:"Reference"`
		Excluded    bool   `json:"Excluded"`
	} `json:"Vulnerabilities"`
	InvalidSemVer bool `json:"InvalidSemVer"`
}

type NancySleuthOutputJSON struct {
	Audited []struct {
		Coordinates     string `json:"Coordinates"`
		Reference       string `json:"Reference"`
		Vulnerabilities any    `json:"Vulnerabilities"`
		InvalidSemVer   bool   `json:"InvalidSemVer"`
	} `json:"audited"`
	Excluded      []VulnerablePackageJSON `json:"excluded"`
	Exclusions    []string                `json:"exclusions"`
	Invalid       []any                   `json:"invalid"`
	NumAudited    int                     `json:"num_audited"`
	NumExclusions int                     `json:"num_exclusions"`
	NumVulnerable int                     `json:"num_vulnerable"`
	Version       string                  `json:"version"`
	Vulnerable    []VulnerablePackageJSON `json:"vulnerable"`
}

type Vulnerability struct {
	ID          string
	Title       string
	Description string
	CvssScore   string
}

func (v Vulnerability) String() string {
	return v.Title
}

type VulnerablePackage struct {
	Name            modules.PackageName
	Version         modules.SemanticVersion
	Vulnerabilities []Vulnerability
}

func (p VulnerablePackage) String() string {
	return fmt.Sprintf("%s@%s-[%d vulnerabilities]", p.Name, p.Version, len(p.Vulnerabilities))
}

func (p VulnerablePackage) ToPackage() modules.Package {
	return modules.Package{
		Name:    p.Name,
		Version: p.Version,
	}
}

func VulnerablePackagesContain(packages []VulnerablePackage, name modules.PackageName) bool {
	for _, pkg := range packages {
		if pkg.Name == name {
			return true
		}
	}
	return false
}

func GetVulnerablePackages(dir string) ([]VulnerablePackage, error) {

	nancyOutput, err := RunSleuth(dir)
	if err != nil {
		return nil, microerror.Mask(err)
	}

	vulnerablePackages, err := extractVulnerablePackages(nancyOutput)

	if err != nil {
		return nil, microerror.Mask(err)
	}

	return vulnerablePackages, nil
}

func RunSleuth(dir string) (NancySleuthOutputJSON, error) {
	nancyExecutable, err := exec.LookPath("nancy")
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}

	r, w := io.Pipe()
	goCmd := exec.Cmd{
		Path:   goExecutable,
		Args:   []string{goExecutable, "list", "-json", "-deps", "./..."},
		Dir:    dir,
		Stdout: w,
	}

	var out bytes.Buffer
	nancyCmd := exec.Cmd{
		Path: nancyExecutable,
		Args: []string{
			nancyExecutable,
			"sleuth",
			"--skip-update-check",
			"--quiet",
			"--exclude-vulnerability-file",
			"./.nancy-ignore",
			"--additional-exclude-vulnerability-files",
			"./.nancy-ignore.generated",
			"-o",
			"json-pretty",
		},
		Dir:    dir,
		Stdin:  r,
		Stdout: &out,
	}

	err = goCmd.Start()
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}
	err = nancyCmd.Start()
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}
	err = goCmd.Wait()
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}

	if err := w.Close(); err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}

	err = nancyCmd.Wait()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Nancy returns inconistent and unexpected exit codes.
		} else {
			return NancySleuthOutputJSON{}, microerror.Mask(err)
		}
	}

	nancyOutput, err := parseNancyOutput(out)
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}

	return nancyOutput, nil
}

func parseNancyOutput(output bytes.Buffer) (NancySleuthOutputJSON, error) {
	jsonParsed := NancySleuthOutputJSON{}

	err := json.Unmarshal(output.Bytes(), &jsonParsed)
	if err != nil {
		return NancySleuthOutputJSON{}, microerror.Mask(err)
	}
	return jsonParsed, nil
}

func extractVulnerablePackages(outputJSON NancySleuthOutputJSON) ([]VulnerablePackage, error) {
	vulnerablePackages := []VulnerablePackage{}

	for _, vulnerablePackageJSON := range outputJSON.Vulnerable {
		vulnerabilities := []Vulnerability{}

		for _, vulnerabilityJSON := range vulnerablePackageJSON.Vulnerabilities {
			vulnerability := Vulnerability{
				ID:          vulnerabilityJSON.ID,
				Title:       vulnerabilityJSON.Title,
				Description: vulnerabilityJSON.Description,
				CvssScore:   vulnerabilityJSON.CvssScore,
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}

		name, version := UnpackCoordinates(vulnerablePackageJSON.Coordinates)
		semVer, err := modules.BuildSemVer(version)
		if err != nil {
			return nil, microerror.Mask(err)
		}

		vulnerablePackage := VulnerablePackage{
			Name:            modules.PackageName(name),
			Version:         semVer,
			Vulnerabilities: vulnerabilities,
		}
		vulnerablePackages = append(vulnerablePackages, vulnerablePackage)

	}
	return vulnerablePackages, nil

}

// coordinates example: pkg:golang/github.com/hashicorp/consul/api@v1.20.0
// name example: github.com/hashicorp/consul/api
// version example: v1.20.0
func UnpackCoordinates(coordinates string) (name string, version string) {
	coordinatesParts := strings.Split(coordinates, "@")
	name = strings.TrimPrefix(coordinatesParts[0], "pkg:golang/")
	version = coordinatesParts[1]
	return name, version

}
