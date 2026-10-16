package modules

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/giantswarm/nancy-fixer/pkg/gocli"
)

type SemanticVersion string

func (v SemanticVersion) String() string {
	return string(v)
}

func (v SemanticVersion) LessThan(other SemanticVersion) bool {
	return semver.Compare(string(v), string(other)) == -1
}

func BuildSemVer(s string) (SemanticVersion, error) {
	if !semver.IsValid(s) {
		return SemanticVersion(
			"",
		), fmt.Errorf("%s is not a valid semantic version: %w", s, invalidSemVerError)
	}

	return SemanticVersion(s), nil
}

func SemVersToStrings(vers []SemanticVersion) []string {
	var strings []string
	for _, ver := range vers {
		strings = append(strings, string(ver))
	}
	return strings
}

type PackageName string

type Package struct {
	Name    PackageName
	Version SemanticVersion
}

func GetVersionsForPackage(name PackageName) ([]SemanticVersion, error) {
	stdout, err := gocli.CallGoNoBuffer(
		gocli.GoConfig{},
		"list",
		"-m",
		"-versions",
		string(name),
	)
	if err != nil {
		return nil, fmt.Errorf("list versions for %s: %w", name, err)
	}

	versions := []SemanticVersion{}
	stdout = strings.Trim(stdout, " \n")
	for _, line := range strings.Split(stdout, " ") {
		if len(line) == 0 {
			continue
		}
		semVer, err := BuildSemVer(line)
		if err != nil {
			continue
		}

		versions = append(versions, semVer)
	}

	return versions, nil
}

func RemovePreReleaseVersions(versions []SemanticVersion) []SemanticVersion {
	var filtered []SemanticVersion
	for _, v := range versions {
		if semver.Prerelease(string(v)) == "" {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func GetNewestVersion(name PackageName) (SemanticVersion, error) {
	versions, err := GetVersionsForPackage(name)
	if err != nil {
		return "", fmt.Errorf("get newest version for %s: %w", name, err)
	}

	if len(versions) == 0 {
		return "", fmt.Errorf("no versions found for %s: %w", name, noVersionsFoundError)
	}
	versions = RemovePreReleaseVersions(versions)

	stringSemVers := SemVersToStrings(versions)
	semver.Sort(stringSemVers)

	return SemanticVersion(stringSemVers[len(stringSemVers)-1]), nil
}

func UpdatePackage(cwd string, name PackageName, version SemanticVersion) error {
	_, err := gocli.CallGoNoBuffer(
		gocli.GoConfig{Cwd: cwd},
		"get",
		fmt.Sprintf("%s@%s", name, version),
	)
	// go get writes to stderr
	if err != nil {
		return fmt.Errorf("run go get for %s@%s: %w", name, version, err)
	}

	_, err = gocli.CallGoNoBuffer(
		gocli.GoConfig{Cwd: cwd},
		"mod",
		"tidy",
	)
	if err != nil {
		return fmt.Errorf("run go mod tidy: %w", err)
	}

	return nil
}

func VetSuceeds(cwd string) (bool, error) {
	_, err := gocli.CallGoNoBuffer(
		gocli.GoConfig{Cwd: cwd},
		"vet",
		"./...",
	)
	if err != nil {
		return false, err
	}
	return true, nil
}

func UpdatePackageWithReplace(cwd string, name PackageName, oldVersion, version SemanticVersion) error {
	_, err := gocli.CallGoNoBuffer(
		gocli.GoConfig{Cwd: cwd},
		"mod",
		"edit",
		"-replace",
		fmt.Sprintf("%s@%s=%s@%s", name, oldVersion, name, version),
	)
	if err != nil {
		return fmt.Errorf("add replace directive for %s@%s: %w", name, oldVersion, err)
	}

	_, err = gocli.CallGoNoBuffer(
		gocli.GoConfig{Cwd: cwd},
		"mod",
		"tidy",
	)
	if err != nil {
		return fmt.Errorf("go mod tidy failed: %w", goModTidyError)
	}

	return nil
}
