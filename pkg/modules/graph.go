package modules

import (
	"strings"

	"github.com/giantswarm/microerror"

	"github.com/giantswarm/nancy-fixer/pkg/gocli"
)

type DependencyLink struct {
	Parent string
	Child  string
}

func (l DependencyLink) String() string {
	return l.Parent + " -> " + l.Child
}

func BuildDependencyLinks(cwd string) ([]DependencyLink, error) {
	out, err := gocli.CallGoNoBuffer(gocli.GoConfig{Cwd: cwd}, "mod", "graph")
	if err != nil {
		return nil, microerror.Mask(err)
	}
	lines := strings.Split(string(out), "\n")
	lines = lines[:len(lines)-1] // last line is empty

	dependencyLinks := make([]DependencyLink, 0, len(lines))

	for _, line := range lines {
		dependencyLink, err := buildDependencyLink(line)
		if err != nil {
			return nil, microerror.Mask(err)
		}
		dependencyLinks = append(dependencyLinks, dependencyLink)
	}

	return dependencyLinks, nil
}

func buildDependencyLink(line string) (DependencyLink, error) {
	parts := strings.Split(line, " ")
	if len(parts) != 2 {
		return DependencyLink{}, microerror.Maskf(
			invalidDependencyLineError,
			"invalid dependency line: %s",
			line,
		)
	}
	return DependencyLink{
		Parent: parts[0],
		Child:  parts[1],
	}, nil
}

// child -> [parent1, parent2, ...]
type ReverseDependencyMap map[string][]string

func BuildReverseDependencyMap(dependencyLinks []DependencyLink) ReverseDependencyMap {
	reverseDependencyMap := make(ReverseDependencyMap)

	for _, link := range dependencyLinks {
		parents, ok := reverseDependencyMap[link.Child]
		if !ok {
			parents = make([]string, 0)
		}
		parents = append(parents, link.Parent)
		reverseDependencyMap[link.Child] = parents
	}

	return reverseDependencyMap
}

// FindRootParents returns a list of the packages that are directly required by
// the root package (i.e. the package that is being checked for vulnerabilities)
// and that require directly or indirectly the given package.
func FindRootParents(
	reverseDependencyMap ReverseDependencyMap,
	packageName PackageName,
	packageVersion SemanticVersion,
	rootPackage PackageName,
) []Package {
	// we have to find the root packages of the current and previoius versions of the given package
	prevPackages := preparePreviousPackages(packageName, packageVersion, reverseDependencyMap)

	selected := make(map[string]bool)
	unvisited := prevPackages
	rootParents := make(map[string]bool)

	for len(unvisited) > 0 {
		current := unvisited[0]
		unvisited = unvisited[1:]

		for _, parent := range reverseDependencyMap[current] {
			if selected[parent] {
				continue
			}
			if parent == string(rootPackage) {
				rootParents[current] = true
				continue
			}
			selected[parent] = true
			unvisited = append(unvisited, parent)
		}

	}

	return getPackagesFromMap(rootParents)
}

func preparePreviousPackages(
	packageName PackageName,
	packageVersion SemanticVersion,
	reverseDependencyMap ReverseDependencyMap,
) []string {
	prevPackages := []string{string(packageName) + "@" + string(packageVersion)}

	for p := range reverseDependencyMap {
		parts := strings.Split(p, "@")
		name, version := parts[0], parts[1]
		if name != string(packageName) {
			continue
		}
		semVer, err := BuildSemVer(version)
		if err != nil {
			panic(err)
		}
		if semVer.LessThan(packageVersion) {
			prevPackages = append(prevPackages, p)
		}
	}
	return prevPackages
}

func getPackagesFromMap(m map[string]bool) []Package {
	packages := make([]Package, 0, len(m))
	for k := range m {
		parts := strings.Split(k, "@")

		semVer, err := BuildSemVer(parts[1])
		if err != nil {
			panic(err)
		}
		packages = append(packages, Package{
			Name:    PackageName(parts[0]),
			Version: semVer,
		})
	}
	return packages
}

func GetModuleName(cwd string) (PackageName, error) {
	out, err := gocli.CallGoNoBuffer(gocli.GoConfig{Cwd: cwd}, "list", "-m")
	if err != nil {
		return "", microerror.Mask(err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) != 2 {
		return "", microerror.Maskf(
			invalidModuleListError,
			"invalid output of go list -m: %s",
			out,
		)
	}
	return PackageName(lines[0]), nil
}
