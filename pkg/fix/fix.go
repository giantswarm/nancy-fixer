package fix

import (
	"fmt"
	"path"

	errors_ "errors"

	"github.com/pkg/errors"
	"github.com/pterm/pterm"

	"github.com/giantswarm/nancy-fixer/pkg/logging"
	"github.com/giantswarm/nancy-fixer/pkg/modules"
	"github.com/giantswarm/nancy-fixer/pkg/modules/revisions"
	"github.com/giantswarm/nancy-fixer/pkg/nancy"
)

const DefaultNancyIgnorePath = ".nancy-ignore"

func Fix(logger *pterm.Logger, cwd string) error {
	logger.Info("Gathering vulnerable packages")

	logger.Debug("Calling nancy to find vulnerabilities for path: ", logger.Args("cwd", cwd))
	vulnerablePackages, err := nancy.GetVulnerablePackages(logger, cwd)
	if err != nil {
		return errors.Cause(err)
	}

	logger.Info(fmt.Sprintf("Found %d vulnerable packages", len(vulnerablePackages)))

	history, err := revisions.BuildHistory(cwd)
	if err != nil {
		return errors.Cause(err)
	}

	fixReasonSummary := makeFixReasonsummary()

	for len(vulnerablePackages) > 0 {
		p := vulnerablePackages[0]
		before, err := history.PushRevision(fmt.Sprintf("Fix %s", p.Name))
		if err != nil {
			return errors.Cause(err)
		}

		logging.LogSection(logger, fmt.Sprintf("Fixing %s@%s", p.Name, p.Version))

		fixResult, err := FixVulnerablePackage(logger, cwd, p, history)
		fixReasonSummary = fixReasonSummary.Update(fixResult)

		if err != nil {
			logger.Error(
				fmt.Sprintf(
					"Error while fixing %s@%s\n",
					p.Name,
					p.Version,
				),
			)

			// We want to know what failed when running on CI without enabling debug
			logger.Error(err.Error())

			logger.Debug(fmt.Sprintf("Restoring state before fix for %s@%s\n", p.Name, p.Version))
			oErr := history.GotoRevision(before)
			if oErr != nil {
				return errors.Cause(errors_.Join(err, oErr))
			}

			// Remove item from vulnerable packages for now
			// This avoid looping forever on the same element and the item will be re-introduced in the next successful run
			arrayLenght := len(vulnerablePackages)
			if arrayLenght > 1 {
				vulnerablePackages[0] = vulnerablePackages[arrayLenght-1]
				vulnerablePackages = vulnerablePackages[:arrayLenght-1]
				continue
			} else {
				// There is nothing else in the package list, don't re-iterate
				break
			}
		}

		// refresh list of vulnerable packages, as the fix might have
		// impacted other vulnerable packages
		vulnerablePackages, err = nancy.GetVulnerablePackages(logger, cwd)

		if err != nil {
			return errors.Cause(err)
		}

		logger.Debug(fmt.Sprintf("%d vulnerable packages remaining", len(vulnerablePackages)))

	}

	logging.LogSection(logger, "Summary")
	LogFixReasonSummary(logger, fixReasonSummary)

	return nil
}

func FixVulnerablePackage(
	logger *pterm.Logger,
	cwd string,
	p nancy.VulnerablePackage,
	history *revisions.History,
) (FixResult, error) {
	fixResult := makeEmptyFixResult()

	moduleName, err := modules.GetModuleName(cwd)
	if err != nil {
		return fixResult, errors.Cause(err)
	}

	newestVersion, updateAvailable, err := checkUpdateAvailable(p.ToPackage())
	if err != nil {
		return fixResult, errors.Cause(err)
	}

	if updateAvailable {
		logger.Info(fmt.Sprintf("Update available: %v", newestVersion))

	} else {
		logger.Info("No update available")
	}

	if updateAvailable {
		beforeUpdate, err := history.PushRevision(fmt.Sprintf("Updating %s", p.Name))
		if err != nil {
			return fixResult, errors.Cause(err)
		}

		updateResult, err := performUpdateSteps(logger, cwd, p, moduleName, newestVersion, history)
		fixResult = fixResult.injectUpdateResult(updateResult)

		if fixResult.isFixed() {
			return fixResult, nil
		}

		// update failed - rollback changes
		oErr := history.GotoRevision(beforeUpdate)
		if oErr != nil {
			return fixResult, errors.Cause(errors_.Join(err, oErr))
		}

		if err != nil {
			return fixResult, errors.Cause(err)
		}

	}

	// everything else failed - ignore the vulnerability
	logger.Info(fmt.Sprintf("Ignoring %s@%s", p.Name, p.Version))
	fixResult.Ignored = true
	err = nancy.IgnoreVulnerabilities(
		p.Vulnerabilities,
		p,
		path.Join(cwd, DefaultNancyIgnorePath),
	)
	if err != nil {
		return fixResult, errors.Cause(err)
	}
	return fixResult, nil
}

func checkUpdateAvailable(
	p modules.Package,
) (newestVersion modules.SemanticVersion, updateAvailable bool, err error) {
	newestVersion, err = modules.GetNewestVersion(p.Name)
	if err != nil {
		return newestVersion, false, errors.Cause(err)
	}
	updateAvailable = p.Version.LessThan(newestVersion)
	return newestVersion, updateAvailable, nil
}

func performUpdateSteps(
	logger *pterm.Logger,
	cwd string,
	p nancy.VulnerablePackage,
	moduleName modules.PackageName,
	newestVersion modules.SemanticVersion,
	history *revisions.History,
) (UpdateResult, error) {
	before, err := history.PushRevision(fmt.Sprintf("Updating parents of %s", p.Name))

	updateResult := makeEmptyUpdateResult()
	if err != nil {
		return updateResult, errors.Cause(err)
	}

	parentResult, err := getAndUpdateParents(logger, cwd, p, moduleName)
	updateResult.ParentResult = parentResult

	if err != nil {
		return updateResult, errors.Cause(err)
	}

	if parentResult == ParentSuccess {
		return updateResult, nil
	}

	logger.Info("Parent update failed - trying to update via replace")
	// rollback changes before proceeding with update via replace
	err = history.GotoRevision(before)
	if err != nil {
		return updateResult, errors.Cause(err)
	}

	replaceResult, err := updateWithReplaceAndCheck(logger, cwd, p, newestVersion)
	updateResult.ReplaceResult = replaceResult

	if err != nil {
		return updateResult, errors.Cause(err)
	}

	switch replaceResult {
	case ReplaceSuccess:
		logger.Info("Update via replace successful")
	case ReplaceDidNotFixVulnerability:
		logger.Info("Update via replace did not fix vulnerability")
	case ReplaceBrokeBuild:
		logger.Info("Update via replace broke build")
	}

	return updateResult, nil
}

func getAndUpdateParents(
	logger *pterm.Logger,
	cwd string,
	p nancy.VulnerablePackage,
	moduleName modules.PackageName,
) (ParentUpdateResult, error) {
	dependencyLinks, err := modules.BuildDependencyLinks(cwd)
	if err != nil {
		return ParentError, errors.Cause(err)
	}
	reverseDependencyMap := modules.BuildReverseDependencyMap(dependencyLinks)

	rootParents := modules.FindRootParents(
		reverseDependencyMap,
		p.Name,
		p.Version,
		moduleName,
	)
	if len(rootParents) == 0 {
		logger.Error("No root parents found, but should always be at least one")
		return ParentError, nil
	}

	LogParents(logger, rootParents, p.Name)

	result, err := updateParents(logger, cwd, rootParents)
	if result == ParentBrokeBuild ||
		result == ParentError ||
		result == ParentUpdateNoUpdateAvailable {
		return result, errors.Cause(err)
	}

	isFixed, err := checkVulnerabilityFixed(logger, cwd, p.Name)
	if err != nil {
		return ParentError, errors.Cause(err)
	}
	if !isFixed {
		logger.Info("Updating parents did not fix vulnerability")
		return ParentDidNotFixVulnerability, nil
	}
	logger.Info("Updating parents fixed vulnerability")
	return ParentSuccess, nil

}

func updateParents(
	logger *pterm.Logger,
	cwd string,
	rootParents []modules.Package,
) (ParentUpdateResult, error) {
	for _, parent := range rootParents {
		result, err := updateParentAndCheck(logger, cwd, parent)

		switch result {
		case ParentError:
			return ParentError, errors.Cause(err)
		case ParentBrokeBuild:
			return ParentBrokeBuild, nil
		case ParentUpdateNoUpdateAvailable:
			return ParentUpdateNoUpdateAvailable, nil
		case ParentSuccess:
			continue

		}
	}
	return ParentSuccess, nil

}

func updateParentAndCheck(
	logger *pterm.Logger,
	cwd string,
	parent modules.Package,
) (ParentUpdateResult, error) {
	logger.Debug(
		"Checking updates for parent package ",
		logger.Args("parent", parent.Name, "version", parent.Version),
	)
	newestVersion, updateAvailable, err := checkUpdateAvailable(parent)

	if err != nil {
		return ParentError, errors.Cause(err)
	}

	if !updateAvailable {
		logger.Info(
			"No update available for parent package ",
			logger.Args("parent", parent.Name, "version", parent.Version),
		)
		return ParentUpdateNoUpdateAvailable, nil
	}
	logger.Info(
		"Updating parent package ",
		logger.Args("parent", parent.Name, "version", parent.Version, "newVersion", newestVersion),
	)

	err = modules.UpdatePackage(cwd, parent.Name, newestVersion)
	if err != nil {
		// sometimes the build already breaks during an update
		// we assume that this is the case, because I don't know to differentiate atm
		return ParentBrokeBuild, nil
		// return ParentError, errors.Cause(err)
	}

	if !modules.VetSuceeds(cwd) {
		logger.Info("Parent update broke build ")
		return ParentBrokeBuild, nil
	}
	return ParentSuccess, nil
}

type ParentUpdateResult int

const (
	ParentUpdateNoUpdateAvailable ParentUpdateResult = iota
	ParentBrokeBuild
	ParentDidNotFixVulnerability
	ParentSuccess
	ParentError
	ParentNotTried
)

type ReplaceResult int

const (
	ResultNoUpdateAvailable ReplaceResult = iota
	ReplaceBrokeBuild
	ReplaceDidNotFixVulnerability
	ReplaceSuccess
	ReplaceError
	ReplaceNotTried
)

type SanityCheckResult int

type UpdateResult struct {
	ReplaceResult ReplaceResult
	ParentResult  ParentUpdateResult
}

func makeEmptyUpdateResult() UpdateResult {
	return UpdateResult{
		ReplaceResult: ReplaceNotTried,
		ParentResult:  ParentNotTried,
	}
}

type FixResult struct {
	ReplaceResult ReplaceResult
	ParentResult  ParentUpdateResult
	Ignored       bool
}

type FixReason int

const (
	ReasonNotFixed FixReason = iota
	ReasonFixedViaReplace
	ReasonFixedViaParent
	ReasonIgnored
)

func (r FixReason) String() string {
	switch r {
	case ReasonNotFixed:
		return "not fixed"
	case ReasonFixedViaReplace:
		return "fixed via replace"
	case ReasonFixedViaParent:
		return "fixed via parent"
	case ReasonIgnored:
		return "ignored"
	}
	return "unknown"
}

func (r FixResult) getFixReason() FixReason {
	if r.Ignored {
		return ReasonIgnored
	}
	if r.ReplaceResult == ReplaceSuccess {
		return ReasonFixedViaReplace
	}
	if r.ParentResult == ParentSuccess {
		return ReasonFixedViaParent
	}
	return ReasonNotFixed
}

type FixReasonSummary struct {
	NotFixedCount        int
	FixedViaReplaceCount int
	FixedViaParentCount  int
	IgnoredCount         int
}

func makeFixReasonsummary() FixReasonSummary {
	return FixReasonSummary{
		NotFixedCount:        0,
		FixedViaReplaceCount: 0,
		FixedViaParentCount:  0,
		IgnoredCount:         0,
	}
}

func (r FixReasonSummary) String() string {
	return fmt.Sprintf(
		"not fixed: %d, fixed via replace: %d, fixed via parent: %d, ignored: %d",
		r.NotFixedCount,
		r.FixedViaReplaceCount,
		r.FixedViaParentCount,
		r.IgnoredCount,
	)

}

func (r FixReasonSummary) Update(fixResult FixResult) FixReasonSummary {
	switch fixResult.getFixReason() {
	case ReasonNotFixed:
		r.NotFixedCount++
	case ReasonFixedViaReplace:
		r.FixedViaReplaceCount++
	case ReasonFixedViaParent:
		r.FixedViaParentCount++
	case ReasonIgnored:
		r.IgnoredCount++
	}
	return r
}

func makeEmptyFixResult() FixResult {
	return FixResult{
		ReplaceResult: ReplaceNotTried,
		ParentResult:  ParentNotTried,
		Ignored:       false,
	}
}

func (r FixResult) injectUpdateResult(updateResult UpdateResult) FixResult {
	r.ReplaceResult = updateResult.ReplaceResult
	r.ParentResult = updateResult.ParentResult
	return r
}

func (r FixResult) isFixed() bool {
	return r.ReplaceResult == ReplaceSuccess || r.ParentResult == ParentSuccess || r.Ignored
}

func updateWithReplaceAndCheck(
	logger *pterm.Logger,
	cwd string,
	p nancy.VulnerablePackage,
	newestVersion modules.SemanticVersion,
) (ReplaceResult, error) {
	err := modules.UpdatePackageWithReplace(
		cwd,
		p.Name,
		p.Version,
		newestVersion,
	)

	if err != nil {
		if modules.IsGoModTidyError(err) {
			return ReplaceBrokeBuild, nil
		}
		return ReplaceError, errors.Cause(err)
	}

	result, err := performSanityCheck(logger, cwd, p.ToPackage())
	if err != nil {
		return ReplaceError, errors.Cause(err)
	}
	return result, nil
}

func performSanityCheck(
	logger *pterm.Logger,
	cwd string,
	p modules.Package,
) (result ReplaceResult, err error) {
	isFixed, err := checkVulnerabilityFixed(logger, cwd, p.Name)
	if err != nil {
		return ReplaceError, errors.Cause(err)
	}
	if !isFixed {
		return ReplaceDidNotFixVulnerability, nil
	}

	if !modules.VetSuceeds(cwd) {
		return ReplaceBrokeBuild, nil
	}
	return ReplaceSuccess, nil
}

func checkVulnerabilityFixed(
	logger *pterm.Logger,
	cwd string,
	name modules.PackageName,
) (bool, error) {
	newVulnerablePackages, err := nancy.GetVulnerablePackages(logger, cwd)
	if err != nil {
		return false, errors.Cause(err)
	}
	if nancy.VulnerablePackagesContain(newVulnerablePackages, name) {
		return false, nil
	}
	return true, nil

}
