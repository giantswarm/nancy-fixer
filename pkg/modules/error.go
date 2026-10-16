package modules

import "errors"

var invalidSemVerError = errors.New("invalidSemVerError")

func IsInvalidSemVerError(err error) bool {
	return errors.Is(err, invalidSemVerError)
}

var invalidDependencyLineError = errors.New("invalidDependencyLineError")

func IsInvalidDependencyLineError(err error) bool {
	return errors.Is(err, invalidDependencyLineError)
}

var invalidModuleListError = errors.New("invalidModuleListError")

func IsInvalidModuleListError(err error) bool {
	return errors.Is(err, invalidModuleListError)
}

var noVersionsFoundError = errors.New("noVersionsFoundError")

func IsNoVersionsFoundError(err error) bool {
	return errors.Is(err, noVersionsFoundError)
}

var goModTidyError = errors.New("goModTidyError")

func IsGoModTidyError(err error) bool {
	return errors.Is(err, goModTidyError)
}
