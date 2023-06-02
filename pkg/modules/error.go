package modules

import "github.com/giantswarm/microerror"

var invalidSemVerError = &microerror.Error{
	Kind: "invalidSemVerError",
}

func IsInvalidSemVerError(err error) bool {
	return microerror.Cause(err) == invalidSemVerError
}

var invalidDependencyLineError = &microerror.Error{
	Kind: "invalidDependencyLineError",
}

func IsInvalidDependencyLineError(err error) bool {
	return microerror.Cause(err) == invalidDependencyLineError
}

var invalidModuleListError = &microerror.Error{
	Kind: "invalidModuleListError",
}

func IsInvalidModuleListError(err error) bool {
	return microerror.Cause(err) == invalidModuleListError
}

var noVersionsFoundError = &microerror.Error{
	Kind: "noVersionsFoundError",
}

func IsNoVersionsFoundError(err error) bool {
	return microerror.Cause(err) == noVersionsFoundError
}

var goModTidyError = &microerror.Error{
	Kind: "goModTidyError",
}

func IsGoModTidyError(err error) bool {
	return microerror.Cause(err) == goModTidyError
}

