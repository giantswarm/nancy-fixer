package revisions

import "github.com/giantswarm/microerror"

var invalidRevisionError = &microerror.Error{
	Kind: "invalidRevisionError",
}

func IsInvalidRevision(err error) bool {
	return microerror.Cause(err) == invalidRevisionError
}
