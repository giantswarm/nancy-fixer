package gocli

import "github.com/giantswarm/microerror"

var stderrNotEmpty = &microerror.Error{
	Kind: "stderrNotEmpty",
}

func IsStderrNotEmpty(err error) bool {
	return microerror.Cause(err) == stderrNotEmpty
}
