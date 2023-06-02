package logging

import "github.com/giantswarm/microerror"

var invalidLogLevelError = &microerror.Error{
	Kind: "invalidLogLevelError",
}

func IsInvalidLogLevelError(err error) bool {
	return microerror.Cause(err) == invalidLogLevelError
}

var invalidLogFormatterError = &microerror.Error{
	Kind: "invalidLogFormatterError",
}

func IsInvalidLogFormatterError(err error) bool {
	return microerror.Cause(err) == invalidLogFormatterError
}
