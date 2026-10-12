package revisions

import "errors"

var invalidRevisionError = errors.New("invalidRevisionError")

func IsInvalidRevision(err error) bool {
	return errors.Is(err, invalidRevisionError)
}
