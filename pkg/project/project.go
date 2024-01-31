package project

var (
	description = "CLI to automatically fix nancy vulnerabilities"
	gitSHA      = "n/a"
	name        = "nancy-fixer"
	source      = "https://github.com/giantswarm/nancy-fixer"
	version     = "0.4.0"
)

func Description() string {
	return description
}

func GitSHA() string {
	return gitSHA
}

func Name() string {
	return name
}

func Source() string {
	return source
}

func Version() string {
	return version
}
