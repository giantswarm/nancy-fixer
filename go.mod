module github.com/giantswarm/nancy-fixer

go 1.26.0

toolchain go1.27.2

require (
	github.com/giantswarm/microerror v0.4.1
	github.com/pkg/errors v0.9.1
	github.com/pterm/pterm v0.12.84
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
	golang.org/x/mod v0.41.0
)

require (
	atomicgo.dev/cursor v0.2.0 // indirect
	atomicgo.dev/keyboard v0.2.10 // indirect
	atomicgo.dev/schedule v0.1.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/containerd/console v1.0.5 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lithammer/fuzzysearch v1.1.8 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/term v0.44.0 // indirect
	golang.org/x/text v0.38.0 // indirect
)

replace golang.org/x/net v0.6.0 => golang.org/x/net v0.56.0

replace golang.org/x/text v0.38.0 => golang.org/x/text v0.40.0
