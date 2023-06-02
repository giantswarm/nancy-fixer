# nancy-fixer

`nancy-fixer` is a CLI tool that scans and automatically fixes nancy
vulnerabilities.

## Installation

```
go install github.com/giantswarm/nancy-fixer@latest
```

## Usage

To fix vulnerabilities in the repository in the current directory use:
```
nancy-fixer fix
```

To specify a different directory use:
```
nancy-fixer fix --dir PATH
```



## Steps 
For each vulnerability, `nancy-fixer` will try three steps:
1. Update all dependencies that require the vulnerable package (in the case of a direct dependency this could be simply the vulnerable package itself)
2. Update the vulnerable package by adding a `replace` in the `go.mod` file.
3. Ignore the vulnerable package.

