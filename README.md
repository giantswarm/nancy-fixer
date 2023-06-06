# nancy-fixer

`nancy-fixer` is a CLI tool that scans and automatically fixes nancy
vulnerabilities.

## Installation
Make sure that you have [nancy](https://gonancy.dev/).

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

## Limitations

### Major Versions
Currently, `nancy-fixer` is not aware of different module names for different major versions.
For example, say you have the dependency `github.com/my/mod/v4` with version
`v4.1.0`, but there is a version `v5.0.0` available. This would require you to 
change the imported module to `github.com/my/mod/v5`.
However, `nancy-fixer` will never try that.

Because of how major versions worked without changing this `vN` postfix before
go modules, `nancy-fixer` will do major version bumps for packages that did not
yet introduce modules.
[This stackoverflow question](https://stackoverflow.com/questions/57355929/what-does-incompatible-in-go-mod-mean-will-it-cause-harm)
might explain more in that regard.
