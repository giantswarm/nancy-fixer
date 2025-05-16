# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Resolve updated code linter findings.

## [0.5.0] - 2025-05-14

### Changed

- Updated nancy binary.
- Fixed issue where the image would fail when run inside a Github Action container.

## [0.4.4] - 2024-04-03

- Fix dependency gathering for `nancy sleuth` to unly use return Go modules used in the current project (`go list -json -deps ./...`). Before, all Go modules in the environment were used (`go list -json -deps all`).

## [0.4.3] - 2024-02-06

### Changed

- Fix ignores being deleted.

## [0.4.2] - 2024-02-02

### Changed

- Fix array out of bounds issue on ignore files.

## [0.4.1] - 2024-02-02

### Changed

- Fix minor fixes on ignore files reading and creation.

## [0.4.0] - 2024-01-31

### Changed

- Reduce ignores expiration time to 30 days.
- Remove ignores when expired.

## [0.3.1] - 2024-01-19

### Changed

- Fix infinite loop when fixing a dependency fails.

## [0.3.0] - 2023-12-07

### Changed

- Specify current used version when fixing by replace.

## [0.2.0] - 2023-07-04

## [0.1.0] - 2023-07-04

[Unreleased]: https://github.com/giantswarm/nancy-fixer/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/giantswarm/nancy-fixer/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/giantswarm/nancy-fixer/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/giantswarm/nancy-fixer/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/giantswarm/nancy-fixer/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/giantswarm/nancy-fixer/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/giantswarm/nancy-fixer/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/giantswarm/nancy-fixer/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/giantswarm/nancy-fixer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/giantswarm/nancy-fixer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/giantswarm/nancy-fixer/releases/tag/v0.1.0
