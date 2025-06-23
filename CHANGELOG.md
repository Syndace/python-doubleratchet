# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Changed the `JSONType` type again to use `Mapping` instead of `Dict`

## [1.1.2] - 23rd of June 2025

### Changed
- Simplified the `JSONObject` type now that recursive aliases are properly supported

## [1.1.1] - 21st of June 2025

### Removed
- Removed project.py and simplified version.py as part of the migration towards pyproject.toml

## [1.1.0] - 15th of October 2024

### Changed
- Drop support for Python3.8, add support for Python3.13, bump PyPy test version to 3.10
- Internal housekeeping, mostly related to pylint

## [1.0.4] - 9th of July 2024

### Changed
- 2024 maintenance (bumped Python versions, adjusted for updates to pydantic, mypy, pylint and GitHub actions)

## [1.0.3] - 8th of November 2022

### Changed
- Exclude tests from the packages

## [1.0.2] - 5th of November 2022

### Changed
- Fixed a bug in the way the storage models were versioned

## [1.0.1] - 3rd of November 2022

### Added
- Python 3.11 to the list of supported versions

### Removed
- Unnecessary NotImplementedErrors in abstract methods

## [1.0.0] - 1st of November 2022

### Added
- Rewrite for modern, type safe Python 3.

### Removed
- Pre-stable (i.e. versions before 1.0.0) changelog omitted.

[Unreleased]: https://github.com/Syndace/python-doubleratchet/compare/v1.1.2...HEAD
[1.1.2]: https://github.com/Syndace/python-doubleratchet/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Syndace/python-doubleratchet/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Syndace/python-doubleratchet/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Syndace/python-doubleratchet/releases/tag/v1.0.0
