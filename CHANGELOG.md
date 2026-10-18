# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure
- Core IOC scanning functionality
- YARA rules integration
- PowerShell equivalent script
- Basic OSINT enrichment module
- Docker support
- GitHub Actions CI/CD pipeline

### Changed
- N/A

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- All scanning operations are read-only by default
- Network enrichment requires explicit flag
- No API keys stored in repository

## [1.0.0] - 2025-09-25

### Added
- Initial release with complete IOC detection framework
- Support for hash-based detection (MD5, SHA1, SHA256)
- YARA rules engine integration
- Process scanning capabilities
- Log parsing functionality
- Markdown and HTML report generation
- Cross-platform support (Linux/Windows)