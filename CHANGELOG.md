# Changelog

All notable changes to Email X-Ray will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-11-27

### Added
- Initial release of Email X-Ray
- Real-time email scanning for Gmail and Yahoo Mail
- Detection of hidden text (0px font, opacity 0, visibility hidden)
- Detection of tracking pixels (1x1 images)
- Detection of suspicious links (data URLs, JavaScript URLs, URL mismatches)
- Homograph attack detection (lookalike Unicode characters)
- Invisible iframe detection
- Zero-width character detection
- Suspicious image metadata detection (long alt text)
- Color camouflage detection (text color matching background)
- Visual highlighting with severity levels (Critical, Warning, Info)
- Interactive results panel with detailed findings
- Export scan results as JSON
- Keyboard shortcut support (⌘+⇧+X / Ctrl+Shift+X)
- Clean, modern UI with gradient design
- Minimal permissions (Gmail and Yahoo Mail only)
- Content Security Policy enforcement
- Privacy-first design (100% local processing)

### Security
- No data collection or transmission
- All processing happens locally in browser
- Strict CSP prevents code injection
- Minimal host permissions
- No external dependencies

---

## Release Notes Format

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security improvements

---

[Unreleased]: https://github.com/yourusername/email-xray/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/yourusername/email-xray/releases/tag/v1.0.0
