# Changelog

All notable changes to Email X-Ray will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-11-27

### Added (Additional Security Enhancements from previous 0.0.9)
- **Enhanced Detection Engine**: Expanded from basic hidden text detection to 8 comprehensive threat types
- **Homograph Attack Detection**: Added detection for lookalike Unicode characters (Cyrillic, Greek confusables)
- **Invisible iFrame Detection**: Added detection for hidden credential harvesting attempts
- **Zero-Width Character Detection**: Added scanning for invisible Unicode characters (U+200B-U+200D, etc.)
- **Link Analysis**: Added detection for JavaScript URLs, data URLs, and URL/text mismatches
- **Suspicious Image Detection**: Added scanning for long alt text on hidden images
- **Color Camouflage Detection**: Enhanced to detect text color matching background color
- **Off-Screen Positioning Detection**: Added detection for text-indent and absolute positioning tricks

### Changes (GUI Improvements to previous 0.0.9)
- **Gmail/Yahoo Specific Selectors**: Optimized DOM targeting for both email platforms
- **Severity Classification System**: Added three-tier system (Critical/Warning/Info) vs. single severity
- **Interactive Results Panel**: 
  - Added statistics dashboard with color-coded counts
  - Click findings to scroll to elements in email
  - Minimize/maximize controls
  - Professional gradient design
- **Visual Highlighting**: 
  - Color-coded by severity (red/orange/blue)
  - Hover effects and animations
  - Pulse animation when scrolling to elements
- **Export Functionality**: Added JSON export with structured findings data
- **Keyboard Shortcut**: Added ⌘+Shift+X / Ctrl+Shift+X quick scan
- **Performance**: Optimized DOM traversal using TreeWalker API
- **Error Handling**: Added comprehensive error handling and user feedback

### Security Improvements
- **Content Security Policy**: Enforced strict CSP in manifest
- **Minimal Permissions**: Restricted to only Gmail and Yahoo Mail domains (no `<all_urls>`)
- **Host Permissions**: Changed from broad permissions to specific host_permissions
- **Storage Permission**: Added for future user preferences (not yet implemented)

### UI/UX Improvements
- **Modern Design**: Professional gradient design (purple/violet theme)
- **Responsive Panel**: Max-height with scrolling, better positioning
- **Status Feedback**: Clear scanning/success/error states in popup
- **Accessibility**: Better color contrast and readable fonts
- **macOS Integration**: Native-style aesthetics for macOS Chrome

### Documentation
- Comprehensive README with feature descriptions and usage guide
- Detailed INSTALLATION guide with troubleshooting
- CONTRIBUTING guidelines for open source collaboration
- SECURITY policy for vulnerability disclosure
- Clear LICENSE (MIT)

### Core Features (Retained)
- Hidden text detection (0px font, opacity 0, visibility hidden)
- Tracking pixel detection (1x1 images)
- Summary panel with findings list
- Element highlighting on page
- Close/remove panel functionality

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
