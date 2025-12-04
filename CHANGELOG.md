# Changelog

All notable changes to Email X-Ray will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.8] - 2024-12-03

### Added
- New extension icons with improved visibility at small scales
- demo_02.jpg: Malicious attachment detection example
- demo_03.jpg: Multiple threat types (tracking pixels, brand impersonation, homograph attacks)
- Expanded screenshot descriptions in README
- Organized assets into banner/ and screenshots/ directories

### Changed
- Redesigned icons for better Chrome toolbar visibility

## [1.1.0] - 2024-11-29

### Added
- **Suspicious Attachment Detection** - Detects malicious PDF attachments and fake file downloads
  - Dangerous file extensions (.exe, .scr, .bat, .vbs, .js, .jar, .apk, .msi, etc.)
  - Double extension tricks (e.g., invoice.pdf.exe)
  - Gibberish/random filename patterns (no vowels, all caps with numbers)
  - Common phishing attachment names (invoice, urgent, verify, confirm, payment, etc.)
  - External hosting detection (attachments not hosted on Gmail/Yahoo servers)
- **Unsubscribe Link Spoofing Detection** - Identifies fake unsubscribe mechanisms
  - JavaScript unsubscribe traps (javascript: URLs)
  - Data URL unsubscribe forms (fake embedded forms)
  - Suspicious TLD usage in unsubscribe links (.top, .xyz, .click, etc.)
  - Embedded unsubscribe forms in email body (phishing red flag)
- **Enhanced Tracking Pixel Detection**
  - SVG-based tracking with zero dimensions but active viewBox
  - Remote SVG image references pointing to tracking servers
  - CSS background-image tracking on hidden elements
  - Comprehensive element scanning beyond traditional <img> tags
- **Reply-To Spoofing Detection** - Identifies email header manipulation
  - Domain mismatch between sender and reply-to addresses
  - No-reply sender but replies go to real mailbox
  - Corporate sender with free email reply-to (Gmail, Yahoo, Outlook)
- **URL Reputation Heuristics** - Advanced link analysis without network lookups
  - Excessive dashes in domains (---) 
  - Long numeric sequences (likely auto-generated)
  - Suspicious TLDs commonly used in phishing
  - Excessive subdomain depth (login.verify.account.security.example.com)
  - Brand impersonation patterns (amazon.verifyaccount.ru)
  - @ symbol URL obfuscation tricks
- **Advanced CSS Detection**
  - CSS filter detection (brightness(0%), blur effects)
  - Mix-blend-mode detection (difference, multiply)
  - Backdrop-filter detection
  - Clip-path hiding techniques

### Changed
- Improved Yahoo Mail attachment selector to use `data-test-id` attributes for reliability
- Enhanced tracking pixel detection to cover more sophisticated techniques
- Total detection methods increased from 8 to 11
- Better element highlighting and finding system with pulse animations
- Upgraded to 30+ specific threat detection patterns

### Fixed
- Popup connection errors when extension is reloaded
- Attachment detection now properly identifies Yahoo Mail attachments
- Resolved JavaScript errors related to const variable reassignment
- Gmail reading view check prevents false scans in inbox/compose views
- Unicode normalization (NFKC) for better homograph detection
- Regex stateful issue with zero-width character detection (.test() → .match())

### Technical Improvements
- File size: ~1,070 lines of production-ready code
- Added proper error handling for all detection methods
- Improved selector specificity for Yahoo Mail compatibility
- Better separation of concerns between detection methods

## [1.0.0] - 2024-11-27

### Added (Additional Security Enhancements from previous 0.9.8)
- **Enhanced Detection Engine**: Expanded from basic hidden text detection to 8 comprehensive threat types
- **Homograph Attack Detection**: Added detection for lookalike Unicode characters (Cyrillic, Greek confusables)
- **Invisible iFrame Detection**: Added detection for hidden credential harvesting attempts
- **Zero-Width Character Detection**: Added scanning for invisible Unicode characters (U+200B-U+200D, etc.)
- **Link Analysis**: Added detection for JavaScript URLs, data URLs, and URL/text mismatches
- **Suspicious Image Detection**: Added scanning for long alt text on hidden images
- **Color Camouflage Detection**: Enhanced to detect text color matching background color
- **Off-Screen Positioning Detection**: Added detection for text-indent and absolute positioning tricks

### Changes (GUI Improvements to previous 0.9.8)
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

[Unreleased]: https://github.com/artcore-c/email-xray/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/artcore-c/email-xray/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/artcore-c/email-xray/releases/tag/v1.0.0
