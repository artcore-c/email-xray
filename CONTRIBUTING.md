# Contributing to Email X-Ray

Thank you for your interest in contributing to Email X-Ray! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment

## How to Contribute

### Reporting Bugs

If you find a bug:

1. Check if it's already reported in [Issues](https://github.com/artcore-c/email-xray/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots (if applicable)
   - Browser version and OS

### Suggesting Features

Feature requests are welcome! Please:

1. Check existing issues/PRs first
2. Explain the use case
3. Describe the proposed solution
4. Consider security implications

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Follow the existing code style
   - Add comments for complex logic
   - Test thoroughly

4. **Commit your changes**:
   ```bash
   git commit -m "Add feature: brief description"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**:
   - Describe what the PR does
   - Reference any related issues
   - Include test results

## Development Setup

1. Clone your fork:
   ```bash
   git clone https://github.com/artcore-c/email-xray.git
   cd email-xray
   ```

2. Load in Chrome:
   - Open `chrome://extensions/`
   - Enable Developer mode
   - Click "Load unpacked"
   - Select the `email-xray` folder

3. Make changes and reload the extension to test

## Code Style Guidelines

### JavaScript

- Use ES6+ features
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small
- Use `const` by default, `let` when needed
- Avoid `var`

### CSS

- Use semantic class names
- Prefix custom classes with `exr-`
- Keep specificity low
- Use CSS variables for colors
- Group related styles

### Naming Conventions

- Files: `kebab-case.js`
- Classes: `PascalCase`
- Functions: `camelCase`
- Constants: `UPPER_SNAKE_CASE`
- CSS classes: `kebab-case`

## Testing

Before submitting a PR:

1. **Manual Testing**:
   - Test on Gmail and Yahoo Mail
   - Test all detection types
   - Test keyboard shortcuts
   - Test export functionality

2. **Browser Testing**:
   - Chrome (latest)
   - Test on macOS if possible

3. **Test Cases**:
   - Create test emails with hidden content
   - Verify detection accuracy
   - Check for false positives

## Detection Logic

When adding new detection methods:

1. **Be specific**: Minimize false positives
2. **Be performant**: Avoid blocking the UI
3. **Be secure**: Don't introduce vulnerabilities
4. **Document**: Explain the detection method
5. **Categorize**: Assign appropriate severity

### Severity Guidelines

- **CRITICAL**: Immediate security threat
  - Hidden iframes with external sources
  - JavaScript/data URLs in links
  - Invisible text with suspicious content

- **WARNING**: Potentially suspicious
  - Tracking pixels
  - Homograph attacks
  - Off-screen positioning

- **INFO**: Worth noting
  - Minor styling anomalies
  - Long alt text
  - Clip-path usage

## Security Considerations

All contributions must:

- ✅ Process data locally only
- ✅ Not introduce external dependencies
- ✅ Not make network requests from content scripts
- ✅ Not access or transmit user data
- ✅ Follow principle of least privilege

## Documentation

When adding features:

- Update README.md
- Add code comments
- Update detection list if applicable
- Consider adding examples

## Release Process

(For maintainers)

1. Update version in `manifest.json`
2. Update CHANGELOG.md
3. Create git tag: `git tag v1.x.x`
4. Push tag: `git push origin v1.x.x`
5. Create GitHub release
6. Update Chrome Web Store listing

## Questions?

- Open a GitHub Discussion
- Comment on relevant issues
- Check existing documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Email X-Ray! 🔍
