# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Email X-Ray is a security-focused tool, and we take security seriously. If you discover a security vulnerability, please follow responsible disclosure practices:

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email details to: [your-security-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-3 days
  - High: 3-7 days
  - Medium: 7-14 days
  - Low: 14-30 days

### Security Considerations

Email X-Ray is designed with security in mind:

- ✅ All processing happens locally (no external servers)
- ✅ Minimal permissions (only Gmail/Yahoo Mail domains)
- ✅ No data collection or transmission
- ✅ Content Security Policy (CSP) enforced
- ✅ No external dependencies
- ✅ No network requests from content scripts

### Known Limitations

- Heuristic detection may produce false positives/negatives
- Cannot detect all possible phishing techniques
- Only scans visible email content (not attachments)
- Requires user-initiated scan (not automatic)

### Security Best Practices for Users

1. Keep the extension updated
2. Only install from trusted sources
3. Review scan results carefully
4. Don't rely solely on this tool for email security
5. Report suspicious emails to your email provider
6. Use multi-factor authentication

### Disclosure Policy

We request that you:
- Allow us reasonable time to fix the vulnerability before public disclosure
- Do not exploit the vulnerability beyond what's necessary for demonstration
- Make a good faith effort to avoid data destruction or privacy violations

We commit to:
- Acknowledging your report promptly
- Keeping you informed of our progress
- Crediting you in security advisories (if desired)
- Not taking legal action against good-faith security researchers

## Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be listed here (with permission).

---

Thank you for helping keep Email X-Ray secure!
