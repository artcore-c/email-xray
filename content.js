// Email X-Ray - Content Script
// Detects hidden phishing tactics in Gmail and Yahoo Mail

const EXR = {
  findings: [],
  scanInProgress: false,
  
  // Threat severity levels
  SEVERITY: {
    CRITICAL: 'critical',
    WARNING: 'warning',
    INFO: 'info'
  },
  
  // Gmail/Yahoo specific selectors
  SELECTORS: {
    gmail: {
      emailBody: '.a3s.aiL, .ii.gt',
      emailContainer: '.nH.if',
      allElements: '.a3s.aiL *, .ii.gt *'
    },
    yahoo: {
      emailBody: '[data-test-id="message-view-body-content"]',
      emailContainer: '#mail-app-component',
      allElements: '[data-test-id="message-view-body-content"] *'
    }
  },
  
  // Detect which email service we're on
  detectEmailService() {
    if (window.location.hostname.includes('mail.google.com')) {
      return 'gmail';
    } else if (window.location.hostname.includes('mail.yahoo.com')) {
      return 'yahoo';
    }
    return null;
  },
  
  // Zero-width and invisible Unicode characters
  ZERO_WIDTH_CHARS: /[\u200B-\u200D\uFEFF\u2060\u180E\u061C\u202A-\u202E]/g,
  
  // Homograph attack detection - confusable characters
  CONFUSABLES: {
    'a': ['а', 'ạ', 'ă', 'ą', 'α', 'а'],
    'e': ['е', 'ė', 'ę', 'ε', 'е'],
    'o': ['о', 'ο', 'σ', 'о', '᧐'],
    'p': ['р', 'ρ', 'р'],
    'c': ['с', 'ϲ', 'с'],
    'i': ['і', 'ı', 'ɪ', 'і', '۱'],
    'l': ['l', 'ǀ', '│', 'Ι', '۱'],
    'm': ['м', 'ṁ'],
    'n': ['п', 'ո'],
    's': ['ѕ', 'ꜱ'],
    'x': ['х', 'χ', 'х'],
    'y': ['у', 'ү', 'у']
  },
  
  // Initialize the scanner
  init() {
    console.log('[Email X-Ray] Initialized');
    
    // Listen for scan requests
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg && msg.type === 'EXR_SCAN') {
        this.performScan().then(results => {
          sendResponse({ ok: true, results });
        }).catch(err => {
          console.error('[Email X-Ray] Scan error:', err);
          sendResponse({ ok: false, error: err.message });
        });
        return true; // Keep channel open for async response
      }
    });
    
    // Listen for keyboard shortcut
    chrome.commands?.onCommand?.addListener((command) => {
      if (command === 'scan-email') {
        this.performScan();
      }
    });
  },
  
  // Main scan function
  async performScan() {
    if (this.scanInProgress) {
      console.log('[Email X-Ray] Scan already in progress');
      return;
    }
    
    this.scanInProgress = true;
    this.findings = [];
    
    // Clear previous highlights
    this.clearHighlights();
    
    const emailService = this.detectEmailService();
    if (!emailService) {
      console.warn('[Email X-Ray] Not on Gmail or Yahoo Mail');
      this.scanInProgress = false;
      return;
    }
    
    console.log(`[Email X-Ray] Scanning ${emailService}...`);
    
    // Abort scan if Gmail is not displaying a message
    if (emailService === 'gmail') {
      const readingView = document.querySelector('.aeH .adn');
      if (!readingView) {
        console.warn('[Email X-Ray] Gmail message view not detected.');
        this.scanInProgress = false;
        return;
      }
    }
    
    const selectors = this.SELECTORS[emailService];
    const emailBody = document.querySelector(selectors.emailBody);
    
    if (!emailBody) {
      console.warn('[Email X-Ray] Email body not found');
      this.scanInProgress = false;
      return;
    }
    
    // Run all detection methods
    this.scanForHiddenText(emailBody);
    this.scanForTrackingPixels(emailBody);
    this.scanForSuspiciousLinks(emailBody);
    this.scanForHomographAttacks(emailBody);
    this.scanForInvisibleIframes(emailBody);
    this.scanForZeroWidthChars(emailBody);
    this.scanForSuspiciousImages(emailBody);
    this.scanForUnsubscribeSpoof(emailBody);
    this.scanForSuspiciousAttachments(emailBody);
    await this.scanForReplyToSpoofing();
    
    // Display results
    this.displayResults();
    
    this.scanInProgress = false;
    return this.findings;
  },
  
  // Detection: Hidden text via CSS
  scanForHiddenText(container) {
    const walker = document.createTreeWalker(
      container,
      NodeFilter.SHOW_ELEMENT,
      null,
      false
    );
    
    let node;
    while ((node = walker.nextNode())) {
      if (!(node instanceof Element)) continue;
      
      const cs = getComputedStyle(node);
      const text = (node.textContent || '').trim();
      
      if (!text || text.length < 2) continue;
      
      const threats = [];
      
      // Font size detection
      const fontSize = parseFloat(cs.fontSize) || 0;
      if (fontSize === 0) {
        threats.push({
          type: 'hidden-text',
          reason: 'Font size is 0px - invisible text',
          severity: this.SEVERITY.CRITICAL
        });
      } else if (fontSize > 0 && fontSize <= 1) {
        threats.push({
          type: 'hidden-text',
          reason: `Font size is ${fontSize}px - nearly invisible`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Opacity detection
      const opacity = parseFloat(cs.opacity);
      if (opacity === 0) {
        threats.push({
          type: 'hidden-text',
          reason: 'Opacity is 0 - completely transparent',
          severity: this.SEVERITY.CRITICAL
        });
      } else if (opacity > 0 && opacity < 0.1) {
        threats.push({
          type: 'hidden-text',
          reason: `Opacity is ${opacity} - nearly transparent`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Visibility/Display detection
      if (cs.visibility === 'hidden' || cs.display === 'none') {
        threats.push({
          type: 'hidden-text',
          reason: `CSS hidden (${cs.visibility}/${cs.display})`,
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // filter: blur(0px) brightness(0%)/backdrop-filter
      if (cs.filter && cs.filter !== 'none') {
        threats.push({
          type: 'hidden-text',
          reason: `CSS filter used (${cs.filter})`,
          severity: this.SEVERITY.INFO
        });
      }
      
      // mix-blend-mode: difference
      if (cs.mixBlendMode && cs.mixBlendMode !== 'normal') {
        threats.push({
          type: 'hidden-text',
          reason: `Blend mode '${cs.mixBlendMode}' may conceal text`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Color camouflage detection
      if (this.colorsAreSimilar(cs.color, cs.backgroundColor)) {
        threats.push({
          type: 'hidden-text',
          reason: 'Text color matches background - camouflaged',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // Off-screen positioning
      const textIndent = parseFloat(cs.textIndent) || 0;
      if (textIndent < -100) {
        threats.push({
          type: 'hidden-text',
          reason: `Text indented ${textIndent}px off-screen`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      const position = cs.position;
      const left = parseFloat(cs.left) || 0;
      const top = parseFloat(cs.top) || 0;
      
      if ((position === 'absolute' || position === 'fixed') && (left < -500 || top < -500)) {
        threats.push({
          type: 'hidden-text',
          reason: `Positioned off-screen (${left}px, ${top}px)`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Clip-path hiding
      if (cs.clipPath && cs.clipPath !== 'none') {
        threats.push({
          type: 'hidden-text',
          reason: 'Uses clip-path (potentially hiding content)',
          severity: this.SEVERITY.INFO
        });
      }
      
      if (threats.length > 0) {
        const highestSeverity = this.getHighestSeverity(threats.map(t => t.severity));
        this.addFinding(node, threats, text.substring(0, 150), highestSeverity);
      }
    }
  },
  
  // Detection: Tracking pixels (1x1 images, SVGs, CSS backgrounds)
  scanForTrackingPixels(container) {
    // Check traditional img tags
    const images = container.querySelectorAll('img');
  
    images.forEach(img => {
      const cs = getComputedStyle(img);
      const width = img.width || parseInt(img.getAttribute('width')) || 0;
      const height = img.height || parseInt(img.getAttribute('height')) || 0;
      const src = img.src || img.getAttribute('src') || '';
      const threats = [];
      
      // Traditional 1x1 or 2x2 tracking pixels
      if ((width === 1 && height === 1) || (width <= 2 && height <= 2)) {
        threats.push({
          type: 'tracking-pixel',
          reason: `Tracking pixel detected (${width}x${height})`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // CSS background-image on img tags
      const bg = cs.backgroundImage;
      if (bg && bg.includes('url(') && bg !== 'none') {
        threats.push({
          type: 'tracking-pixel',
          reason: 'CSS background-image may be a tracking pixel',
          severity: this.SEVERITY.WARNING
        });
      }
      
      if (threats.length > 0) {
        this.addFinding(img, threats, `Source: ${src.substring(0, 100)}`, this.SEVERITY.WARNING);
      }
    });
    
    // Also check SVG elements directly
    const svgs = container.querySelectorAll('svg');
    svgs.forEach(svg => {
      const cs = getComputedStyle(svg);
      const width = parseInt(svg.getAttribute('width')) || 0;
      const height = parseInt(svg.getAttribute('height')) || 0;
      const viewBox = svg.getAttribute('viewBox');
      
      // SVG with 0 dimensions but has viewBox (hidden tracking)
      if ((width === 0 || height === 0) && viewBox) {
        this.addFinding(svg, [{
          type: 'tracking-pixel',
          reason: 'SVG with zero dimensions but active viewBox (tracking)',
          severity: this.SEVERITY.WARNING
        }], `ViewBox: ${viewBox}`, this.SEVERITY.WARNING);
      }
      
      // Check for remote image references in SVG
      const svgImages = svg.querySelectorAll('image');
      svgImages.forEach(svgImg => {
        const href = svgImg.getAttribute('href') || svgImg.getAttribute('xlink:href') || '';
        if (href.startsWith('http://') || href.startsWith('https://')) {
          this.addFinding(svgImg, [{
            type: 'tracking-pixel',
            reason: 'SVG <image> references remote server (tracking)',
            severity: this.SEVERITY.WARNING
          }], `Remote: ${href.substring(0, 100)}`, this.SEVERITY.WARNING);
        }
      });
    });
    
    // Check elements with CSS background-image (not just img tags)
    const allElements = container.querySelectorAll('*');
    allElements.forEach(el => {
      if (el.tagName === 'IMG' || el.tagName === 'SVG') return; // Already checked
      
      const cs = getComputedStyle(el);
      const bg = cs.backgroundImage;
      
      if (bg && bg.includes('url(') && bg !== 'none') {
        const width = el.offsetWidth || 0;
        const height = el.offsetHeight || 0;
        
        // Flag small or hidden elements with background images
        if ((width <= 2 && height <= 2) || cs.display === 'none' || parseFloat(cs.opacity) === 0) {
          this.addFinding(el, [{
            type: 'tracking-pixel',
            reason: 'Hidden element with CSS background-image (tracking)',
            severity: this.SEVERITY.WARNING
          }], `Background: ${bg.substring(0, 100)}`, this.SEVERITY.WARNING);
        }
      }
    });
  },
  
  // Detection: Suspicious links (data URLs, javascript:, homographs)
  scanForSuspiciousLinks(container) {
    const links = container.querySelectorAll('a[href]');
    
    links.forEach(link => {
      const href = link.getAttribute('href') || '';
      const displayText = link.textContent.trim();
      const threats = [];
      
      // Data URL detection
      if (href.startsWith('data:')) {
        threats.push({
          type: 'suspicious-link',
          reason: 'Uses data: URL (can hide malicious content)',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // JavaScript URL detection
      if (href.toLowerCase().startsWith('javascript:')) {
        threats.push({
          type: 'suspicious-link',
          reason: 'Uses javascript: URL (XSS risk)',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // URL mismatch detection
      if (displayText && this.isURL(displayText) && !href.includes(this.extractDomain(displayText))) {
        threats.push({
          type: 'suspicious-link',
          reason: 'Displayed URL differs from actual link target',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // Punycode detection (IDN homograph)
      if (href.includes('xn--')) {
        threats.push({
          type: 'homograph-attack',
          reason: 'Contains punycode (potential homograph attack)',
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Extract domain safely
      let domain = '';
      try {
        domain = new URL(href).hostname.toLowerCase();
      } catch {}
      
      // --- URL REPUTATION HEURISTICS ---
      
      // Excessive dashes (---)
      if (domain.match(/-{3,}/)) {
        threats.push({
          type: 'suspicious-link',
          reason: 'Domain contains excessive dashes (---)',
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Long numeric sequences (likely random generated subdomains)
      if (domain.match(/[0-9]{6,}/)) {
        threats.push({
          type: 'suspicious-link',
          reason: 'Domain contains long numeric sequence (likely auto-generated)',
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Suspicious/abused TLDs
      const suspiciousTLDs = [
        '.top', '.xyz', '.rest', '.click', '.link', '.work', '.shop', '.buzz',
        '.space', '.online', '.gq', '.ml', '.cf', '.ga', '.tk', '.bid', '.country'
      ];
      if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        const tld = domain.split('.').pop();
        threats.push({
          type: 'suspicious-link',
          reason: `Suspicious TLD (.${tld}) often used in phishing`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Excessive subdomain depth (e.g., login.verify.account.security.example.com)
      const parts = domain.split('.');
        if (parts.length > 5) {
        threats.push({
          type: 'suspicious-link',
          reason: `Excessively long domain chain (${parts.length} subdomains)`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Brand impersonation pattern: known brand appears AFTER an unknown domain
      // Example: secure.login.amazon.verifyaccount.ru
      const famousBrands = [
        'amazon', 'apple', 'paypal', 'microsoft', 'google', 'bankofamerica',
        'chase', 'facebook', 'instagram'
      ];
      const brandMatch = famousBrands.find(b => domain.includes(b));
      
      if (brandMatch) {
        const endsCorrectly =
          domain.endsWith(`${brandMatch}.com`) ||
          domain.endsWith(`${brandMatch}.net`) ||
          domain.endsWith(`${brandMatch}.org`);
        
        if (!endsCorrectly) {
          threats.push({
            type: 'suspicious-link',
            reason: `Brand name "${brandMatch}" used in non-official domain`,
            severity: this.SEVERITY.CRITICAL
          });
        }
      }
      
      // At-symbol in link text or href (encoding tricks: foo@bar.com inside URL)
      if (href.includes('@') && !href.startsWith('mailto:')) {
        threats.push({
          type: 'suspicious-link',
          reason: 'URL contains @ symbol (possible obfuscation)',
          severity: this.SEVERITY.WARNING
        });
      }
      
      if (threats.length > 0) {
        const highestSeverity = this.getHighestSeverity(threats.map(t => t.severity));
        this.addFinding(link, threats, `Link: ${href.substring(0, 100)}`, highestSeverity);
      }
    });
  },
  
  // Detection: Homograph attacks (confusable characters)
  scanForHomographAttacks(container) {
    const links = container.querySelectorAll('a[href]');
    
    links.forEach(link => {
      const href = link.getAttribute('href') || '';
      const displayText = link.textContent.trim();
      
      // Check for confusable characters in URLs
      const text = href + displayText;
      const normalized = text.normalize('NFKC');
    
      // Count confusables in both original and normalized forms
      const confusableCount = this.countConfusableChars(text) + this.countConfusableChars(normalized);
      
      if (confusableCount > 2) {
        this.addFinding(link, [{
          type: 'homograph-attack',
          reason: `Contains ${confusableCount} confusable Unicode characters`,
          severity: this.SEVERITY.WARNING
        }], `Text: ${displayText.substring(0, 100)}`, this.SEVERITY.WARNING);
      }
    });
  },
  
  // Detection: Invisible iframes
  scanForInvisibleIframes(container) {
    const iframes = container.querySelectorAll('iframe');
    
    iframes.forEach(iframe => {
      const cs = getComputedStyle(iframe);
      const width = iframe.width || parseInt(iframe.getAttribute('width')) || 0;
      const height = iframe.height || parseInt(iframe.getAttribute('height')) || 0;
      const src = iframe.src || iframe.getAttribute('src') || '';
      
      const threats = [];
      
      if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) {
        threats.push({
          type: 'hidden-iframe',
          reason: 'Hidden iframe (potential credential harvesting)',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      if (width < 10 && height < 10) {
        threats.push({
          type: 'hidden-iframe',
          reason: `Tiny iframe (${width}x${height}) - suspicious`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      if (threats.length > 0) {
        const highestSeverity = this.getHighestSeverity(threats.map(t => t.severity));
        this.addFinding(iframe, threats, `Source: ${src.substring(0, 100)}`, highestSeverity);
      }
    });
  },
  
  // Detection: Zero-width characters
  scanForZeroWidthChars(container) {
    const walker = document.createTreeWalker(
      container,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );
    
    let node;
    while ((node = walker.nextNode())) {
      const text = node.textContent || '';
      const matches = text.match(this.ZERO_WIDTH_CHARS);
      
      if (matches && matches.length > 0) {
        const element = node.parentElement;
        if (element) {
          this.addFinding(element, [{
            type: 'zero-width-chars',
            reason: `Contains ${matches.length} zero-width/invisible characters`,
            severity: this.SEVERITY.WARNING
          }], text.replace(this.ZERO_WIDTH_CHARS, '⬜').substring(0, 150), this.SEVERITY.WARNING);
        }
      }
    }
  },
  
  // Detection: Suspicious image alt text
  scanForSuspiciousImages(container) {
    const images = container.querySelectorAll('img[alt]');
    
    images.forEach(img => {
      const alt = img.getAttribute('alt') || '';
      
      // Very long alt text on potentially hidden image
      if (alt.length > 200) {
        const cs = getComputedStyle(img);
        const width = img.width || parseInt(img.getAttribute('width')) || 0;
        const height = img.height || parseInt(img.getAttribute('height')) || 0;
        
        if (width < 10 || height < 10 || cs.display === 'none') {
          this.addFinding(img, [{
            type: 'suspicious-alt',
            reason: `Long alt text (${alt.length} chars) on hidden/tiny image`,
            severity: this.SEVERITY.INFO
          }], alt.substring(0, 150), this.SEVERITY.INFO);
        }
      }
      
      // Zero-width chars in alt text
      if (alt.match(this.ZERO_WIDTH_CHARS)) {
        this.addFinding(img, [{
          type: 'zero-width-chars',
          reason: 'Alt text contains zero-width characters',
          severity: this.SEVERITY.WARNING
        }], alt.replace(this.ZERO_WIDTH_CHARS, '⬜').substring(0, 150), this.SEVERITY.WARNING);
      }
    });
  },
  
  // Helper: Add a finding
  addFinding(element, threats, text, severity) {
    this.findings.push({
      element,
      threats,
      text,
      severity
    });
    
    // Highlight the element
    element.classList.add(`exr-${severity}`);
    
    // Add click handler to show details
    element.addEventListener('click', (e) => {
      e.preventDefault();
      this.showElementDetails(element, threats, text);
    });
  },
  
  // Helper: Color similarity check
  colorsAreSimilar(fg, bg) {
    if (!fg || !bg) return false;
    
    const rgbRegex = /rgba?\((\d+),\s*(\d+),\s*(\d+)/;
    const m1 = fg.match(rgbRegex);
    const m2 = bg.match(rgbRegex);
    
    if (!m1 || !m2) return false;
    
    const f = m1.slice(1, 4).map(Number);
    const b = m2.slice(1, 4).map(Number);
    
    const diff = Math.abs(f[0] - b[0]) + Math.abs(f[1] - b[1]) + Math.abs(f[2] - b[2]);
    
    return diff < 40;
  },
  
  // Helper: Count confusable characters
  countConfusableChars(text) {
    if (!text) return 0;
    
    let count = 0;
    const seen = new Set(); // Avoid counting same char position twice
    
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      for (let normal in this.CONFUSABLES) {
        if (this.CONFUSABLES[normal].includes(char) && !seen.has(i)) {
          count++;
          seen.add(i);
          break; // Don't count same char multiple times
        }
      }
    }
    return count;
  },
  
  // Helper: Check if string is URL
  isURL(str) {
    try {
      new URL(str);
      return true;
    } catch {
      return str.match(/^https?:\/\//i) !== null;
    }
  },
  
  // Helper: Extract domain from URL
  extractDomain(url) {
    try {
      const u = new URL(url.startsWith('http') ? url : 'http://' + url);
      return u.hostname;
    } catch {
      return '';
    }
  },
  
  // Helper: Get highest severity
  getHighestSeverity(severities) {
    if (severities.includes(this.SEVERITY.CRITICAL)) return this.SEVERITY.CRITICAL;
    if (severities.includes(this.SEVERITY.WARNING)) return this.SEVERITY.WARNING;
    return this.SEVERITY.INFO;
  },
  
  // Detection: Unsubscribe link spoofing
  scanForUnsubscribeSpoof(container) {
    // Find all links with "unsubscribe" text
    const links = container.querySelectorAll('a');
    
    links.forEach(link => {
      const text = link.textContent.toLowerCase();
      const href = link.getAttribute('href') || '';
      
      if (!text.includes('unsubscribe') && !text.includes('opt-out') && !text.includes('opt out')) {
        return; // Not an unsubscribe link
      }
      
      const threats = [];
      
      // JavaScript unsubscribe trap
      if (href.toLowerCase().startsWith('javascript:')) {
        threats.push({
          type: 'unsubscribe-spoof',
          reason: 'Unsubscribe link uses JavaScript (potential trap)',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // Data URL unsubscribe (fake form)
      if (href.startsWith('data:')) {
        threats.push({
          type: 'unsubscribe-spoof',
          reason: 'Unsubscribe link uses data: URL (fake form)',
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // Extract domain
      let domain = '';
      try {
        domain = new URL(href).hostname.toLowerCase();
      } catch {
        return;
      }
      
      // Suspicious TLDs for unsubscribe links
      const suspiciousTLDs = ['.top', '.xyz', '.click', '.link', '.tk', '.ml', '.ga'];
      if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
        threats.push({
          type: 'unsubscribe-spoof',
          reason: `Unsubscribe link goes to suspicious domain (.${domain.split('.').pop()})`,
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Check if unsubscribe domain differs from sender domain
      // (You'd need to extract sender domain from headers - complex)
      
      if (threats.length > 0) {
        this.addFinding(link, threats, `Unsubscribe: ${href.substring(0, 100)}`, this.getHighestSeverity(threats.map(t => t.severity)));
      }
    });
    
    // Check for fake unsubscribe forms (form elements in email body)
    const forms = container.querySelectorAll('form');
    forms.forEach(form => {
      const formText = form.textContent.toLowerCase();
      if (formText.includes('unsubscribe') || formText.includes('opt-out')) {
        this.addFinding(form, [{
          type: 'unsubscribe-spoof',
          reason: 'Email contains unsubscribe form (potential phishing - legitimate emails use links)',
          severity: this.SEVERITY.WARNING
        }], formText.substring(0, 100), this.SEVERITY.WARNING);
      }
    });
  },
  
  // Detection: Suspicious attachment links
  scanForSuspiciousAttachments(container) {
    const emailService = this.detectEmailService();
    
    // Yahoo Mail uses data-test-id attributes
    let attachmentElements = [];
    
    if (emailService === 'yahoo') {
      // Yahoo: Find all attachment items
      attachmentElements = document.querySelectorAll('[data-test-id="attachment-item"], [data-test-id="attachment-details"]');
    } else if (emailService === 'gmail') {
      // Gmail attachments (keeping for future Gmail support)
      const emailContainer = document.querySelector('.nH.if');
      if (emailContainer) {
        attachmentElements = emailContainer.querySelectorAll('.aZo, [download], a[href*="attachment"]');
      }
    }
    
    attachmentElements.forEach(element => {
      // Get filename from title, aria-label, or text content
      let filename = element.getAttribute('title') || 
                      element.getAttribute('aria-label') || 
                      element.textContent.trim();
      
      // Clean up filename - remove file size info (e.g., "52.2 KB")
      // filename = filename.split(/\s*[·,]\s*/)[0].trim();
      
      const threats = [];
      
      if (!filename) return;
      
      // Dangerous file extensions
      const dangerousExts = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar', '.apk', '.msi'];
      if (dangerousExts.some(ext => filename.toLowerCase().endsWith(ext))) {
        threats.push({
          type: 'suspicious-attachment',
          reason: `Dangerous file extension (${filename.split('.').pop()})`,
          severity: this.SEVERITY.CRITICAL
        });
      }
      
      // Double extension trick (e.g., invoice.pdf.exe)
      const extensionCount = (filename.match(/\./g) || []).length;
      if (extensionCount >= 2 && !filename.match(/\.(tar\.gz|tar\.bz2)$/i)) {
        threats.push({
          type: 'suspicious-attachment',
          reason: 'Multiple file extensions (possible disguise)',
          severity: this.SEVERITY.WARNING
        });
      }
      
      // Gibberish/random filename pattern
      if (filename.length > 10) {
        const nameWithoutExt = filename.replace(/\.[^.]+$/, '');
        const hasVowels = /[aeiou]/i.test(nameWithoutExt);
        const isAllCaps = nameWithoutExt === nameWithoutExt.toUpperCase() && /[A-Z]/.test(nameWithoutExt);
        const hasNumbers = /\d{3,}/.test(nameWithoutExt);
        
        if (!hasVowels || (isAllCaps && hasNumbers)) {
          threats.push({
            type: 'suspicious-attachment',
            reason: 'Random/gibberish filename pattern',
            severity: this.SEVERITY.WARNING
          });
        }
      }
      
      // Suspicious attachment names (common phishing patterns)
      const phishyNames = ['invoice', 'receipt', 'statement', 'payment', 'urgent', 'verify', 
                          'confirm', 'suspended', 'locked', 'security', 'alert', 'notification'];
      const lowerFilename = filename.toLowerCase();
      if (phishyNames.some(name => lowerFilename.includes(name))) {
        threats.push({
          type: 'suspicious-attachment',
          reason: 'Common phishing attachment name pattern',
          severity: this.SEVERITY.INFO
        });
      }
      
      if (threats.length > 0) {
        this.addFinding(element, threats, `Attachment: ${filename}`, this.getHighestSeverity(threats.map(t => t.severity)));
      }
    });
  },
  
  // Detection: Reply-To spoofing
  async scanForReplyToSpoofing() {
    const emailService = this.detectEmailService();
    if (!emailService) return;
    
    let fromText = '';
    let replyToText = '';
    
    // --- Gmail extraction ---
    if (emailService === 'gmail') {
      const fromNode = document.querySelector('.gD');           // visible sender
      const replyNode = document.querySelector('.g2');          // reply-to entry
      
      if (fromNode) fromText = fromNode.getAttribute('email') || fromNode.textContent.trim();
      if (replyNode) replyToText = replyNode.getAttribute('email') || replyNode.textContent.trim();
    }
    
    // --- Yahoo Mail extraction ---
    if (emailService === 'yahoo') {
      const fromNode = document.querySelector('[data-test-id="message-view-sender-email"]');
      const replyNode = document.querySelector('[data-test-id="message-view-reply-to-email"]');
      
      if (fromNode) fromText = fromNode.textContent.trim();
      if (replyNode) replyToText = replyNode.textContent.trim();
    }
    
    // If no Reply-To field present, nothing to check
    if (!replyToText || !fromText) return;
    
    const threats = [];
    
    // Normalize
    const fromLower = fromText.toLowerCase();
    const replyLower = replyToText.toLowerCase();
    
    // 1. Direct mismatch but same "brand"
    // Example:
    // FROM: paypal.com
    // REPLY-TO: support-paypal-secure.com
    let fromDomain = fromLower.split('@')[1] || '';
    let replyDomain = replyLower.split('@')[1] || '';
    
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      // If one domain contains the other → high suspicion
      const baseFrom = fromDomain.replace(/^www\./, '');
      const baseReply = replyDomain.replace(/^www\./, '');
      
      const similar =
        baseFrom.includes(baseReply.split('.')[0]) ||
        baseReply.includes(baseFrom.split('.')[0]);
      
      threats.push({
        type: 'reply-to-spoof',
        reason: similar
          ? `Reply-To domain mimics sender domain (${replyDomain})`
          : `Reply-To domain differs from sender domain (${fromDomain} → ${replyDomain})`,
        severity: similar ? this.SEVERITY.CRITICAL : this.SEVERITY.WARNING
      });
    }
    
    // 2. "NOREPLY" / "info" sender → but reply goes to a person
    if (fromLower.includes('noreply') && !replyLower.includes('noreply')) {
      threats.push({
        type: 'reply-to-spoof',
        reason: `Email claims to be no-reply but replies go to a real mailbox (${replyLower})`,
        severity: this.SEVERITY.WARNING
      });
    }
    
    // 3. Free-mail mismatch (classic fraud pattern)
    // FROM: support@paypal.com
    // REPLY-TO: paypal.support@outlook.com
    const freeMail = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com', 'aol.com'];
    
    const replyIsFree = freeMail.includes(replyDomain);
    const fromIsCorp = !freeMail.includes(fromDomain);
    
    if (replyIsFree && fromIsCorp) {
      threats.push({
        type: 'reply-to-spoof',
        reason: `Corporate sender but reply-to is a free email service (${replyDomain})`,
        severity: this.SEVERITY.CRITICAL
      });
    }
    
    // If no threats → done
    if (threats.length === 0) return;
    
    // Attach finding visually to the header
    const referenceElement =
      document.querySelector('.gD') ||
      document.querySelector('[data-test-id="message-view-sender-email"]') ||
      document.body;
    
    this.addFinding(referenceElement, threats, `From: ${fromText}\nReply-To: ${replyToText}`, this.getHighestSeverity(threats.map(t => t.severity)));
  },
  
  // Display scan results
  displayResults() {
    // Remove existing panel
    const existing = document.getElementById('exr-panel');
    if (existing) existing.remove();
    
    const panel = this.createPanel();
    document.body.appendChild(panel);
  },
  
  // Create results panel
  createPanel() {
    const panel = document.createElement('div');
    panel.id = 'exr-panel';
    
    // Header
    const header = document.createElement('div');
    header.id = 'exr-panel-header';
    
    const title = document.createElement('h1');
    title.textContent = '🔍 Email X-Ray';
    header.appendChild(title);
    
    const controls = document.createElement('div');
    controls.id = 'exr-panel-controls';
    
    const minimizeBtn = document.createElement('button');
    minimizeBtn.className = 'exr-btn exr-btn-icon';
    minimizeBtn.textContent = '−';
    minimizeBtn.title = 'Minimize';
    minimizeBtn.onclick = () => panel.classList.toggle('minimized');
    controls.appendChild(minimizeBtn);
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'exr-btn exr-btn-icon';
    closeBtn.textContent = '×';
    closeBtn.title = 'Close';
    closeBtn.onclick = () => {
      panel.remove();
      this.clearHighlights();
    };
    controls.appendChild(closeBtn);
    
    header.appendChild(controls);
    panel.appendChild(header);
    
    // Content
    const content = document.createElement('div');
    content.id = 'exr-panel-content';
    
    // Statistics
    const stats = this.createStats();
    content.appendChild(stats);
    
    // Findings
    if (this.findings.length > 0) {
      const findingsDiv = document.createElement('div');
      findingsDiv.className = 'exr-findings';
      
      this.findings.slice(0, 50).forEach((finding, idx) => {
        const findingEl = this.createFindingElement(finding, idx + 1);
        findingsDiv.appendChild(findingEl);
      });
      
      content.appendChild(findingsDiv);
      
      // Export button
      const exportBtn = document.createElement('button');
      exportBtn.className = 'exr-btn exr-btn-export';
      exportBtn.textContent = 'Export Results (JSON)';
      exportBtn.onclick = () => this.exportResults();
      content.appendChild(exportBtn);
    } else {
      const noFindings = document.createElement('div');
      noFindings.className = 'exr-no-findings';
      noFindings.innerHTML = 'No suspicious content detected<br><small>This email appears safe</small>';
      content.appendChild(noFindings);
    }
    
    // Rescan button
    const rescanBtn = document.createElement('button');
    rescanBtn.className = 'exr-btn exr-btn-primary';
    rescanBtn.textContent = 'Rescan Email';
    rescanBtn.onclick = () => this.performScan();
    content.appendChild(rescanBtn);
    
    panel.appendChild(content);
    
    return panel;
  },
  
  // Create statistics display
  createStats() {
    const stats = document.createElement('div');
    stats.className = 'exr-stats';
    
    const critical = this.findings.filter(f => f.severity === this.SEVERITY.CRITICAL).length;
    const warning = this.findings.filter(f => f.severity === this.SEVERITY.WARNING).length;
    const info = this.findings.filter(f => f.severity === this.SEVERITY.INFO).length;
    
    const criticalStat = document.createElement('div');
    criticalStat.className = 'exr-stat exr-stat-critical';
    criticalStat.innerHTML = `<span class="exr-stat-count">${critical}</span><span class="exr-stat-label">Critical</span>`;
    stats.appendChild(criticalStat);
    
    const warningStat = document.createElement('div');
    warningStat.className = 'exr-stat exr-stat-warning';
    warningStat.innerHTML = `<span class="exr-stat-count">${warning}</span><span class="exr-stat-label">Warning</span>`;
    stats.appendChild(warningStat);
    
    const infoStat = document.createElement('div');
    infoStat.className = 'exr-stat exr-stat-info';
    infoStat.innerHTML = `<span class="exr-stat-count">${info}</span><span class="exr-stat-label">Info</span>`;
    stats.appendChild(infoStat);
    
    return stats;
  },
  
  // Create individual finding element
  createFindingElement(finding, index) {
    const el = document.createElement('div');
    el.className = `exr-finding exr-finding-${finding.severity}`;
    
    const header = document.createElement('div');
    header.className = 'exr-finding-header';
    
    const title = document.createElement('div');
    title.className = 'exr-finding-title';
    title.textContent = `#${index} ${finding.threats[0].type.replace(/-/g, ' ')}`;
    header.appendChild(title);
    
    const severityBadge = document.createElement('span');
    severityBadge.className = `exr-finding-severity exr-severity-${finding.severity}`;
    severityBadge.textContent = finding.severity;
    header.appendChild(severityBadge);
    
    el.appendChild(header);
    
    const details = document.createElement('div');
    details.className = 'exr-finding-details';
    details.innerHTML = finding.threats.map(t => `• ${t.reason}`).join('<br>');
    el.appendChild(details);
    
    if (finding.text) {
      const text = document.createElement('div');
      text.className = 'exr-finding-text';
      text.textContent = finding.text;
      el.appendChild(text);
    }
    
    // Click to scroll to element
    el.style.cursor = 'pointer';
    el.onclick = () => {
      finding.element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      finding.element.style.animation = 'none';
      setTimeout(() => {
        finding.element.style.animation = 'pulse 0.5s ease-in-out 3';
      }, 10);
    };
    
    return el;
  },
  
  // Export results as JSON
  exportResults() {
    const data = {
      scanDate: new Date().toISOString(),
      totalFindings: this.findings.length,
      findings: this.findings.map((f, idx) => ({
        id: idx + 1,
        severity: f.severity,
        threats: f.threats,
        text: f.text,
        element: {
          tag: f.element.tagName,
          classes: Array.from(f.element.classList).filter(c => !c.startsWith('exr-')).join(' '),
          id: f.element.id
        }
      }))
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-xray-scan-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  },
  
  // Clear all highlights
  clearHighlights() {
    document.querySelectorAll('[class*="exr-"]').forEach(el => {
      el.classList.remove('exr-critical', 'exr-warning', 'exr-info');
    });
  },
  
  // Show element details on click
  showElementDetails(element, threats, text) {
    console.log('Element details:', { element, threats, text });
  }
};

// Add pulse animation
const style = document.createElement('style');
style.textContent = `
  @keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.05); }
  }
`;
document.head.appendChild(style);

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => EXR.init());
} else {
  EXR.init();
}
