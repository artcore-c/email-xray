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
  
  // Detection: Tracking pixels (1x1 images)
  scanForTrackingPixels(container) {
    const images = container.querySelectorAll('img');
    
    images.forEach(img => {
      const width = img.width || parseInt(img.getAttribute('width')) || 0;
      const height = img.height || parseInt(img.getAttribute('height')) || 0;
      
      if ((width === 1 && height === 1) || (width <= 2 && height <= 2)) {
        const src = img.src || img.getAttribute('src') || '';
        
        this.addFinding(img, [{
          type: 'tracking-pixel',
          reason: `Tracking pixel detected (${width}x${height})`,
          severity: this.SEVERITY.WARNING
        }], `Source: ${src.substring(0, 100)}`, this.SEVERITY.WARNING);
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
      const confusableCount = this.countConfusableChars(href + displayText);
      
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
      if (this.ZERO_WIDTH_CHARS.test(alt)) {
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
    let count = 0;
    for (let char of text) {
      for (let normal in this.CONFUSABLES) {
        if (this.CONFUSABLES[normal].includes(char)) {
          count++;
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
