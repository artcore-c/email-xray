# Installation Guide

Complete guide for installing and testing Email X-Ray on macOS Chrome.

## Prerequisites

- **macOS**: 10.14 (Mojave) or later
- **Chrome**: Version 88 or later
- **Git**: For cloning the repository (optional)

## Installation Steps

### Method 1: Install from GitHub (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/email-xray.git
   cd email-xray
   ```

2. **Open Chrome Extensions page**:
   - Open Chrome
   - Navigate to `chrome://extensions/`
   - Or use menu: **Chrome** → **More Tools** → **Extensions**

3. **Enable Developer Mode**:
   - Look for "Developer mode" toggle in the top-right corner
   - Click to enable it

4. **Load the extension**:
   - Click the **"Load unpacked"** button
   - Navigate to the `email-xray` folder
   - Click **"Select"**

5. **Verify installation**:
   - You should see Email X-Ray listed in your extensions
   - The 🔍 icon should appear in your Chrome toolbar
   - Status should show "Enabled"

### Method 2: Download ZIP

1. **Download the repository**:
   - Go to the GitHub repository
   - Click **Code** → **Download ZIP**
   - Extract the ZIP file to a permanent location

2. **Follow steps 2-5 from Method 1**

## Configuration

### Pin the Extension (Recommended)

1. Click the **puzzle piece icon** in Chrome toolbar
2. Find **Email X-Ray**
3. Click the **pin icon** to keep it visible

### Set Keyboard Shortcut (Optional)

1. Go to `chrome://extensions/shortcuts`
2. Find **Email X-Ray**
3. Customize the shortcut if desired (default: ⌘+⇧+X)

## Testing the Installation

### Quick Test

1. **Open Gmail or Yahoo Mail**:
   - Navigate to https://mail.google.com or https://mail.yahoo.com
   - Open any email

2. **Run a scan**:
   - Click the Email X-Ray icon in toolbar
   - Click **"Scan Current Email"**
   - You should see the results panel appear

3. **Test keyboard shortcut**:
   - Press **⌘+⇧+X** (or Ctrl+Shift+X)
   - Scan should run automatically

### Create Test Email (Comprehensive Test)

To fully test the extension, create a test email with hidden content:

1. **Compose a new email to yourself**

2. **Add test content** (paste this HTML into Gmail/Yahoo composer if possible, or use developer tools):

   ```html
   Normal visible text here.
   
   <!-- Hidden text test -->
   <span style="font-size: 0px;">This text is hidden with 0px font</span>
   
   <!-- Transparent text test -->
   <div style="opacity: 0;">This text is completely transparent</div>
   
   <!-- Color camouflage test -->
   <p style="color: #ffffff; background-color: #ffffff;">This text matches the background</p>
   
   <!-- Tracking pixel test -->
   <img src="https://example.com/pixel.gif" width="1" height="1" alt="tracker">
   
   <!-- Suspicious link test -->
   <a href="javascript:alert('XSS')">Click here</a>
   
   <!-- Zero-width character test -->
   Hell​o Wor​ld (contains zero-width spaces)
   ```

3. **Send and open the email**

4. **Scan the email**:
   - You should see multiple detections
   - Critical: JavaScript URL, 0px font, transparent text
   - Warning: Tracking pixel, color camouflage
   - Info: Various other findings

### Expected Results

A properly working installation should:

Display colored highlights on suspicious elements  
Show a detailed results panel  
Categorize findings by severity  
Allow clicking findings to scroll to them  
Enable export of results as JSON  
Work with keyboard shortcut  

## Troubleshooting

### Extension Not Loading

**Problem**: "Load unpacked" button is grayed out  
**Solution**: Enable Developer mode in top-right corner

**Problem**: Error loading extension  
**Solution**: 
- Verify all files are present (manifest.json, content.js, etc.)
- Check console for specific error messages
- Ensure manifest.json is valid JSON

### Extension Loaded But Not Working

**Problem**: Icon doesn't appear in toolbar  
**Solution**: 
- Check if extension is enabled
- Click puzzle piece icon and pin the extension
- Reload Chrome

**Problem**: Scan button doesn't work  
**Solution**:
- Refresh the Gmail/Yahoo Mail page
- Check browser console for errors (F12 → Console)
- Verify you're on supported domain

**Problem**: "Please navigate to Gmail or Yahoo Mail first"  
**Solution**:
- Ensure you're on mail.google.com or mail.yahoo.com
- Refresh the page after installing extension

### Scan Not Finding Anything

**Problem**: Clean scan on email with hidden content  
**Solution**:
- Gmail/Yahoo may sanitize some HTML
- Try the comprehensive test above
- Verify email actually contains suspicious content

### Keyboard Shortcut Not Working

**Problem**: ⌘+⇧+X doesn't trigger scan  
**Solution**:
- Check `chrome://extensions/shortcuts`
- Verify no conflicts with other extensions
- Reload the Gmail/Yahoo page

## Updating the Extension

When you pull new updates from Git:

1. Pull latest changes:
   ```bash
   cd email-xray
   git pull origin main
   ```

2. Reload the extension:
   - Go to `chrome://extensions/`
   - Find Email X-Ray
   - Click the **reload icon** (circular arrow)

## Uninstalling

1. Go to `chrome://extensions/`
2. Find Email X-Ray
3. Click **"Remove"**
4. Confirm removal

To reinstall later, follow installation steps again.

## Development Mode

If you're developing or testing changes:

1. Make changes to the code files
2. Save your changes
3. Go to `chrome://extensions/`
4. Click the reload icon on Email X-Ray
5. Refresh any Gmail/Yahoo tabs
6. Test your changes

## Permissions Explained

Email X-Ray requests minimal permissions:

- **activeTab**: To scan the currently open email
- **storage**: To save user preferences (future use)
- **host_permissions** (mail.google.com, mail.yahoo.com): To inject detection scripts

The extension **does not**:
- Access other websites
- Send data to external servers
- Access your browsing history
- Modify emails or send emails

## Performance Notes

- Scans typically complete in < 1 second
- No impact on email loading time
- Minimal memory footprint (~5-10 MB)
- No background processes (only active during scan)

## Support

If you encounter issues:

1. Check this guide's Troubleshooting section
2. Review the [README.md](README.md)
3. Open an issue on GitHub
4. Include:
   - Chrome version
   - macOS version
   - Error messages
   - Steps to reproduce

---

You're all set! Start scanning emails for hidden threats. 🔍
