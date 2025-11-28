// Email X-Ray - Popup Script
// Handles scan requests from the extension popup

const scanBtn = document.getElementById('scanBtn');
const statusDiv = document.getElementById('status');

// Show status message
function showStatus(message, type) {
  statusDiv.textContent = message;
  statusDiv.className = `status show status-${type}`;
  
  if (type === 'success' || type === 'error') {
    setTimeout(() => {
      statusDiv.classList.remove('show');
    }, 3000);
  }
}

// Perform scan
async function performScan() {
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';
  showStatus('Scanning email for hidden threats...', 'scanning');
  
  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.id) {
      throw new Error('No active tab found');
    }
    
    // Check if we're on Gmail or Yahoo Mail
    if (!tab.url.includes('mail.google.com') && !tab.url.includes('mail.yahoo.com')) {
      throw new Error('Please navigate to Gmail or Yahoo Mail first');
    }
    
    // Send scan message to content script
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'EXR_SCAN' });
    
    if (response && response.ok) {
      const count = response.results ? response.results.length : 0;
      if (count > 0) {
        showStatus(`Scan complete! Found ${count} suspicious ${count === 1 ? 'item' : 'items'}. Check the page.`, 'success');
      } else {
        showStatus('Scan complete! No threats detected. Email appears safe.', 'success');
      }
    } else {
      throw new Error(response?.error || 'Scan failed');
    }
  } catch (error) {
    console.error('Scan error:', error);
    
    // Provide helpful error messages
    if (error.message.includes('Receiving end does not exist')) {
      showStatus('Please refresh the page and try again.', 'error');
    } else if (error.message.includes('navigate to Gmail or Yahoo')) {
      showStatus(error.message, 'error');
    } else {
      showStatus(`Error: ${error.message}`, 'error');
    }
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan Current Email';
  }
}

// Event listeners
scanBtn.addEventListener('click', performScan);

// Also allow Enter key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !scanBtn.disabled) {
    performScan();
  }
});

// Load saved settings (for future use)
chrome.storage.local.get(['autoScan', 'sensitivity'], (result) => {
  console.log('Settings loaded:', result);
});
