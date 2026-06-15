// Background service worker for automated blocklist triggers
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Trigger when page loading completes
  if (changeInfo.status === 'complete' && tab.url) {
    const url = tab.url;
    if (url.includes('youtube.com/watch?v=') || url.includes('youtu.be/')) {
      console.log('Automated check: Detected YouTube video navigation:', url);
      
      // Send tab URL to local Flask dashboard for dynamic ad-serving domain scraping
      const formData = new URLSearchParams();
      formData.append('url', url);
      
      fetch('http://127.0.0.1:5000', {
        method: 'POST',
        body: formData,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      })
      .then(response => {
        console.log('Background server: Successfully updated blocklist for video:', url);
      })
      .catch(err => {
        console.warn('Background server: Could not auto-submit URL to local server:', err);
      });
    }
  }
});
