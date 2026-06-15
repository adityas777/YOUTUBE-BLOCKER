const SERVER_URL = 'http://127.0.0.1:5000';

document.addEventListener('DOMContentLoaded', () => {
  const statusBadge = document.getElementById('status-badge');
  const statusText = document.getElementById('status-text');
  const statTotal = document.getElementById('stat-total');
  const statBlocked = document.getElementById('stat-blocked');
  const statRate = document.getElementById('stat-rate');
  const btnBlockYt = document.getElementById('btn-block-yt');
  const alertMsg = document.getElementById('alert-msg');
  const logsList = document.getElementById('logs-list');

  let currentTabUrl = '';

  // Check active tab to see if it's YouTube
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) {
      currentTabUrl = tabs[0].url || '';
      if (currentTabUrl.includes('youtube.com/watch?v=') || currentTabUrl.includes('youtu.be/')) {
        btnBlockYt.classList.remove('disabled');
        btnBlockYt.addEventListener('click', blockYouTubeStream);
      }
    }
  });

  // Fetch stats and logs from local Flask server
  function updateData() {
    fetch(`${SERVER_URL}/api/stats`)
      .then(response => {
        if (!response.ok) throw new Error('Offline');
        return response.json();
      })
      .then(data => {
        // Update status
        statusBadge.classList.remove('offline');
        statusText.textContent = 'ONLINE';

        // Update stats
        const stats = data.stats;
        statTotal.textContent = stats.total_queries;
        statBlocked.textContent = stats.blocked_queries;
        
        let rate = 0;
        if (stats.total_queries > 0) {
          rate = (stats.blocked_queries / stats.total_queries * 100).toFixed(2);
        }
        statRate.textContent = rate + '%';

        // Update logs list
        const logs = data.dpi_logs;
        if (logs.length > 0) {
          logsList.innerHTML = '';
          logs.forEach(log => {
            const isDns = log.ip === '0.0.0.0' || log.ip.includes('DNS');
            const typeClass = isDns ? 'dns' : 'dpi';
            const typeText = isDns ? 'DNS' : 'DPI';
            
            const item = document.createElement('div');
            item.className = 'log-item';
            item.innerHTML = `
              <span class="log-host" title="${log.sni}">${log.sni}</span>
              <span class="log-badge ${typeClass}">${typeText}</span>
            `;
            logsList.appendChild(item);
          });
        } else {
          logsList.innerHTML = '<div class="no-logs">No blocked ads detected yet.</div>';
        }
      })
      .catch(err => {
        // Set offline status
        statusBadge.classList.add('offline');
        statusText.textContent = 'OFFLINE';
        logsList.innerHTML = '<div class="no-logs">Cannot connect to blocker server. Make sure dashboard is running.</div>';
      });
  }

  // Action: Block YouTube stream domains
  function blockYouTubeStream() {
    if (!currentTabUrl) return;

    btnBlockYt.classList.add('disabled');
    showAlert('Scraping ad domains...', false);

    // Prepare URL-encoded form payload (exactly like the form post in dashboard.py)
    const formData = new URLSearchParams();
    formData.append('url', currentTabUrl);

    fetch(SERVER_URL, {
      method: 'POST',
      body: formData,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    .then(response => {
      showAlert('Ad streams submitted! Blocklist updated.', true);
      updateData();
      setTimeout(() => {
        btnBlockYt.classList.remove('disabled');
      }, 3000);
    })
    .catch(err => {
      showAlert('Failed to connect to local server.', false);
      btnBlockYt.classList.remove('disabled');
    });
  }

  function showAlert(msg, isSuccess) {
    alertMsg.textContent = msg;
    alertMsg.style.display = 'block';
    if (isSuccess) {
      alertMsg.style.backgroundColor = 'hsla(142, 70%, 45%, 0.1)';
      alertMsg.style.borderColor = 'hsla(142, 70%, 45%, 0.2)';
      alertMsg.style.color = 'hsl(142, 70%, 75%)';
    } else {
      alertMsg.style.backgroundColor = 'hsla(250, 89%, 66%, 0.1)';
      alertMsg.style.borderColor = 'hsla(250, 89%, 66%, 0.2)';
      alertMsg.style.color = 'hsl(250, 89%, 80%)';
    }
    setTimeout(() => {
      alertMsg.style.display = 'none';
    }, 4000);
  }

  // Update immediately and poll every 4 seconds
  updateData();
  setInterval(updateData, 4000);
});
