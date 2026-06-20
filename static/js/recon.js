/**
 * CyberRecon Pro — Recon Module JavaScript
 * Live terminal output polling, scan management
 */

document.addEventListener('DOMContentLoaded', () => {

  let pollInterval   = null;
  let currentScanId  = null;
  let isPolling      = false;

  const termBody      = document.getElementById('terminal-output');
  const statusBadge   = document.getElementById('scan-status-badge');
  const progressBar   = document.getElementById('scan-progress-bar');
  const startBtn      = document.getElementById('btn-start-scan');
  const stopBtn       = document.getElementById('btn-stop-scan');
  const toolSelect    = document.getElementById('tool-select');
  const targetSelect  = document.getElementById('target-select');
  const optionsPanel  = document.getElementById('tool-options-panel');

  // ── Tool Options Toggle ────────────────────────────────────────────────────
  const toolOptions = {
    nmap:      ['nmap-flags', 'nmap-ports'],
    subfinder: ['subfinder-options'],
    amass:     ['amass-options'],
    ffuf:      ['ffuf-options'],
    whois:     ['whois-options'],
    whatweb:   ['whatweb-options'],
  };

  if (toolSelect) {
    toolSelect.addEventListener('change', function () {
      // Hide all option groups
      document.querySelectorAll('.tool-option-group').forEach(g => {
        g.style.display = 'none';
      });
      // Show relevant group
      const groups = toolOptions[this.value] || [];
      groups.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'block';
      });
    });
    // Trigger on load
    toolSelect.dispatchEvent(new Event('change'));
  }

  // ── Start Scan ─────────────────────────────────────────────────────────────
  if (startBtn) {
    startBtn.addEventListener('click', async function () {
      const tool     = toolSelect?.value;
      const targetId = targetSelect?.value;

      if (!tool || !targetId) {
        window.CyberToast?.error('Please select a tool and target.');
        return;
      }

      // Gather form data
      const formData = new FormData(document.getElementById('recon-form'));

      try {
        startBtn.disabled = true;
        startBtn.innerHTML = '<span class="spinner-cyber d-inline-block me-2" style="width:16px;height:16px;border-width:2px;"></span> Initializing...';

        const res  = await fetch('/recon/start', {
          method: 'POST',
          body: formData,
        });
        const data = await res.json();

        if (data.success) {
          currentScanId = data.scan_id;
          termPrint(`[+] Scan initiated — ID: ${data.scan_id}`, 'success');
          termPrint(`[*] Tool: ${tool.toUpperCase()} | Target: ${data.target}`, 'info');
          termPrint('[*] Connecting to live feed...', 'info');
          updateStatus('running');
          startBtn.style.display  = 'none';
          if (stopBtn) stopBtn.style.display = 'inline-flex';
          startPolling(data.scan_id);
        } else {
          termPrint(`[!] Error: ${data.error}`, 'error');
          window.CyberToast?.error(data.error);
          startBtn.disabled = false;
          startBtn.innerHTML = '<i class="fas fa-play me-2"></i> Start Scan';
        }
      } catch (err) {
        termPrint(`[!] Network error: ${err.message}`, 'error');
        window.CyberToast?.error('Failed to start scan.');
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play me-2"></i> Start Scan';
      }
    });
  }

  // ── Stop Scan ──────────────────────────────────────────────────────────────
  if (stopBtn) {
    stopBtn.addEventListener('click', async function () {
      if (!currentScanId) return;
      stopPolling();
      termPrint('[!] Scan stop requested by user.', 'warning');
      updateStatus('stopped');
      stopBtn.style.display  = 'none';
      startBtn.style.display = 'inline-flex';
      startBtn.disabled = false;
      startBtn.innerHTML = '<i class="fas fa-play me-2"></i> Start Scan';
    });
  }

  // ── Polling ────────────────────────────────────────────────────────────────
  function startPolling(scanId) {
    if (isPolling) return;
    isPolling = true;
    pollInterval = setInterval(() => fetchStatus(scanId), 1000);
  }

  function stopPolling() {
    clearInterval(pollInterval);
    isPolling = false;
  }

  async function fetchStatus(scanId) {
    try {
      const res  = await fetch(`/recon/status/${scanId}`);
      const data = await res.json();

      // Append new lines
      if (data.new_output && data.new_output.length > 0) {
        data.new_output.forEach(line => termPrint(line));
      }

      // Update progress
      if (data.progress !== undefined && progressBar) {
        progressBar.style.width = `${data.progress}%`;
      }

      if (data.status === 'completed') {
        stopPolling();
        termPrint('[✓] Scan completed successfully.', 'success');
        termPrint(`[*] Results saved to database.`, 'info');
        updateStatus('completed');
        resetScanButtons();
        // Auto-redirect to results after 2s
        if (data.scan_id) {
          setTimeout(() => {
            window.location.href = `/recon/results/${data.scan_id}`;
          }, 2000);
        }
      } else if (data.status === 'failed') {
        stopPolling();
        termPrint(`[!] Scan failed: ${data.error || 'Unknown error'}`, 'error');
        updateStatus('failed');
        resetScanButtons();
      }

    } catch (err) {
      console.error('Poll error:', err);
    }
  }

  // ── Terminal Helpers ───────────────────────────────────────────────────────
  function termPrint(text, type = 'default') {
    if (!termBody) return;

    // Detect type from content
    if (type === 'default') {
      if (text.startsWith('[+]') || text.startsWith('[✓]')) type = 'success';
      else if (text.startsWith('[!]')) type = 'error';
      else if (text.startsWith('[*]')) type = 'info';
      else if (text.startsWith('[~]') || text.startsWith('[W]')) type = 'warning';
    }

    const line = document.createElement('span');
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    termBody.appendChild(line);
    termBody.appendChild(document.createElement('br'));
    termBody.scrollTop = termBody.scrollHeight;
  }

  function updateStatus(status) {
    if (!statusBadge) return;
    const statusMap = {
      running:   { text: 'RUNNING',   css: 'risk-medium' },
      completed: { text: 'COMPLETED', css: 'risk-low' },
      failed:    { text: 'FAILED',    css: 'risk-critical' },
      stopped:   { text: 'STOPPED',   css: 'risk-high' },
      pending:   { text: 'PENDING',   css: 'risk-info' },
    };
    const s = statusMap[status] || { text: status.toUpperCase(), css: 'risk-info' };
    statusBadge.className = `risk-badge ${s.css}`;
    statusBadge.textContent = s.text;
  }

  function resetScanButtons() {
    if (startBtn) {
      startBtn.style.display = 'inline-flex';
      startBtn.disabled = false;
      startBtn.innerHTML = '<i class="fas fa-play me-2"></i> Start Scan';
    }
    if (stopBtn) {
      stopBtn.style.display = 'none';
    }
  }

  // ── Resume polling for in-progress scans ──────────────────────────────────
  const activeScanEl = document.getElementById('active-scan-id');
  if (activeScanEl && activeScanEl.value) {
    currentScanId = activeScanEl.value;
    termPrint('[*] Reconnecting to active scan...', 'info');
    updateStatus('running');
    startPolling(currentScanId);
  }

});
