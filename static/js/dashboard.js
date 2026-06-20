/**
 * CyberRecon Pro — Dashboard JavaScript
 * Chart.js charts, live stats, activity feed
 */

document.addEventListener('DOMContentLoaded', () => {

  // Chart.js global defaults for dark theme
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = 'rgba(0, 212, 255, 0.08)';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";

  // ── Tool Usage Doughnut Chart ──────────────────────────────────────────────
  const toolCtx = document.getElementById('toolsChart');
  if (toolCtx) {
    const labels = JSON.parse(toolCtx.dataset.labels || '[]');
    const values = JSON.parse(toolCtx.dataset.values || '[]');

    new Chart(toolCtx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: [
            'rgba(0, 212, 255, 0.7)',
            'rgba(124, 58, 237, 0.7)',
            'rgba(0, 255, 136, 0.7)',
            'rgba(255, 170, 0, 0.7)',
            'rgba(255, 51, 102, 0.7)',
            'rgba(255, 215, 0, 0.7)',
            'rgba(100, 200, 255, 0.7)',
            'rgba(200, 100, 255, 0.7)',
          ],
          borderColor: 'rgba(0,0,0,0)',
          borderWidth: 0,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              padding: 14,
              usePointStyle: true,
              pointStyle: 'circle',
              font: { size: 11 },
            },
          },
          tooltip: {
            backgroundColor: 'rgba(10, 22, 40, 0.95)',
            titleColor: '#00d4ff',
            bodyColor: '#8b949e',
            borderColor: 'rgba(0, 212, 255, 0.2)',
            borderWidth: 1,
            padding: 12,
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${ctx.parsed} scans`,
            },
          },
        },
      },
    });
  }

  // ── Risk Distribution Bar Chart ────────────────────────────────────────────
  const riskCtx = document.getElementById('riskChart');
  if (riskCtx) {
    const riskLabels = JSON.parse(riskCtx.dataset.labels || '[]');
    const riskValues = JSON.parse(riskCtx.dataset.values || '[]');
    const riskColors = {
      critical:      'rgba(255, 51,  102, 0.8)',
      high:          'rgba(255, 170,  0,  0.8)',
      medium:        'rgba(0,   212, 255, 0.8)',
      low:           'rgba(0,   255, 136, 0.8)',
      informational: 'rgba(139, 148, 158, 0.8)',
      info:          'rgba(139, 148, 158, 0.8)',
    };

    new Chart(riskCtx, {
      type: 'bar',
      data: {
        labels: riskLabels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [{
          label: 'Findings',
          data: riskValues,
          backgroundColor: riskLabels.map(l => riskColors[l] || 'rgba(139,148,158,0.8)'),
          borderRadius: 6,
          borderSkipped: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(10, 22, 40, 0.95)',
            titleColor: '#00d4ff',
            bodyColor: '#8b949e',
            borderColor: 'rgba(0, 212, 255, 0.2)',
            borderWidth: 1,
            padding: 12,
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#8b949e' },
          },
          y: {
            grid: { color: 'rgba(0, 212, 255, 0.05)' },
            ticks: { color: '#8b949e', stepSize: 1 },
            beginAtZero: true,
          },
        },
      },
    });
  }

  // ── Activity Timeline Line Chart ───────────────────────────────────────────
  const timeCtx = document.getElementById('timelineChart');
  if (timeCtx) {
    const dates  = JSON.parse(timeCtx.dataset.dates  || '[]');
    const counts = JSON.parse(timeCtx.dataset.counts || '[]');

    new Chart(timeCtx, {
      type: 'line',
      data: {
        labels: dates,
        datasets: [{
          label: 'Scans',
          data: counts,
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0, 212, 255, 0.06)',
          borderWidth: 2,
          pointBackgroundColor: '#00d4ff',
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true,
          tension: 0.4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(10, 22, 40, 0.95)',
            titleColor: '#00d4ff',
            bodyColor: '#8b949e',
            borderColor: 'rgba(0, 212, 255, 0.2)',
            borderWidth: 1,
            padding: 12,
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#8b949e', maxTicksLimit: 7 },
          },
          y: {
            grid: { color: 'rgba(0, 212, 255, 0.05)' },
            ticks: { color: '#8b949e', stepSize: 1 },
            beginAtZero: true,
          },
        },
      },
    });
  }

});
