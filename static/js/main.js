/**
 * CyberRecon Pro — Global JavaScript
 * Sidebar toggle, alerts, topbar utilities, animations
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── Sidebar Toggle (Mobile) ───────────────────────────────────────────────
  const sidebar        = document.getElementById('sidebar');
  const sidebarToggle  = document.getElementById('sidebarToggle');
  const sidebarOverlay = document.getElementById('sidebarOverlay');

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      sidebarOverlay.classList.toggle('show');
    });
  }

  if (sidebarOverlay) {
    sidebarOverlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      sidebarOverlay.classList.remove('show');
    });
  }

  // ── Active Nav Link ───────────────────────────────────────────────────────
  const currentPath = window.location.pathname.split('/')[1];
  document.querySelectorAll('.sidebar-nav-item').forEach(link => {
    const href = link.getAttribute('href') || '';
    const linkPath = href.split('/')[1];
    if (linkPath && linkPath === currentPath) {
      link.classList.add('active');
    }
  });

  // ── Flash Alert Auto-dismiss ──────────────────────────────────────────────
  document.querySelectorAll('.alert-cyber').forEach(alert => {
    if (!alert.dataset.persist) {
      setTimeout(() => {
        alert.style.transition = 'opacity 0.5s ease';
        alert.style.opacity = '0';
        setTimeout(() => alert.remove(), 500);
      }, 4000);
    }
  });

  // ── Toast Notification System ─────────────────────────────────────────────
  window.CyberToast = {
    show(message, type = 'info', duration = 3500) {
      let container = document.getElementById('toast-container');
      if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `
          position: fixed; top: 1.5rem; right: 1.5rem;
          display: flex; flex-direction: column; gap: 0.5rem;
          z-index: 9999; max-width: 360px;
        `;
        document.body.appendChild(container);
      }

      const icons = {
        success: 'fa-circle-check',
        danger: 'fa-circle-xmark',
        warning: 'fa-triangle-exclamation',
        info: 'fa-circle-info',
      };

      const toast = document.createElement('div');
      toast.className = `alert-cyber ${type} animate-fade-up`;
      toast.style.cssText = 'opacity:0; transform:translateY(-10px); transition: all 0.3s ease; cursor:pointer;';
      toast.innerHTML = `
        <i class="fas ${icons[type] || icons.info}"></i>
        <span style="flex:1; font-size:0.82rem;">${message}</span>
        <i class="fas fa-xmark" style="opacity:0.5; font-size:0.75rem;"></i>
      `;

      container.appendChild(toast);
      requestAnimationFrame(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';
      });

      const dismiss = () => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-10px)';
        setTimeout(() => toast.remove(), 300);
      };

      toast.addEventListener('click', dismiss);
      setTimeout(dismiss, duration);
    },

    success: (msg) => window.CyberToast.show(msg, 'success'),
    error:   (msg) => window.CyberToast.show(msg, 'danger'),
    warning: (msg) => window.CyberToast.show(msg, 'warning'),
    info:    (msg) => window.CyberToast.show(msg, 'info'),
  };

  // ── Animate Page Elements ─────────────────────────────────────────────────
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('animate-fade-up');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.stat-card, .glass-card, .note-card').forEach(el => {
    el.style.opacity = '0';
    observer.observe(el);
  });

  // ── Confirm Delete Dialogs ────────────────────────────────────────────────
  document.querySelectorAll('[data-confirm]').forEach(btn => {
    btn.addEventListener('click', function(e) {
      const msg = this.dataset.confirm || 'Are you sure you want to delete this?';
      if (!confirm(msg)) e.preventDefault();
    });
  });

  // ── Copy to Clipboard ─────────────────────────────────────────────────────
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', function() {
      const text = this.dataset.copy;
      navigator.clipboard.writeText(text).then(() => {
        const orig = this.innerHTML;
        this.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => { this.innerHTML = orig; }, 1500);
        window.CyberToast.success('Copied to clipboard!');
      });
    });
  });

  // ── Topbar Clock ──────────────────────────────────────────────────────────
  const clockEl = document.getElementById('topbar-clock');
  if (clockEl) {
    const updateClock = () => {
      clockEl.textContent = new Date().toUTCString().replace('GMT', 'UTC');
    };
    updateClock();
    setInterval(updateClock, 1000);
  }

  // ── Number Counter Animation ──────────────────────────────────────────────
  document.querySelectorAll('[data-counter]').forEach(el => {
    const target = parseInt(el.dataset.counter, 10);
    if (isNaN(target)) return;
    let current = 0;
    const increment = Math.ceil(target / 40);
    const timer = setInterval(() => {
      current = Math.min(current + increment, target);
      el.textContent = current.toLocaleString();
      if (current >= target) clearInterval(timer);
    }, 30);
  });

  // ── Search Filter ─────────────────────────────────────────────────────────
  const searchInput = document.getElementById('inline-search');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      const q = this.value.toLowerCase();
      document.querySelectorAll('[data-searchable]').forEach(item => {
        item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

});
