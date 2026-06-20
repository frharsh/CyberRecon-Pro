/**
 * CyberRecon Pro — Notes Module JavaScript
 * Markdown preview, auto-save, tag management
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── Markdown-lite Preview ──────────────────────────────────────────────────
  const contentArea = document.getElementById('note-content');
  const previewArea = document.getElementById('note-preview');
  const previewBtn  = document.getElementById('btn-preview');
  const editBtn     = document.getElementById('btn-edit');

  if (contentArea && previewArea && previewBtn) {
    previewBtn.addEventListener('click', () => {
      const md = contentArea.value;
      previewArea.innerHTML = simpleMarkdown(md);
      contentArea.style.display  = 'none';
      previewArea.style.display  = 'block';
      previewBtn.style.display   = 'none';
      if (editBtn) editBtn.style.display = 'inline-flex';
    });

    if (editBtn) {
      editBtn.addEventListener('click', () => {
        previewArea.style.display = 'none';
        contentArea.style.display = 'block';
        editBtn.style.display     = 'none';
        previewBtn.style.display  = 'inline-flex';
      });
    }
  }

  // ── Simple Markdown Renderer ───────────────────────────────────────────────
  function simpleMarkdown(text) {
    return text
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/^### (.+)$/gm, '<h3 style="color:var(--cyan);font-family:var(--font-display);font-size:0.9rem;margin:1rem 0 0.5rem;">$1</h3>')
      .replace(/^## (.+)$/gm,  '<h2 style="color:var(--cyan);font-family:var(--font-display);font-size:1rem;margin:1rem 0 0.5rem;">$1</h2>')
      .replace(/^# (.+)$/gm,   '<h1 style="color:var(--cyan);font-family:var(--font-display);font-size:1.2rem;margin:1rem 0 0.5rem;">$1</h1>')
      .replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--text-primary);">$1</strong>')
      .replace(/\*(.+?)\*/g,     '<em style="color:var(--purple);">$1</em>')
      .replace(/`(.+?)`/g,       '<code style="background:var(--bg-dark);color:var(--green);padding:0.1em 0.4em;border-radius:3px;font-family:var(--font-mono);">$1</code>')
      .replace(/^- (.+)$/gm,     '<li style="margin:0.25rem 0;color:var(--text-secondary);">$1</li>')
      .replace(/\n/g,            '<br>');
  }

  // ── Tag Input System ───────────────────────────────────────────────────────
  const tagInput     = document.getElementById('tag-input');
  const tagContainer = document.getElementById('tag-container');
  const tagsHidden   = document.getElementById('tags-hidden');

  if (tagInput && tagContainer) {
    let tags = tagsHidden ? tagsHidden.value.split(',').filter(Boolean) : [];

    function renderTags() {
      const existing = tagContainer.querySelectorAll('.tag-pill');
      existing.forEach(p => p.remove());

      tags.forEach(tag => {
        const pill = document.createElement('span');
        pill.className = 'note-tag d-inline-flex align-items-center gap-1 me-1 mb-1';
        pill.innerHTML = `${tag} <i class="fas fa-xmark" style="cursor:pointer;font-size:0.6rem;" data-tag="${tag}"></i>`;
        pill.querySelector('i').addEventListener('click', () => {
          tags = tags.filter(t => t !== tag);
          renderTags();
          updateHidden();
        });
        tagContainer.insertBefore(pill, tagInput);
      });
    }

    function updateHidden() {
      if (tagsHidden) tagsHidden.value = tags.join(',');
    }

    tagInput.addEventListener('keydown', function (e) {
      if (['Enter', ',', ' '].includes(e.key)) {
        e.preventDefault();
        const val = this.value.trim().replace(/,/g, '');
        if (val && !tags.includes(val)) {
          tags.push(val);
          renderTags();
          updateHidden();
        }
        this.value = '';
      }
    });

    renderTags();
  }

  // ── Auto-save Indicator ────────────────────────────────────────────────────
  let autoSaveTimer = null;
  const autoSaveEl  = document.getElementById('autosave-status');

  if (contentArea && autoSaveEl) {
    contentArea.addEventListener('input', () => {
      autoSaveEl.textContent = 'Editing...';
      autoSaveEl.style.color = 'var(--text-muted)';
      clearTimeout(autoSaveTimer);
      autoSaveTimer = setTimeout(() => {
        // Store to localStorage as backup
        const noteId = document.getElementById('note-id')?.value;
        if (noteId) {
          localStorage.setItem(`note_draft_${noteId}`, contentArea.value);
        }
        autoSaveEl.textContent = 'Draft saved';
        autoSaveEl.style.color = 'var(--green)';
        setTimeout(() => { autoSaveEl.textContent = ''; }, 2000);
      }, 1500);
    });
  }

  // ── Restore Draft ──────────────────────────────────────────────────────────
  const noteId = document.getElementById('note-id')?.value;
  if (noteId && contentArea) {
    const draft = localStorage.getItem(`note_draft_${noteId}`);
    if (draft && draft !== contentArea.value) {
      const restoreBar = document.getElementById('restore-draft-bar');
      if (restoreBar) {
        restoreBar.style.display = 'flex';
        document.getElementById('btn-restore-draft')?.addEventListener('click', () => {
          contentArea.value = draft;
          restoreBar.style.display = 'none';
        });
        document.getElementById('btn-discard-draft')?.addEventListener('click', () => {
          localStorage.removeItem(`note_draft_${noteId}`);
          restoreBar.style.display = 'none';
        });
      }
    }
  }

  // ── Note Card Click → Navigate ─────────────────────────────────────────────
  document.querySelectorAll('.note-card[data-href]').forEach(card => {
    card.style.cursor = 'pointer';
    card.addEventListener('click', () => {
      window.location.href = card.dataset.href;
    });
  });

});
