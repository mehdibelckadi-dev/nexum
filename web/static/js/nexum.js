/* ============================================================
   NEXUM — Scanner UI logic
   Vanilla JS. No dependencies.
   ============================================================ */

(function () {
  'use strict';

  // ── DOM refs ────────────────────────────────────────────
  const dropZone     = document.getElementById('dropZone');
  const fileInput    = document.getElementById('fileInput');
  const dropIcon     = document.getElementById('dropIcon');
  const dropTitle    = document.getElementById('dropTitle');
  const btnScan      = document.getElementById('btnScan');
  const btnReport    = document.getElementById('btnReport');
  const scanLoading  = document.getElementById('scanLoading');
  const loadingText  = document.getElementById('loadingText');
  const scanError    = document.getElementById('scanError');
  const errorMsg     = document.getElementById('errorMsg');
  const scanResult   = document.getElementById('scanResult');
  const scoreNumber  = document.getElementById('scoreNumber');
  const tierBadge    = document.getElementById('tierBadge');
  const findingsCount = document.getElementById('findingsCount');
  const findingsList = document.getElementById('findingsList');
  const badgeMarkdown = document.getElementById('badgeMarkdown');
  const btnCopy      = document.getElementById('btnCopy');
  const statApis     = document.getElementById('statApis');

  // Guard: only run on pages that have the scanner
  if (!dropZone) return;

  let selectedFile = null;
  let lastTier = null;

  // ── Init — ensure clean state regardless of CSS load order ──
  hideAll();

  // ── File selection ───────────────────────────────────────
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) onFileSelected(fileInput.files[0]);
  });

  function onFileSelected(file) {
    selectedFile = file;
    dropTitle.textContent = file.name;
    if (dropIcon) dropIcon.textContent = '✓';
    dropZone.classList.add('has-file');
    btnScan.disabled = false;
    btnReport.disabled = false;
    hideAll();
  }

  // ── Drag & drop ──────────────────────────────────────────
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) {
      fileInput.files = e.dataTransfer.files;
      onFileSelected(file);
    }
  });

  // ── Scan ────────────────────────────────────────────────
  btnScan.addEventListener('click', runScan);

  async function runScan() {
    if (!selectedFile) return;
    hideAll();
    showLoading('Analyzing spec…');

    const form = new FormData();
    form.append('file', selectedFile);

    try {
      const res = await fetch('/scan', { method: 'POST', body: form });
      const data = await res.json();

      if (!res.ok) {
        showError(data.detail || 'Scan failed. Please check your file and try again.');
        return;
      }
      renderResult(data);
    } catch (err) {
      showError('Network error. Please check your connection and try again.');
    }
  }

  function renderResult(data) {
    hideAll();
    const tier = data.tier;
    lastTier = tier;

    // Score
    scoreNumber.textContent = data.score;
    scoreNumber.className = 'result-score-number mono tier-' + tier;

    // Tier badge
    tierBadge.textContent = data.tier_label;
    tierBadge.className = 'result-tier-badge tier-' + tier;

    // Findings count
    const total = data.findings_count;
    findingsCount.textContent = total === 1 ? '1 finding' : total + ' findings';

    // Top findings list
    findingsList.innerHTML = '';
    (data.top_findings || []).forEach((f) => {
      const li = document.createElement('li');
      li.className = 'finding-item';
      li.innerHTML = `
        <span class="finding-sev sev-${f.severity}">${f.severity}</span>
        <span class="finding-path mono">${escHtml(f.method)} ${escHtml(f.path)} &mdash; ${escHtml(f.rule_id)}</span>
      `;
      findingsList.appendChild(li);
    });

    // Badge markdown
    const mdText = `![Nexum Certified](https://getnexum.dev/badge/${tier})`;
    badgeMarkdown.textContent = mdText;
    badgeMarkdown.dataset.value = mdText;

    scanResult.classList.add('visible');
  }

  // ── Report download ──────────────────────────────────────
  btnReport.addEventListener('click', downloadReport);

  async function downloadReport() {
    if (!selectedFile) return;
    hideAll();
    showLoading('Generating PDF…');

    const form = new FormData();
    form.append('file', selectedFile);

    try {
      const res = await fetch('/report', { method: 'POST', body: form });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        showError(data.detail || 'Report generation failed.');
        return;
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      const stem = selectedFile.name.replace(/\.[^.]+$/, '');
      a.href     = url;
      a.download = stem + '_nexum.pdf';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      hideAll();
      // Re-show result if we had one
      if (lastTier !== null) scanResult.classList.add('visible');
    } catch (err) {
      showError('Network error while downloading the report.');
    }
  }

  // ── Copy badge markdown ──────────────────────────────────
  window.copyBadge = function () {
    const text = badgeMarkdown.dataset.value || badgeMarkdown.textContent;
    navigator.clipboard.writeText(text).then(() => {
      btnCopy.textContent = 'Copied!';
      btnCopy.classList.add('copied');
      setTimeout(() => {
        btnCopy.textContent = 'Copy';
        btnCopy.classList.remove('copied');
      }, 2000);
    });
  };

  // ── Helpers ──────────────────────────────────────────────
  function showLoading(msg) {
    loadingText.textContent = msg;
    scanLoading.classList.add('visible');
  }

  function showError(msg) {
    hideAll();
    errorMsg.textContent = msg;
    scanError.classList.add('visible');
  }

  function hideAll() {
    scanLoading.classList.remove('visible');
    scanError.classList.remove('visible');
    scanResult.classList.remove('visible');
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Dynamic stats ────────────────────────────────────────
  if (statApis) {
    fetch('/registry-data')
      .then((r) => r.json())
      .then((d) => { statApis.textContent = d.length.toLocaleString(); })
      .catch(() => {});
  }
})();
