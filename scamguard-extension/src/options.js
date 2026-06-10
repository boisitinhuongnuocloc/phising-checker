const historyEl = document.querySelector('#history');
const clearBtn = document.querySelector('#clear-history');

function escapeHtml(str) {
  return String(str || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function loadHistory() {
  const { scamguardHistory = [] } = await chrome.storage.local.get('scamguardHistory');
  if (!scamguardHistory.length) {
    historyEl.innerHTML = '<div class="empty">Chưa có lịch sử scan.</div>';
    return;
  }
  historyEl.innerHTML = scamguardHistory.map((report) => `
    <article class="item">
      <div class="item-head">
        <div>
          <strong>${escapeHtml(report.summary)}</strong>
          <p>${escapeHtml(new Date(report.scannedAt).toLocaleString())}</p>
        </div>
        <span class="badge ${escapeHtml(report.level)}">${escapeHtml(report.level.toUpperCase())} ${report.score}/100</span>
      </div>
      ${report.page?.url ? `<p class="url">${escapeHtml(report.page.url)}</p>` : ''}
      <ul class="findings">
        ${(report.findings || []).slice(0, 6).map((f) => `<li>${escapeHtml(f.title)} — ${escapeHtml(f.detail)}</li>`).join('')}
      </ul>
    </article>
  `).join('');
}

clearBtn.addEventListener('click', async () => {
  await chrome.storage.local.set({ scamguardHistory: [] });
  loadHistory();
});

loadHistory();
