const $ = (selector) => document.querySelector(selector);

const tabPage = $('#tab-page');
const tabManual = $('#tab-manual');
const pagePanel = $('#page-panel');
const manualPanel = $('#manual-panel');
const resultEl = $('#result');
let lastReport = null;

function setTab(name) {
  const page = name === 'page';
  tabPage.classList.toggle('active', page);
  tabManual.classList.toggle('active', !page);
  pagePanel.classList.toggle('active', page);
  manualPanel.classList.toggle('active', !page);
}

tabPage.addEventListener('click', () => setTab('page'));
tabManual.addEventListener('click', () => setTab('manual'));

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function getCurrentPagePayload() {
  const tab = await activeTab();
  if (!tab?.id) throw new Error('Không tìm thấy tab hiện tại.');

  try {
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'SCAMGUARD_GET_PAGE' });
    if (response?.ok) return response.payload;
  } catch (err) {
    // Some Chrome pages do not allow content scripts. Fallback to tab URL only.
  }

  return {
    title: tab.title || '',
    url: tab.url || '',
    selectedText: '',
    bodyText: '',
    links: []
  };
}

function combinedTextFromPage(payload) {
  const linkText = (payload.links || [])
    .map((link) => `${link.text || ''} ${link.href || ''}`)
    .join('\n')
    .slice(0, 30000);
  return [
    payload.title || '',
    payload.url || '',
    payload.selectedText || '',
    payload.bodyText || '',
    linkText
  ].join('\n');
}

function escapeHtml(str) {
  return String(str || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function renderReport(report) {
  lastReport = report;
  const levelText = {
    high: 'HIGH RISK',
    medium: 'MEDIUM',
    low: 'LOW',
    safe: 'SAFE'
  }[report.level] || report.level;

  const recs = window.SafeCheckScanner.recommendation(report.level);
  const findingHtml = report.findings.length
    ? report.findings.map((finding) => `
      <article class="finding ${escapeHtml(finding.severity)}">
        <div class="finding-title">${escapeHtml(finding.title)} <span class="points">+${finding.points}</span></div>
        <div class="finding-detail">${escapeHtml(finding.detail)}</div>
        ${finding.url ? `<div class="finding-detail">URL: ${escapeHtml(finding.url)}</div>` : ''}
      </article>
    `).join('')
    : '<p class="hint">Không phát hiện dấu hiệu rõ ràng.</p>';

  const urlHtml = report.urlReports?.length
    ? `<h3 class="subhead">URLs detected</h3><ul class="url-list">${report.urlReports.slice(0, 8).map((u) => `<li>${escapeHtml(u.hostname || u.url)} — ${u.score}/100</li>`).join('')}</ul>`
    : '';

  resultEl.classList.remove('empty');
  resultEl.innerHTML = `
    <div class="score-head">
      <div>
        <div class="level ${report.level}">${levelText}</div>
      </div>
      <div class="score-number">${report.score}</div>
    </div>
    <div class="meter"><div class="meter-fill ${report.level}" style="width:${report.score}%"></div></div>
    <p class="summary">${escapeHtml(report.summary)}</p>
    <h3 class="subhead">Findings</h3>
    ${findingHtml}
    ${urlHtml}
    <h3 class="subhead">Recommended actions</h3>
    <ul class="recs">${recs.map((rec) => `<li>${escapeHtml(rec)}</li>`).join('')}</ul>
  `;
}

async function scanPage() {
  $('#scan-page').disabled = true;
  try {
    const payload = await getCurrentPagePayload();
    const report = window.SafeCheckScanner.analyzeText(combinedTextFromPage(payload), { source: 'page' });
    report.page = { title: payload.title, url: payload.url, linkCount: payload.links?.length || 0 };
    renderReport(report);
  } catch (err) {
    resultEl.innerHTML = `<div class="empty-state">${escapeHtml(err.message)}</div>`;
  } finally {
    $('#scan-page').disabled = false;
  }
}

function scanManual() {
  const text = $('#manual-input').value;
  const report = window.SafeCheckScanner.analyzeText(text, { source: 'manual' });
  renderReport(report);
}

async function highlightLinks() {
  const tab = await activeTab();
  if (!tab?.id) return;
  try {
    const res = await chrome.tabs.sendMessage(tab.id, { type: 'SCAMGUARD_HIGHLIGHT_LINKS' });
    resultEl.innerHTML = `<div class="empty-state">Đã highlight ${res?.highlighted || 0} link đáng nghi trên trang.</div>`;
  } catch {
    resultEl.innerHTML = '<div class="empty-state">Không thể highlight trên trang này. Chrome pages và extension pages thường bị chặn.</div>';
  }
}

async function clearHighlights() {
  const tab = await activeTab();
  if (!tab?.id) return;
  try { await chrome.tabs.sendMessage(tab.id, { type: 'SCAMGUARD_CLEAR_HIGHLIGHTS' }); } catch {}
}

function reportText(report) {
  if (!report) return 'No report yet.';
  const lines = [
    `ScamGuard report`,
    `Risk: ${report.level.toUpperCase()} (${report.score}/100)`,
    `Summary: ${report.summary}`,
    '',
    'Findings:'
  ];
  report.findings.forEach((f) => lines.push(`- [${f.severity}] ${f.title}: ${f.detail}`));
  lines.push('', 'Recommended actions:');
  window.SafeCheckScanner.recommendation(report.level).forEach((rec) => lines.push(`- ${rec}`));
  return lines.join('\n');
}

async function copyReport() {
  await navigator.clipboard.writeText(reportText(lastReport));
}

async function saveHistory() {
  if (!lastReport) return;
  const { scamguardHistory = [] } = await chrome.storage.local.get('scamguardHistory');
  scamguardHistory.unshift(lastReport);
  await chrome.storage.local.set({ scamguardHistory: scamguardHistory.slice(0, 50) });
}

$('#scan-page').addEventListener('click', scanPage);
$('#scan-manual').addEventListener('click', scanManual);
$('#highlight-links').addEventListener('click', highlightLinks);
$('#clear-highlights').addEventListener('click', clearHighlights);
$('#copy-report').addEventListener('click', copyReport);
$('#save-history').addEventListener('click', saveHistory);

document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
    if (manualPanel.classList.contains('active')) scanManual();
    else scanPage();
  }
});
