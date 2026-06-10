(function scamGuardContent() {
  'use strict';

  function pagePayload() {
    const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 400).map((a) => ({
      href: a.href,
      text: (a.innerText || a.textContent || '').trim().slice(0, 160)
    }));

    const selectedText = String(window.getSelection ? window.getSelection() : '').trim();
    const bodyText = (document.body?.innerText || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 12000);

    return {
      title: document.title,
      url: location.href,
      selectedText,
      bodyText,
      links
    };
  }

  function clearHighlights() {
    document.querySelectorAll('[data-scamguard-highlight="1"]').forEach((el) => {
      el.style.outline = el.dataset.scamguardOldOutline || '';
      el.style.boxShadow = el.dataset.scamguardOldBoxShadow || '';
      el.style.borderRadius = el.dataset.scamguardOldBorderRadius || '';
      el.removeAttribute('data-scamguard-highlight');
      delete el.dataset.scamguardOldOutline;
      delete el.dataset.scamguardOldBoxShadow;
      delete el.dataset.scamguardOldBorderRadius;
    });
  }

  function highlightLinks() {
    clearHighlights();
    if (!window.SafeCheckScanner) return { highlighted: 0 };

    let highlighted = 0;
    document.querySelectorAll('a[href]').forEach((a) => {
      const report = window.SafeCheckScanner.analyzeUrl(a.href);
      if (report.score >= 45) {
        a.dataset.scamguardHighlight = '1';
        a.dataset.scamguardOldOutline = a.style.outline || '';
        a.dataset.scamguardOldBoxShadow = a.style.boxShadow || '';
        a.dataset.scamguardOldBorderRadius = a.style.borderRadius || '';
        a.style.outline = report.level === 'high' ? '3px solid #ff3b30' : '3px solid #ffcc00';
        a.style.boxShadow = '0 0 0 4px rgba(255, 59, 48, 0.25)';
        a.style.borderRadius = '4px';
        a.title = `[ScamGuard] Risk ${report.score}/100 - ${report.findings[0]?.title || 'Suspicious link'}`;
        highlighted += 1;
      }
    });
    return { highlighted };
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === 'SCAMGUARD_GET_PAGE') {
      sendResponse({ ok: true, payload: pagePayload() });
      return true;
    }
    if (message?.type === 'SCAMGUARD_HIGHLIGHT_LINKS') {
      sendResponse({ ok: true, ...highlightLinks() });
      return true;
    }
    if (message?.type === 'SCAMGUARD_CLEAR_HIGHLIGHTS') {
      clearHighlights();
      sendResponse({ ok: true });
      return true;
    }
    return false;
  });
})();
