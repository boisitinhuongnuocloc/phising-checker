chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ scamguardInstalledAt: new Date().toISOString() });
});
