/**
 * JobFlow AI — Cross-Browser Extension Background Worker (Chrome, Safari, Firefox)
 * Manages cross-tab autofill session state, secure action tickets, and execution lifecycle.
 */

// Cross-browser compatibility polyfill (Safari Web Extension / Chrome / Firefox)
if (typeof chrome === "undefined" && typeof browser !== "undefined") {
  globalThis.chrome = browser;
} else if (typeof browser === "undefined" && typeof chrome !== "undefined") {
  globalThis.browser = chrome;
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("[JobFlow Extension] Installed and initialized.");
  chrome.action.setBadgeText({ text: "" });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "JOBFLOW_SET_ACTIVE_PLAN") {
    const data = {
      plan: message.payload,
      timestamp: Date.now(),
    };
    chrome.storage.local.set({ activeAutofill: data }, () => {
      chrome.action.setBadgeText({ text: "ACT" });
      chrome.action.setBadgeBackgroundColor({ color: "#4f46e5" });
      sendResponse({ success: true });
    });
    return true; // Keep message channel open for async response
  }

  if (message.type === "JOBFLOW_GET_ACTIVE_PLAN") {
    chrome.storage.local.get("activeAutofill", (result) => {
      const active = result.activeAutofill;
      if (!active || !active.plan) {
        sendResponse({ plan: null });
        return;
      }
      // Check 10-minute expiry
      const ageMs = Date.now() - (active.timestamp || 0);
      if (ageMs > 10 * 60 * 1000) {
        chrome.storage.local.remove("activeAutofill");
        chrome.action.setBadgeText({ text: "" });
        sendResponse({ plan: null, expired: true });
        return;
      }
      sendResponse({ plan: active.plan });
    });
    return true;
  }

  if (message.type === "JOBFLOW_REPORT_COMPLETED") {
    chrome.action.setBadgeText({ text: "DONE" });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
    // After 10 seconds clear badge
    setTimeout(() => {
      chrome.action.setBadgeText({ text: "" });
    }, 10000);
    sendResponse({ success: true });
    return true;
  }

  if (message.type === "JOBFLOW_CLEAR_ACTIVE_PLAN") {
    chrome.storage.local.remove("activeAutofill", () => {
      chrome.action.setBadgeText({ text: "" });
      sendResponse({ success: true });
    });
    return true;
  }
});
