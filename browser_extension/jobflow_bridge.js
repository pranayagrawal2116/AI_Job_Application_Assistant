/**
 * JobFlow AI — React Web App Bridge (jobflow_bridge.js)
 * Injected on http://localhost:3000 to bridge web UI actions with the Chrome Extension.
 */

(function () {
  // 1. Signal to React that the JobFlow Extension is active and ready
  document.documentElement.setAttribute("data-jobflow-extension-installed", "true");
  window.__JOBFLOW_EXTENSION_ACTIVE__ = true;

  // Dispatch a custom event in case React has already mounted
  window.dispatchEvent(new CustomEvent("JOBFLOW_EXTENSION_READY", { detail: { version: "1.0.0" } }));

  // 2. Listen for messages from JobFlow frontend
  window.addEventListener("message", (event) => {
    if (!event.data || typeof event.data !== "object") return;

    if (event.data.type === "JOBFLOW_START_AUTOFILL") {
      const plan = event.data.payload;
      if (!plan || !plan.execution_id) return;

      console.log("[JobFlow Bridge] Received active autofill plan from web app:", plan.execution_id);
      chrome.runtime.sendMessage(
        {
          type: "JOBFLOW_SET_ACTIVE_PLAN",
          payload: plan,
        },
        (response) => {
          console.log("[JobFlow Bridge] Plan registered with extension background:", response);
        }
      );
    }
  });

  console.log("[JobFlow Bridge] Extension bridge connected to JobFlow Web UI.");
})();
