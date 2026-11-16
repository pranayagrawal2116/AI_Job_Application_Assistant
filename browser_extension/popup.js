document.addEventListener("DOMContentLoaded", async () => {
  const statusBadge = document.getElementById("statusBadge");
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  const jobTitle = document.getElementById("jobTitle");
  const jobDetails = document.getElementById("jobDetails");
  const autofillBtn = document.getElementById("autofillBtn");

  try {
    chrome.runtime.sendMessage({ type: "JOBFLOW_GET_ACTIVE_PLAN" }, (response) => {
      if (response && response.plan) {
        const plan = response.plan;
        statusDot.classList.add("active");
        statusText.textContent = "Ready for Form Auto-Fill";
        statusBadge.style.background = "#ecfdf5";
        statusBadge.style.color = "#047857";

        jobTitle.textContent = plan.job_title || "Application In Progress";
        jobDetails.textContent = `${plan.company_name || "Employer"} • ATS: ${plan.ats_provider || "Standard"}`;

        autofillBtn.disabled = false;
        autofillBtn.onclick = async () => {
          autofillBtn.disabled = true;
          autofillBtn.textContent = "Populating...";
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab && tab.id) {
            chrome.scripting.executeScript({
              target: { tabId: tab.id },
              files: ["content.js"],
            });
            setTimeout(() => {
              window.close();
            }, 1000);
          }
        };
      } else {
        statusDot.classList.remove("active");
        statusText.textContent = "Idle — No Active Plan";
        jobTitle.textContent = "No Active Application";
        jobDetails.textContent = 'Go to JobFlow web app, open an application, and click "Open Employer Application Form & Auto-Fill".';
        autofillBtn.disabled = true;
      }
    });
  } catch (err) {
    statusText.textContent = "Extension Offline";
    console.error("Popup error:", err);
  }
});
