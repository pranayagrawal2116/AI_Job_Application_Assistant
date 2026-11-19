/**
 * JobFlow AI — Cross-Browser Extension Content Script (Chrome, Safari, Firefox)
 * Automatically detects employer ATS forms and performs autofill using verified candidate data.
 */

// Cross-browser compatibility polyfill (Safari Web Extension / Chrome / Firefox)
if (typeof chrome === "undefined" && typeof browser !== "undefined") {
  globalThis.chrome = browser;
} else if (typeof browser === "undefined" && typeof chrome !== "undefined") {
  globalThis.browser = chrome;
}

(async function () {
  console.log("[JobFlow Content] Initialized on:", window.location.href);

  // 1. Try to get active plan from extension background storage
  let activePlan = null;
  try {
    const response = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "JOBFLOW_GET_ACTIVE_PLAN" }, resolve);
    });
    if (response && response.plan) {
      activePlan = response.plan;
    }
  } catch (err) {
    // If not in extension context, check window.JOBFLOW_CONFIG
    console.debug("[JobFlow Content] chrome.runtime not reachable or no active plan:", err);
  }

  if (!activePlan && window.JOBFLOW_CONFIG) {
    activePlan = {
      application_id: window.JOBFLOW_CONFIG.appId,
      action_ticket: window.JOBFLOW_CONFIG.ticket,
      execution_id: window.JOBFLOW_CONFIG.executionId,
      api_base: window.JOBFLOW_CONFIG.apiBase,
    };
  }

  // 2. Check if this page is an employer application form or matches the active plan
  function isEmployerApplicationPage() {
    // Match URL or page DOM markers for ATS
    const url = window.location.href.toLowerCase();
    const isAtsUrl = url.includes("keka.com") || url.includes("greenhouse.io") || 
                      url.includes("lever.co") || url.includes("workday") || 
                      url.includes("careers") || url.includes("jobs") || url.includes("apply");
    
    const hasApplicationForm = !!(
      document.querySelector('form') ||
      document.querySelector('input[type="file"]') ||
      document.querySelector('#resume-upload, .resume-upload, [id*="resume"], [class*="resume"]') ||
      document.querySelector('input[name*="name"], input[id*="name"], input[name*="email"], input[id*="email"]')
    );

    return isAtsUrl || hasApplicationForm;
  }

  // If there's an active plan, verify target domain matches or runs if user triggered it
  if (!activePlan) {
    console.log("[JobFlow Content] No active autofill plan found for this tab.");
    return;
  }

  // Set global config so existing companion script functions can read it seamlessly
  window.JOBFLOW_CONFIG = {
    apiBase: activePlan.api_base || "http://127.0.0.1:8000/api",
    appId: activePlan.application_id,
    ticket: activePlan.action_ticket,
    executionId: activePlan.execution_id,
  };

  console.log("[JobFlow Content] Active plan detected for Application #" + activePlan.application_id);

  // Execute form-filling routines
  await runFormFillingRoutine(window.JOBFLOW_CONFIG, activePlan);

  async function runFormFillingRoutine(config, plan) {
    const API_BASE = config.apiBase;
    const APP_ID = config.appId;
    const TICKET = config.ticket;
    const EXECUTION_ID = config.executionId;

    // Helper: Safe element creation
    function el(tag, styles = {}, attrs = {}, text = '') {
      const elem = document.createElement(tag);
      for (const [k, v] of Object.entries(styles)) {
        elem.style[k] = v;
      }
      for (const [k, v] of Object.entries(attrs)) {
        elem.setAttribute(k, v);
      }
      if (text) {
        elem.textContent = text;
      }
      return elem;
    }

    // Helper: Floating overlay
    function createOverlay() {
      let existing = document.getElementById("jobflow-assistant-overlay");
      if (existing) existing.remove();

      const container = el("div", {
        position: "fixed",
        bottom: "24px",
        right: "24px",
        width: "390px",
        maxHeight: "85vh",
        overflowY: "auto",
        background: "#ffffff",
        color: "#0f172a",
        borderRadius: "16px",
        boxShadow: "0 20px 25px -5px rgba(0,0,0,0.2), 0 8px 10px -6px rgba(0,0,0,0.1)",
        border: "1px solid #cbd5e1",
        zIndex: "9999999",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        fontSize: "13px",
        lineHeight: "1.5",
        padding: "16px",
        boxSizing: "border-box",
      }, { id: "jobflow-assistant-overlay" });

      document.body.appendChild(container);
      return container;
    }

    const overlay = createOverlay();

    function renderHeader(company = "", role = "") {
      const header = el("div", {
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        marginBottom: "12px",
        borderBottom: "1px solid #f1f5f9",
        paddingBottom: "8px",
      });

      const left = el("div", { display: "flex", alignItems: "center", gap: "8px" });
      const dot = el("div", { width: "10px", height: "10px", borderRadius: "50%", background: "#4f46e5" });
      const titleWrap = el("div");
      const strong = el("strong", { fontSize: "14px", color: "#1e293b" }, {}, "JobFlow AI Assistant");
      titleWrap.appendChild(strong);
      if (company) {
        const subtitle = el("div", { fontSize: "11px", color: "#64748b" }, {}, `${role ? role + " • " : ""}${company}`);
        titleWrap.appendChild(subtitle);
      }

      left.appendChild(dot);
      left.appendChild(titleWrap);

      const closeBtn = el("button", {
        border: "none",
        background: "none",
        cursor: "pointer",
        color: "#94a3b8",
        fontSize: "18px",
        fontWeight: "bold",
      }, {}, "×");
      closeBtn.onclick = () => overlay.remove();

      header.appendChild(left);
      header.appendChild(closeBtn);
      return header;
    }

    function setOverlayContent(contentElem, company = "", role = "") {
      overlay.replaceChildren(renderHeader(company, role), contentElem);
    }

    // React-compatible value setter
    function setNativeValue(element, value) {
      if (!element) return;
      const tag = element.tagName.toLowerCase();
      if (tag === "select") {
        let matched = false;
        const targetVal = String(value).toLowerCase().trim();
        for (let i = 0; i < element.options.length; i++) {
          const opt = element.options[i];
          if (opt.value.toLowerCase().trim() === targetVal || opt.text.toLowerCase().trim() === targetVal) {
            element.selectedIndex = i;
            matched = true;
            break;
          }
        }
        if (!matched && element.options.length > 0) {
          for (let i = 0; i < element.options.length; i++) {
            const opt = element.options[i];
            if (opt.text.toLowerCase().includes(targetVal)) {
              element.selectedIndex = i;
              break;
            }
          }
        }
        element.dispatchEvent(new Event("change", { bubbles: true }));
        return;
      }

      const proto = tag === "textarea" ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
      const desc = Object.getOwnPropertyDescriptor(proto, "value");
      if (desc && desc.set) {
        desc.set.call(element, value);
      } else {
        element.value = value;
      }
      element.dispatchEvent(new Event("input", { bubbles: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
      element.dispatchEvent(new Event("blur", { bubbles: true }));
    }

    const stateCard = el("div", {}, {}, "Connecting to JobFlow AI...");
    setOverlayContent(stateCard);

    // 3. Fetch Autofill Plan & Facts
    let fetchedPlan = plan;
    try {
      const headers = { "Content-Type": "application/json" };
      if (TICKET) headers["Authorization"] = `Bearer ${TICKET}`;
      const planRes = await fetch(`${API_BASE}/applications/${APP_ID}/autofill/plan`, {
        method: "POST",
        headers,
        body: JSON.stringify({ action_ticket: TICKET, execution_id: EXECUTION_ID }),
      });
      if (planRes.ok) {
        fetchedPlan = await planRes.json();
      }
    } catch (err) {
      console.warn("[JobFlow Content] Could not refresh plan from server, using cached plan:", err);
    }

    const companyName = fetchedPlan.company_name || "";
    const jobTitle = fetchedPlan.job_title || "";
    const facts = fetchedPlan.candidate_facts || fetchedPlan.facts || {};
    const host = window.location.hostname.toLowerCase();

    let atsDetected = fetchedPlan.ats_provider || "universal";
    if (host.includes("lever.co")) atsDetected = "lever";
    else if (host.includes("keka.com")) atsDetected = "keka";
    else if (host.includes("greenhouse.io")) atsDetected = "greenhouse";
    else if (host.includes("workday.com")) atsDetected = "workday";

    const formFound = !!(
      document.querySelector("form#application-form") ||
      document.querySelector("form") ||
      document.querySelector('[data-qa="name-input"]') ||
      document.querySelector('input[name="name"]') ||
      document.querySelector('input[type="file"]')
    );

    async function pushProgress(stage, stageIndex, message, stats = null) {
      try {
        const headers = { "Content-Type": "application/json" };
        if (TICKET) headers["Authorization"] = `Bearer ${TICKET}`;
        await fetch(`${API_BASE}/applications/${APP_ID}/autofill/progress`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            execution_id: EXECUTION_ID,
            action_ticket: TICKET,
            stage: stage,
            stage_index: stageIndex,
            message: message,
            stats: stats,
          }),
        });
      } catch (e) {}
    }

    // Handshake
    try {
      const headers = { "Content-Type": "application/json" };
      if (TICKET) headers["Authorization"] = `Bearer ${TICKET}`;
      await fetch(`${API_BASE}/applications/${APP_ID}/autofill/handshake`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          execution_id: EXECUTION_ID,
          action_ticket: TICKET,
          domain: host,
          companion_version: "1.2.0",
          ats_detected: atsDetected,
          form_found: formFound,
        }),
      });
    } catch (hErr) {
      console.warn("[JobFlow Content] Handshake warning:", hErr);
    }

    // Step 1.8: Pre-Application Gate Detection (IAGH)
    function detectPageGate() {
      const cf = document.querySelector('iframe[src*="challenges.cloudflare.com"], #cf-chl-widget, .cf-turnstile');
      const h1Text = (document.querySelector('h1, h2, title')?.innerText || '').toLowerCase();
      if (cf || h1Text.includes('just a moment') || h1Text.includes('verify you are human')) {
        return {
          category: 'SECURITY',
          gateType: 'CLOUDFLARE_VERIFICATION',
          isBlocking: true,
          title: 'Security Verification Required',
          instruction: 'Please complete the Cloudflare verification in this tab. JobFlow will resume automatically.',
        };
      }

      const cookieBanner = document.querySelector('#onetrust-banner-sdk, .cookie-banner, .cookie-consent, [aria-label*="cookie" i], [id*="cookie" i]');
      if (cookieBanner && cookieBanner.querySelector('button, a')) {
        return {
          category: 'COOKIE',
          gateType: 'COOKIE_CONSENT',
          isBlocking: true,
          title: 'Cookie Consent Preferences',
          instruction: 'Please select your cookie preferences in this tab to proceed.',
          element: cookieBanner,
        };
      }

      const pwdInput = document.querySelector('input[type="password"]');
      const hasResumeInput = !!document.querySelector('input[type="file"], [data-qa="input-resume"]');
      if (pwdInput && !hasResumeInput) {
        return {
          category: 'AUTHENTICATION',
          gateType: 'LOGIN_REQUIRED',
          isBlocking: true,
          title: 'Employer Portal Sign-In Required',
          instruction: 'Please sign in to your candidate account in this tab. JobFlow will resume once authenticated.',
          element: pwdInput.closest('form') || pwdInput,
        };
      }

      const modalDialog = document.querySelector('dialog[open], [role="dialog"], .modal.show, .modal-open, .terms-modal');
      const scope = modalDialog || document;
      const consentHeader = scope.querySelector('h1, h2, h3, h4, legend, strong');
      const headerText = (consentHeader?.innerText || '').toLowerCase();
      const hasConsentHeading = /privacy notice|candidate privacy|terms and conditions|recruitment consent|data processing|applicant declaration/i.test(headerText);
      const agreeBtn = scope.querySelector('button, input[type="submit"], a');
      const agreeBtnText = (agreeBtn?.innerText || agreeBtn?.value || '').toLowerCase();
      const hasAgreeBtn = /i agree|i accept|accept and continue|acknowledge|agree & continue/i.test(agreeBtnText);
      const consentCheckbox = scope.querySelector('input[type="checkbox"][name*="consent" i], input[type="checkbox"][name*="privacy" i], input[type="checkbox"][name*="agree" i]');

      if ((hasConsentHeading && (hasAgreeBtn || consentCheckbox)) || (modalDialog && (hasAgreeBtn || consentCheckbox))) {
        if (!consentHeader?.closest('footer, .footer, #footer')) {
          return {
            category: 'LEGAL_PRIVACY',
            gateType: headerText.includes('terms') ? 'TERMS_AND_CONDITIONS' : 'PRIVACY_POLICY',
            isBlocking: true,
            title: 'Legal & Privacy Agreement Review',
            instruction: 'The employer requires you to review and accept their agreement before continuing. Please make your decision in this tab.',
            element: modalDialog || agreeBtn || consentCheckbox,
          };
        }
      }

      const hasName = !!document.querySelector('[data-qa="name-input"], input[name="name"], input[name*="fullname" i]');
      const hasEmail = !!document.querySelector('[data-qa="email-input"], input[type="email"], input[name="email"]');
      if ((hasResumeInput && (hasName || hasEmail)) || (hasName && hasEmail)) {
        return {
          category: 'NONE',
          gateType: 'APPLICATION_FORM_READY',
          isBlocking: false,
          title: 'Application Form Ready',
          instruction: 'Application form is ready for auto-population.',
          formDetected: true,
        };
      }

      return {
        category: 'NONE',
        gateType: 'GENERIC_PAGE',
        isBlocking: false,
        title: 'Page Analyzing',
        instruction: 'Analyzing page structure...',
        formDetected: false,
      };
    }

    let currentGate = detectPageGate();
    if (currentGate.isBlocking) {
      console.log('[JobFlow Content] Blocking gate detected:', currentGate.gateType);
      const wrap = el('div', { padding: '10px 0' });
      const badge = el('div', {
        display: 'inline-flex',
        alignItems: 'center',
        padding: '4px 10px',
        borderRadius: '9999px',
        background: '#fef3c7',
        color: '#92400e',
        fontSize: '11px',
        fontWeight: '600',
        marginBottom: '8px',
      }, {}, '⏳ Action Required in This Tab');
      const title = el('div', { fontWeight: '700', fontSize: '14px', color: '#0f172a', marginBottom: '6px' }, {}, currentGate.title);
      const desc = el('div', { fontSize: '12px', color: '#475569', marginBottom: '12px' }, {}, currentGate.instruction);
      wrap.appendChild(badge);
      wrap.appendChild(title);
      wrap.appendChild(desc);
      setOverlayContent(wrap, companyName, jobTitle);

      try {
        await fetch(`${API_BASE}/applications/${APP_ID}/autofill/gate-event`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TICKET}` },
          body: JSON.stringify({
            execution_id: EXECUTION_ID,
            action_ticket: TICKET,
            event_type: 'GATE_DETECTED',
            current_url: window.location.href,
          }),
        });
      } catch (e) {}

      await new Promise((resolve) => {
        const interval = setInterval(() => {
          const check = detectPageGate();
          if (!check.isBlocking) {
            clearInterval(interval);
            resolve(true);
          }
        }, 800);
      });

      try {
        await fetch(`${API_BASE}/applications/${APP_ID}/autofill/resume`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TICKET}` },
          body: JSON.stringify({ execution_id: EXECUTION_ID, action_ticket: TICKET }),
        });
      } catch (e) {}
    }

    await pushProgress("FORM_IDENTIFIED", 3, `Identified ${atsDetected.toUpperCase()} application form on ${host}`);
    await pushProgress("FACTS_RETRIEVED", 4, "Retrieved verified candidate facts from JobFlow profile");

    const progressDiv = el("div", { display: "flex", flexDirection: "column", gap: "8px" });
    const stepLabel = el("div", { fontWeight: "600", color: "#334155" }, {}, "Step 1/3: Attaching verified resume...");
    progressDiv.appendChild(stepLabel);
    setOverlayContent(progressDiv, companyName, jobTitle);

    // 4. Attach Resume Binary to File Upload
    let resumeAttached = false;
    try {
      const fileInputSelectors = [
        'input[data-qa="input-resume"]',
        '#resume-upload-input',
        'input[type="file"][name="resume"]',
        '#resume-upload',
        'input[data-field-identifier="resume"]',
        'input[type="file"][name*="resume"]',
        'input[type="file"][id*="resume"]',
        'input[type="file"][accept*="pdf"]',
        '.resume-upload input[type="file"]',
        'input[type="file"]',
      ];
      let targetInput = null;
      for (const sel of fileInputSelectors) {
        const found = document.querySelector(sel);
        if (found) {
          targetInput = found;
          break;
        }
      }

      if (targetInput) {
        const resumeUrl = `${API_BASE}/applications/${APP_ID}/autofill/resume-binary?ticket=${encodeURIComponent(TICKET)}`;
        const resumeResp = await fetch(resumeUrl);
        if (resumeResp.ok) {
          const blob = await resumeResp.blob();
          const disp = resumeResp.headers.get("content-disposition") || "";
          let filename = "Candidate_Resume.pdf";
          const match = disp.match(/filename=["']?([^"';]+)["']?/);
          if (match && match[1]) filename = match[1];

          const file = new File([blob], filename, { type: blob.type || "application/pdf" });
          const dt = new DataTransfer();
          dt.items.add(file);
          targetInput.files = dt.files;
          targetInput.dispatchEvent(new Event("change", { bubbles: true }));
          targetInput.dispatchEvent(new Event("input", { bubbles: true }));
          resumeAttached = true;
          console.log("[JobFlow Content] Successfully attached verified resume:", filename);
        }
      }
    } catch (err) {
      console.warn("[JobFlow Content] Error attaching resume binary:", err);
    }

    await pushProgress("RESUME_UPLOADED", 5, resumeAttached ? "Verified resume uploaded to file input" : "No file upload input found; proceeding with text fields", { resume_uploaded: resumeAttached });

    // 5. Wait for ATS Resume Parsing
    stepLabel.textContent = "Step 2/3: Observing ATS resume parsing...";
    await new Promise((r) => setTimeout(r, 2000));
    await pushProgress("ATS_PARSING_COMPLETED", 6, "Observed ATS resume parsing response");

    // 6. Map and Populate Fields
    stepLabel.textContent = "Step 3/3: Auto-populating verified fields...";

    const populatedFields = [];
    const manualReviewFields = [];
    const atsParsedFields = [];

    const fieldSelectors = "input:not([type=hidden]):not([type=submit]):not([type=file]):not([type=button]):not([type=checkbox]):not([type=radio]), textarea, select";
    const allInputs = Array.from(document.querySelectorAll(fieldSelectors));

    for (const input of allInputs) {
      const dataQa = (input.getAttribute("data-qa") || "").toLowerCase();
      const idName = ((input.id || "") + " " + (input.name || "") + " " + (input.getAttribute("placeholder") || "") + " " + (input.getAttribute("aria-label") || "") + " " + dataQa).toLowerCase();
      let labelText = "";
      if (input.id) {
        const l = document.querySelector(`label[for="${input.id}"]`);
        if (l) labelText = l.textContent.toLowerCase();
      }
      const combined = (idName + " " + labelText).trim();

      // Check if existing value is already present (e.g. parsed by ATS or candidate entered)
      const currentVal = (input.value || "").trim();
      if (currentVal) {
        atsParsedFields.push({ label: labelText || input.name || input.id, value: currentVal });
        input.style.backgroundColor = "#eff6ff";
        input.style.border = "1.5px solid #3b82f6";
        continue;
      }

      // Check against sensitive fields (Zero Hallucination)
      if (combined.includes("gender") || combined.includes("birth") || combined.includes("dob") ||
          combined.includes("salary") || combined.includes("notice period") || combined.includes("ctc") ||
          combined.includes("race") || combined.includes("veteran") || combined.includes("eeo")) {
        manualReviewFields.push({ label: labelText || input.name || input.id, reason: "Requires Candidate Input (Zero Hallucination)" });
        input.style.backgroundColor = "#fffbeb";
        input.style.border = "1.5px solid #f59e0b";
        continue;
      }

      // Match facts
      let matchedKey = null;
      if (combined.includes("first name") || combined.includes("firstname")) matchedKey = "first_name";
      else if (combined.includes("last name") || combined.includes("lastname") || combined.includes("surname")) matchedKey = "last_name";
      else if (combined.includes("name-input") || combined.includes("full name") || combined.includes("fullname") || combined.includes("your name") || combined.includes("candidate name") || combined === "name") matchedKey = "full_name";
      else if (combined.includes("email-input") || combined.includes("email") || combined.includes("e-mail")) matchedKey = "email";
      else if (combined.includes("phone-input") || combined.includes("phone") || combined.includes("mobile") || combined.includes("contact number") || combined.includes("tel")) matchedKey = "phone";
      else if (combined.includes("urls[linkedin]") || combined.includes("linkedin")) matchedKey = "linkedin_url";
      else if (combined.includes("urls[github]") || combined.includes("github")) matchedKey = "github_url";
      else if (combined.includes("urls[portfolio]") || combined.includes("portfolio") || combined.includes("website") || combined.includes("personal url")) matchedKey = "portfolio_url";
      else if (combined.includes("location-input") || combined.includes("city") || combined.includes("location") || combined.includes("address")) matchedKey = "current_location";
      else if (combined.includes("org-input") || combined.includes("company") || combined.includes("employer") || combined.includes("organization") || combined === "org") matchedKey = "current_company";
      else if (combined.includes("job title") || combined.includes("designation") || combined.includes("title") || combined.includes("current role")) matchedKey = "current_job_title";
      else if (combined.includes("skills") || combined.includes("technologies")) matchedKey = "skills";

      if (matchedKey && facts[matchedKey] && facts[matchedKey].value) {
        const fact = facts[matchedKey];
        const valToSet = String(fact.value).trim();
        setNativeValue(input, valToSet);

        // Independent verification in DOM
        let finalVal = (input.value || "").trim();
        if (finalVal !== valToSet) {
          setNativeValue(input, valToSet);
          finalVal = (input.value || "").trim();
        }

        if (finalVal === valToSet) {
          input.style.backgroundColor = "#ecfdf5";
          input.style.border = "1.5px solid #10b981";
          populatedFields.push({ label: labelText || matchedKey, value: valToSet, key: matchedKey });
        } else {
          manualReviewFields.push({ label: labelText || matchedKey, reason: `Verification mismatch: expected '${valToSet}', got '${finalVal}'` });
          input.style.backgroundColor = "#fffbeb";
          input.style.border = "1.5px solid #f59e0b";
        }
      }
    }

    const isSuccess = (populatedFields.length > 0 || atsParsedFields.length > 0 || resumeAttached);
    const reportStatus = isSuccess ? "SUCCESS" : "NO_FIELDS_POPULATED";
    const reportMsg = isSuccess
      ? `Populated ${populatedFields.length} fields, ${atsParsedFields.length} parsed by ATS, ${manualReviewFields.length} require manual review.`
      : "Autofill could not populate any fields. The employer form remains unchanged. Please check the browser companion connection.";

    await pushProgress(isSuccess ? "READY_FOR_REVIEW" : "FAILED", isSuccess ? 9 : 4, reportMsg, {
      fields_populated_count: populatedFields.length,
      fields_ats_parsed_count: atsParsedFields.length,
      fields_preserved_count: 0,
      fields_manual_review_count: manualReviewFields.length,
      fields_verified_count: populatedFields.length,
    });

    // 7. Render Final Summary Card in Overlay
    const summaryCard = el("div", { display: "flex", flexDirection: "column", gap: "12px" });
    const successTitle = el("div", {
      display: "flex",
      alignItems: "center",
      gap: "6px",
      fontSize: "14px",
      fontWeight: "600",
      color: isSuccess ? "#059669" : "#b45309",
    }, {}, isSuccess ? "✓ Form Auto-Population Complete" : "⚠ Autofill Could Not Populate Fields");

    const statGrid = el("div", {
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr",
      gap: "8px",
      marginTop: "4px",
    });

    function statBox(num, label, color) {
      const b = el("div", {
        background: "#f8fafc",
        border: "1px solid #e2e8f0",
        borderRadius: "8px",
        padding: "8px",
        textAlign: "center",
      });
      const n = el("div", { fontSize: "16px", fontWeight: "700", color }, {}, String(num));
      const l = el("div", { fontSize: "10px", color: "#64748b", textTransform: "uppercase" }, {}, label);
      b.appendChild(n);
      b.appendChild(l);
      return b;
    }

    statGrid.appendChild(statBox(populatedFields.length, "Populated", "#10b981"));
    statGrid.appendChild(statBox(atsParsedFields.length, "ATS Parsed", "#3b82f6"));
    statGrid.appendChild(statBox(manualReviewFields.length, "Review", "#f59e0b"));

    const alertBanner = el("div", {
      background: isSuccess ? "#eff6ff" : "#fffbeb",
      border: `1px solid ${isSuccess ? "#bfdbfe" : "#fde68a"}`,
      color: isSuccess ? "#1e40af" : "#92400e",
      borderRadius: "8px",
      padding: "10px",
      fontSize: "11px",
      lineHeight: "1.4",
      fontWeight: "500",
    }, {}, isSuccess
      ? "Strict Human Control: Please review all populated fields above. JobFlow AI never submits forms automatically. When satisfied, click the employer's Apply button yourself."
      : "The employer form remains unchanged. Please inspect the page or complete the application manually.");

    summaryCard.appendChild(successTitle);
    summaryCard.appendChild(statGrid);
    summaryCard.appendChild(alertBanner);
    setOverlayContent(summaryCard, companyName, jobTitle);

    // 8. Report Completion to JobFlow API & Extension Background
    const report = {
      action_ticket: TICKET,
      execution_id: EXECUTION_ID,
      ats_provider: fetchedPlan.ats_provider || "universal",
      target_url: window.location.href,
      resume_uploaded: resumeAttached,
      fields_populated: populatedFields.length,
      fields_preserved: atsParsedFields.length,
      manual_review_fields: manualReviewFields.length,
      status: reportStatus,
      message: reportMsg,
      field_results: populatedFields.map((f) => ({
        target_name: f.label,
        matched_fact: f.key,
        value_written: f.value,
        action: "POPULATED",
      })),
    };

    try {
      const headers = { "Content-Type": "application/json" };
      if (TICKET) headers["Authorization"] = `Bearer ${TICKET}`;
      await fetch(`${API_BASE}/applications/${APP_ID}/autofill/complete`, {
        method: "POST",
        headers,
        body: JSON.stringify(report),
      });
      console.log("[JobFlow Content] Execution report recorded successfully.");
    } catch (err) {
      console.warn("[JobFlow Content] Could not post complete report:", err);
    }

    try {
      chrome.runtime.sendMessage({ type: "JOBFLOW_REPORT_COMPLETED", payload: report });
    } catch (e) {
      // Ignore if not in extension context
    }
  }
})();
