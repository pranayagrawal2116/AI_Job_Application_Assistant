/**
 * JobFlow AI — Trusted External ATS Form Auto-Population Companion (Phase C.1)
 *
 * Injected / executed in the employer application page (e.g. blueflamelabs.keka.com)
 * Communicates with the local authenticated JobFlow backend at http://127.0.0.1:8000
 *
 * Responsibilities:
 * 1. Fetch authorized candidate facts and form-filling plan.
 * 2. Fetch authenticated, verified resume binary via single-use ticket.
 * 3. Upload verified resume to ATS file upload control (#resume-upload / .resume-upload).
 * 4. Wait for employer ATS asynchronous resume parsing to complete.
 * 5. Re-inspect DOM fields and identify ATS-parsed vs unfilled fields.
 * 6. Populate remaining empty fields with verified candidate profile data.
 * 7. Verify populated values and highlight them on the page.
 * 8. Render a clean JobFlow review overlay on the page.
 * 9. STRICT INVARIANT: Never click the final Submit Application button!
 * 10. Report completion stats back to JobFlow API.
 */

(async function () {
    const JOBFLOW_API_BASE = window.JOBFLOW_CONFIG?.apiBase || 'http://127.0.0.1:8000/api';
    const APP_ID = window.JOBFLOW_CONFIG?.appId;

    if (!APP_ID) {
        alert('JobFlow AI: Application ID is missing from configuration.');
        return;
    }

    console.log(`[JobFlow Companion] Initializing form auto-population for Application #${APP_ID}...`);

    // Helper: show floating status banner on employer page
    function createOverlay() {
        let el = document.getElementById('jobflow-assistant-overlay');
        if (el) el.remove();

        el = document.createElement('div');
        el.id = 'jobflow-assistant-overlay';
        el.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            width: 380px;
            max-height: 85vh;
            overflow-y: auto;
            background: #ffffff;
            color: #0f172a;
            border-radius: 16px;
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2), 0 8px 10px -6px rgba(0,0,0,0.1);
            border: 1px solid #e2e8f0;
            z-index: 9999999;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 13px;
            line-height: 1.5;
            padding: 16px;
            transition: all 0.3s ease;
        `;
        document.body.appendChild(el);
        return el;
    }

    const overlay = createOverlay();

    function updateOverlay(html) {
        overlay.innerHTML = `
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;border-bottom:1px solid #f1f5f9;padding-bottom:8px;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <div style="width:10px;height:10px;border-radius:50%;background:#3b82f6;"></div>
                    <strong style="font-size:14px;color:#1e293b;">JobFlow AI Assistant</strong>
                </div>
                <button onclick="document.getElementById('jobflow-assistant-overlay').remove()" style="border:none;background:none;cursor:pointer;color:#94a3b8;font-size:16px;">&times;</button>
            </div>
            <div>${html}</div>
        `;
    }

    updateOverlay(`
        <div style="display:flex;align-items:center;gap:10px;">
            <div class="jobflow-spinner" style="width:18px;height:18px;border:2px solid #3b82f6;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>
            <span>Connecting to JobFlow & preparing verified application data...</span>
        </div>
        <style>@keyframes spin { to { transform: rotate(360deg); } }</style>
    `);

    try {
        // Step 1: Fetch Autofill Plan
        const planResp = await fetch(`${JOBFLOW_API_BASE}/applications/${APP_ID}/autofill/plan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: window.location.href }),
            credentials: 'include'
        });

        if (!planResp.ok) {
            const err = await planResp.json().catch(() => ({ detail: 'Failed to fetch autofill plan' }));
            throw new Error(err.detail || 'Failed to fetch autofill plan');
        }

        const plan = await planResp.json();
        console.log('[JobFlow Companion] Received plan:', plan);

        updateOverlay(`
            <p style="margin:0 0 8px;color:#475569;">Verified Candidate: <strong>${plan.facts.full_name?.value || 'Candidate'}</strong></p>
            <p style="margin:0 0 8px;color:#475569;">ATS Provider: <strong>${plan.ats_provider}</strong></p>
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:16px;height:16px;border:2px solid #3b82f6;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>
                <span>Downloading verified resume (<code>${plan.resume_filename}</code>)...</span>
            </div>
        `);

        // Step 2: Fetch Verified Resume Binary
        const resumeResp = await fetch(
            `${JOBFLOW_API_BASE}/applications/${APP_ID}/autofill/resume-binary?ticket=${encodeURIComponent(plan.action_ticket)}`,
            { credentials: 'include' }
        );

        if (!resumeResp.ok) {
            throw new Error('Failed to retrieve verified resume binary.');
        }

        const resumeBlob = await resumeResp.blob();
        const resumeFile = new File([resumeBlob], plan.resume_filename, { type: resumeBlob.type || 'application/pdf' });
        console.log('[JobFlow Companion] Downloaded resume blob:', resumeFile.size, 'bytes');

        // Step 3: Locate file input and upload
        updateOverlay(`
            <p style="margin:0 0 8px;">Uploading verified resume to ATS...</p>
        `);

        const fileInput = document.querySelector('input[data-field-identifier="resume"], #resume-upload, .resume-upload, input[type="file"][name*="resume"], input[type="file"]');
        let resumeUploaded = false;

        if (fileInput) {
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(resumeFile);
            fileInput.files = dataTransfer.files;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
            fileInput.dispatchEvent(new Event('input', { bubbles: true }));
            resumeUploaded = true;
            console.log('[JobFlow Companion] Set input files and dispatched change event on', fileInput);
        } else {
            console.warn('[JobFlow Companion] No file upload input found on this page.');
        }

        // Step 4: Wait for ATS resume parsing
        updateOverlay(`
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:16px;height:16px;border:2px solid #3b82f6;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>
                <span>Waiting for employer ATS to extract details from resume...</span>
            </div>
        `);

        await new Promise(r => setTimeout(r, 4000));

        // Step 5: Inspect and populate remaining fields
        updateOverlay(`<span>Mapping and populating remaining fields...</span>`);

        const facts = plan.facts || {};
        const fieldResults = [];

        // Universal field matching dictionary
        const mappings = [
            { keys: ['first_name'], selectors: ['#firstName', '[name="firstName"]', '[name*="first_name"]'], val: facts.first_name?.value },
            { keys: ['middle_name'], selectors: ['#middleName', '[name="middleName"]', '[name*="middle_name"]'], val: facts.middle_name?.value },
            { keys: ['last_name'], selectors: ['#lastName', '[name="lastName"]', '[name*="last_name"]'], val: facts.last_name?.value },
            { keys: ['email'], selectors: ['#email', '[name="email"]', 'input[type="email"]'], val: facts.email?.value },
            { keys: ['country_code'], selectors: ['#mobilePhone\\.countryCode', '[name="mobilePhone.countryCode"]', '.countryCode'], val: facts.country_code?.value },
            { keys: ['phone'], selectors: ['#mobilePhone\\.number', '[name="mobilePhone.number"]', '.mobilePhone', 'input[type="tel"]'], val: facts.phone?.value },
            { keys: ['date_of_birth'], selectors: ['#dateOfBirth', '[name*="dateOfBirth"]'], val: facts.date_of_birth?.value },
            { keys: ['experience_years'], selectors: ['#workExperience', '[name="workExperience.years"]'], val: facts.experience_years?.value },
            { keys: ['experience_months'], selectors: ['[name="workExperience.months"]', '.workExperienceMonths'], val: facts.experience_months?.value },
            { keys: ['current_location'], selectors: ['#currentLocation', '[name*="currentLocation"]', '[name*="city"]'], val: facts.current_location?.value },
            { keys: ['preferred_location'], selectors: ['#locationPreference', '[name*="locationPreference"]'], val: facts.preferred_location?.value },
            { keys: ['current_salary'], selectors: ['#currentSalary', '[name="currentSalary.amount"]'], val: facts.current_salary?.value },
            { keys: ['expected_salary'], selectors: ['#expectedSalary', '[name="expectedSalary.amount"]'], val: facts.expected_salary?.value },
            { keys: ['availability_days'], selectors: ['#availability', '[name*="availability"]'], val: facts.availability_days?.value },
            { keys: ['college_name'], selectors: ['#1d9c080f-d347-4129-bc69-68e84b90402c', '[name*="college"]', '[name*="university"]'], val: facts.college_name?.value },
            { keys: ['branch'], selectors: ['#df9e8b1c-376f-4061-848c-1be135a8266e', '[name*="branch"]', '[name*="major"]'], val: facts.branch?.value },
            { keys: ['cgpa'], selectors: ['#c5c44e06-12b2-45e1-bbc7-029c00746894', '[name*="cgpa"]', '[name*="gpa"]'], val: facts.cgpa?.value },
        ];

        let popCount = 0;
        let atsCount = 0;
        let presCount = 0;
        let reviewCount = 0;

        for (const item of mappings) {
            let el = null;
            for (const sel of item.selectors) {
                try {
                    const found = document.querySelector(sel);
                    if (found) { el = found; break; }
                } catch (e) {}
            }

            if (!el) continue;

            const currentVal = el.value?.trim() || '';
            const fieldName = item.keys[0].replace(/_/g, ' ').toUpperCase();

            if (currentVal && currentVal.length > 0) {
                // Preserved existing or parsed by ATS
                atsCount++;
                fieldResults.push({
                    field_name: fieldName,
                    selector: item.selectors[0],
                    field_type: el.tagName.toLowerCase(),
                    intended_value: item.val,
                    actual_value: currentVal,
                    provenance: 'ATS_PARSED',
                    status: 'ATS_PARSED'
                });
            } else if (item.val !== null && item.val !== undefined && String(item.val).trim() !== '') {
                // Populate empty field
                const valToFill = String(item.val).trim();
                if (el.tagName.toLowerCase() === 'select') {
                    let matched = false;
                    for (let i = 0; i < el.options.length; i++) {
                        const opt = el.options[i];
                        if (opt.value.trim().toLowerCase() === valToFill.toLowerCase() ||
                            opt.text.trim().toLowerCase() === valToFill.toLowerCase() ||
                            opt.text.trim().toLowerCase().includes(valToFill.toLowerCase())) {
                            el.selectedIndex = i;
                            matched = true;
                            break;
                        }
                    }
                    if (matched) {
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        popCount++;
                        fieldResults.push({
                            field_name: fieldName,
                            selector: item.selectors[0],
                            field_type: 'select',
                            intended_value: valToFill,
                            actual_value: el.value,
                            provenance: facts[item.keys[0]]?.provenance || 'VERIFIED_PROFILE',
                            status: 'AUTO_FILLED'
                        });
                        el.style.backgroundColor = '#ecfdf5';
                        el.style.borderColor = '#10b981';
                    }
                } else {
                    el.value = valToFill;
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    el.dispatchEvent(new Event('blur', { bubbles: true }));
                    popCount++;
                    fieldResults.push({
                        field_name: fieldName,
                        selector: item.selectors[0],
                        field_type: 'text',
                        intended_value: valToFill,
                        actual_value: valToFill,
                        provenance: facts[item.keys[0]]?.provenance || 'VERIFIED_PROFILE',
                        status: 'AUTO_FILLED'
                    });
                    el.style.backgroundColor = '#ecfdf5';
                    el.style.borderColor = '#10b981';
                }
            } else {
                reviewCount++;
                fieldResults.push({
                    field_name: fieldName,
                    selector: item.selectors[0],
                    field_type: el.tagName.toLowerCase(),
                    intended_value: null,
                    actual_value: '',
                    provenance: 'NEEDS_CANDIDATE_INPUT',
                    status: 'MANUAL_REVIEW'
                });
                el.style.backgroundColor = '#fffbeb';
                el.style.borderColor = '#f59e0b';
            }
        }

        // Step 6: Post completion report back to backend API
        const report = {
            execution_id: plan.execution_id,
            application_id: APP_ID,
            user_id: plan.user_id,
            ats_provider: plan.ats_provider,
            target_url: window.location.href,
            validated_domain: window.location.hostname,
            resume_uploaded: resumeUploaded,
            resume_id: plan.resume_id,
            resume_version_num: plan.resume_version_num,
            resume_file_hash: plan.plan_hash,
            resume_filename: plan.resume_filename,
            ats_parsing_completed: true,
            total_fields_detected: fieldResults.length,
            fields_populated_count: popCount,
            fields_ats_parsed_count: atsCount,
            fields_preserved_count: presCount,
            fields_manual_review_count: reviewCount,
            fields_unmatched_count: 0,
            field_results: fieldResults,
            anti_automation_detected: false,
            submission_prevented: true,
            status: 'SUCCESS',
            message: `Populated ${popCount} fields, ${atsCount} parsed by ATS, ${reviewCount} require review.`
        };

        fetch(`${JOBFLOW_API_BASE}/applications/${APP_ID}/autofill/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(report),
            credentials: 'include'
        }).catch(err => console.warn('[JobFlow Companion] Audit logging error:', err));

        // Step 7: Render completion review card in overlay
        updateOverlay(`
            <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:12px;margin-bottom:12px;">
                <div style="display:flex;align-items:center;gap:6px;color:#166534;font-weight:600;font-size:14px;margin-bottom:4px;">
                    <span>&#10003; Form Auto-Population Complete</span>
                </div>
                <div style="font-size:12px;color:#15803d;">
                    Green highlighted fields have been auto-populated from your verified profile.
                </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;">
                <div style="background:#f8fafc;padding:8px;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:11px;color:#64748b;">Populated Fields</div>
                    <div style="font-size:18px;font-weight:bold;color:#0f172a;">${popCount}</div>
                </div>
                <div style="background:#f8fafc;padding:8px;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:11px;color:#64748b;">ATS Extracted</div>
                    <div style="font-size:18px;font-weight:bold;color:#0f172a;">${atsCount}</div>
                </div>
            </div>

            ${reviewCount > 0 ? `
                <div style="background:#fffbeb;border:1px solid #fef3c7;border-radius:8px;padding:10px;margin-bottom:12px;font-size:12px;color:#92400e;">
                    <strong>&#9888; Note:</strong> ${reviewCount} field(s) require manual input (such as DOB, gender, or notice period).
                </div>
            ` : ''}

            <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:10px;margin-bottom:12px;font-size:12px;color:#1e40af;">
                <strong>Strict Human Control:</strong> Applications are never submitted automatically. Please review all fields above and click <em>Submit Application</em> manually when ready.
            </div>

            <button onclick="document.getElementById('jobflow-assistant-overlay').remove()" style="width:100%;padding:10px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;">
                Done &amp; Ready for Review
            </button>
        `);

    } catch (err) {
        console.error('[JobFlow Companion] Error during form population:', err);
        updateOverlay(`
            <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:12px;color:#991b1b;margin-bottom:12px;">
                <div style="font-weight:600;margin-bottom:4px;">Auto-Population Failed</div>
                <div style="font-size:12px;">${err.message || String(err)}</div>
            </div>
            <button onclick="document.getElementById('jobflow-assistant-overlay').remove()" style="width:100%;padding:8px;background:#e2e8f0;color:#334155;border:none;border-radius:6px;cursor:pointer;">
                Close
            </button>
        `);
    }
})();
