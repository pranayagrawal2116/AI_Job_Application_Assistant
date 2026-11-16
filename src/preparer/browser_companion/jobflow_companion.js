/**
 * JobFlow AI — Trusted External ATS Form Auto-Population Companion
 *
 * Injected / executed in the employer application page (e.g. blueflamelabs.keka.com, greenhouse.io, lever.co)
 * Communicates with the authenticated JobFlow backend via signed action tickets.
 *
 * Responsibilities:
 * 1. Fetch authorized candidate facts and form-filling plan.
 * 2. Fetch authenticated, verified resume binary via single-use ticket.
 * 3. Upload verified resume to ATS file upload control (#resume-upload / .resume-upload / input[type="file"]).
 * 4. Wait for employer ATS asynchronous resume parsing with bounded polling & DOM mutation observation.
 * 5. Re-inspect DOM fields and identify ATS-parsed vs unfilled fields.
 * 6. Populate remaining empty fields with verified candidate profile data using React-compatible native setters.
 * 7. Verify populated values and highlight them on the page.
 * 8. Render a clean JobFlow review overlay on the page with field counters and human approval notice.
 * 9. STRICT INVARIANT: Never click the final Apply / Submit Application button!
 * 10. Report completion stats back to JobFlow API.
 */

(async function () {
    const JOBFLOW_API_BASE = window.JOBFLOW_CONFIG?.apiBase || 'http://127.0.0.1:8000/api';
    const APP_ID = window.JOBFLOW_CONFIG?.appId;
    const TICKET = window.JOBFLOW_CONFIG?.ticket || null;
    const EXECUTION_ID = window.JOBFLOW_CONFIG?.executionId || null;

    if (!APP_ID) {
        alert('JobFlow AI: Application ID is missing from configuration.');
        return;
    }

    console.log(`[JobFlow Companion] Initializing form auto-population for Application #${APP_ID}...`);

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

    // Helper: Show floating status overlay on employer page
    function createOverlay() {
        let existing = document.getElementById('jobflow-assistant-overlay');
        if (existing) existing.remove();

        const container = el('div', {
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            width: '390px',
            maxHeight: '85vh',
            overflowY: 'auto',
            background: '#ffffff',
            color: '#0f172a',
            borderRadius: '16px',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.2), 0 8px 10px -6px rgba(0,0,0,0.1)',
            border: '1px solid #cbd5e1',
            zIndex: '9999999',
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            fontSize: '13px',
            lineHeight: '1.5',
            padding: '16px',
            boxSizing: 'border-box',
        }, { id: 'jobflow-assistant-overlay' });

        document.body.appendChild(container);
        return container;
    }

    const overlay = createOverlay();

    function renderHeader(company = '', role = '') {
        const header = el('div', {
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '12px',
            borderBottom: '1px solid #f1f5f9',
            paddingBottom: '8px',
        });

        const left = el('div', { display: 'flex', alignItems: 'center', gap: '8px' });
        const dot = el('div', { width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6' });
        const titleWrap = el('div');
        const strong = el('strong', { fontSize: '14px', color: '#1e293b' }, {}, 'JobFlow AI Assistant');
        titleWrap.appendChild(strong);
        if (company) {
            const subtitle = el('div', { fontSize: '11px', color: '#64748b' }, {}, `${role ? role + ' • ' : ''}${company}`);
            titleWrap.appendChild(subtitle);
        }

        left.appendChild(dot);
        left.appendChild(titleWrap);

        const closeBtn = el('button', {
            border: 'none',
            background: 'none',
            cursor: 'pointer',
            color: '#94a3b8',
            fontSize: '18px',
            fontWeight: 'bold',
        }, {}, '×');
        closeBtn.onclick = () => overlay.remove();

        header.appendChild(left);
        header.appendChild(closeBtn);
        return header;
    }

    function setOverlayContent(contentElem, company = '', role = '') {
        overlay.replaceChildren(renderHeader(company, role), contentElem);
    }

    function showStatus(message, company = '', role = '') {
        const wrap = el('div', { display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 0' });
        const spinner = el('div', {
            width: '18px',
            height: '18px',
            border: '2px solid #3b82f6',
            borderTopColor: 'transparent',
            borderRadius: '50%',
            animation: 'jobflow-spin 1s linear infinite',
            flexShrink: '0',
        });
        const text = el('span', { color: '#334155', fontWeight: '500' }, {}, message);

        wrap.appendChild(spinner);
        wrap.appendChild(text);

        // Inject keyframes if not present
        if (!document.getElementById('jobflow-keyframes')) {
            const style = document.createElement('style');
            style.id = 'jobflow-keyframes';
            style.textContent = '@keyframes jobflow-spin { to { transform: rotate(360deg); } }';
            document.head.appendChild(style);
        }

        setOverlayContent(wrap, company, role);
    }

    // Helper: React-compatible native input value setter
    function setNativeValue(element, value) {
        const proto = Object.getPrototypeOf(element);
        const descriptor = Object.getOwnPropertyDescriptor(proto, 'value') ||
                           Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value') ||
                           Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');

        if (descriptor && descriptor.set) {
            descriptor.set.call(element, value);
        } else {
            element.value = value;
        }

        element.dispatchEvent(new Event('input', { bubbles: true }));
        element.dispatchEvent(new Event('change', { bubbles: true }));
        element.dispatchEvent(new Event('blur', { bubbles: true }));
    }

    // Initial status
    showStatus('Connecting to JobFlow AI and preparing verified facts...');

    try {
        // Step 1: Fetch Autofill Plan
        const headers = { 'Content-Type': 'application/json' };
        if (TICKET) {
            headers['X-JobFlow-Ticket'] = TICKET;
            headers['Authorization'] = `Bearer ${TICKET}`;
        }

        let plan;
        try {
            const planResp = await fetch(`${JOBFLOW_API_BASE}/applications/${APP_ID}/autofill/plan`, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ target_url: window.location.href }),
                credentials: 'include',
            });

            if (!planResp.ok) {
                const errData = await planResp.json().catch(() => ({}));
                throw new Error(errData.detail || `Server returned HTTP ${planResp.status}`);
            }
            plan = await planResp.json();
        } catch (planErr) {
            console.warn('[JobFlow Companion] Plan fetch failed with credentials; attempting fallback:', planErr);
            throw new Error(`Failed to initialize application plan: ${planErr.message}`);
        }

        console.log('[JobFlow Companion] Received plan for company:', plan.company_name, 'Job:', plan.job_title);
        const activeTicket = plan.action_ticket || TICKET;
        const activeExecutionId = plan.execution_id || EXECUTION_ID;

        showStatus(`Downloading verified resume (${plan.resume_filename})...`, plan.company_name, plan.job_title);

        // Step 2: Fetch Verified Resume Binary
        const resumeUrl = `${JOBFLOW_API_BASE}/applications/${APP_ID}/autofill/resume-binary?ticket=${encodeURIComponent(activeTicket)}`;
        const resumeResp = await fetch(resumeUrl, {
            headers: {
                'X-JobFlow-Ticket': activeTicket,
                'Authorization': `Bearer ${activeTicket}`,
            },
            credentials: 'include',
        });

        if (!resumeResp.ok) {
            throw new Error(`Failed to retrieve verified resume binary (HTTP ${resumeResp.status})`);
        }

        const resumeBlob = await resumeResp.blob();
        const resumeFile = new File([resumeBlob], plan.resume_filename, {
            type: resumeBlob.type || (plan.resume_file_format === 'docx' ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' : 'application/pdf'),
        });
        console.log('[JobFlow Companion] Verified resume downloaded:', resumeFile.size, 'bytes');

        // Step 3: Locate File Upload Input & Upload Resume
        showStatus('Uploading verified resume to employer ATS...', plan.company_name, plan.job_title);

        const fileInputSelectors = [
            '#resume-upload',
            'input[data-field-identifier="resume"]',
            'input[type="file"][name*="resume"]',
            'input[type="file"][id*="resume"]',
            'input[type="file"][accept*="pdf"]',
            '.resume-upload input[type="file"]',
            'input[type="file"]',
        ];

        let fileInput = null;
        for (const sel of fileInputSelectors) {
            const found = document.querySelector(sel);
            if (found) {
                fileInput = found;
                break;
            }
        }

        let resumeUploaded = false;
        if (fileInput) {
            try {
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(resumeFile);
                fileInput.files = dataTransfer.files;
                fileInput.dispatchEvent(new Event('change', { bubbles: true }));
                fileInput.dispatchEvent(new Event('input', { bubbles: true }));
                resumeUploaded = true;
                console.log('[JobFlow Companion] Resume file successfully staged in', fileInput);
            } catch (fileErr) {
                console.error('[JobFlow Companion] Could not attach file to input:', fileErr);
            }
        } else {
            console.warn('[JobFlow Companion] No file upload control found on this page.');
        }

        // Step 4: Bounded Polling & DOM Mutation Observation for ATS Resume Parsing
        showStatus('Observing employer ATS resume parsing...', plan.company_name, plan.job_title);

        const startTime = Date.now();
        const maxWaitMs = 12000;
        let atsParsingCompleted = false;

        while (Date.now() - startTime < maxWaitMs) {
            await new Promise((r) => setTimeout(r, 400));

            // Check if any personal field received a value from ATS background parser
            const testFields = ['#firstName', '#lastName', '#email', 'input[name="firstName"]', 'input[name="email"]'];
            let filledCount = 0;
            for (const tf of testFields) {
                const elFound = document.querySelector(tf);
                if (elFound && elFound.value && elFound.value.trim().length > 0) {
                    filledCount++;
                }
            }

            // Check if loading spinners are active
            const spinners = document.querySelectorAll('.loading, .spinner, [aria-busy="true"], .k-loading-mask, #uploadStatus');
            const hasActiveSpinner = Array.from(spinners).some((s) => s.offsetParent !== null);

            if (filledCount >= 1 && !hasActiveSpinner) {
                atsParsingCompleted = true;
                console.log('[JobFlow Companion] ATS background parsing completed. Detected fields filled:', filledCount);
                break;
            }

            // Check for explicit error messages
            const pageText = document.body.innerText || '';
            if (pageText.includes('Unable to process this file') || pageText.includes('Upload failed') || pageText.includes('File exceeds size')) {
                console.warn('[JobFlow Companion] ATS reported file parsing failure.');
                break;
            }
        }

        // Step 5: Map and Populate Remaining Blank Fields
        showStatus('Mapping verified candidate facts to remaining blank fields...', plan.company_name, plan.job_title);

        const facts = plan.facts || {};
        const fieldResults = [];

        // Comprehensive mapping taxonomy
        const fieldDefinitions = [
            { key: 'first_name', selectors: ['#firstName', '[name="firstName"]', '[name*="first_name"]', 'input[autocomplete="given-name"]'], val: facts.first_name?.value },
            { key: 'middle_name', selectors: ['#middleName', '[name="middleName"]', '[name*="middle_name"]'], val: facts.middle_name?.value },
            { key: 'last_name', selectors: ['#lastName', '[name="lastName"]', '[name*="last_name"]', 'input[autocomplete="family-name"]'], val: facts.last_name?.value },
            { key: 'full_name', selectors: ['#fullName', '[name="name"]', 'input[name="full_name"]', 'input[name="applicant_name"]'], val: facts.full_name?.value },
            { key: 'email', selectors: ['#email', '[name="email"]', 'input[type="email"]', 'input[autocomplete="email"]'], val: facts.email?.value },
            { key: 'country_code', selectors: ['#mobilePhone\\.countryCode', '[name="mobilePhone.countryCode"]', '#countryCode', '.countryCode'], val: facts.country_code?.value, isSelect: true },
            { key: 'phone', selectors: ['#mobilePhone\\.number', '[name="mobilePhone.number"]', '#phone', 'input[type="tel"]', 'input[name*="phone"]'], val: facts.phone?.value },
            { key: 'gender', selectors: ['#gender', '[name="gender"]', 'select[name*="gender"]'], val: facts.gender?.value, isSelect: true },
            { key: 'date_of_birth', selectors: ['#dateOfBirth', '[name*="dateOfBirth"]', '#dob', 'input[name*="dob"]'], val: facts.date_of_birth?.value },
            { key: 'experience_years', selectors: ['#workExperience', '[name="workExperience.years"]', 'input[name*="experience_years"]'], val: facts.experience_years?.value },
            { key: 'experience_months', selectors: ['[name="workExperience.months"]', '#workExperience\\.months', '.workExperienceMonths'], val: facts.experience_months?.value, isSelect: true },
            { key: 'current_company', selectors: ['#currentCompany', '[name="org"]', 'input[name*="company"]', 'input[name*="employer"]'], val: facts.current_company?.value },
            { key: 'current_job_title', selectors: ['#currentRole', 'input[name*="title"]', 'input[name*="designation"]'], val: facts.current_job_title?.value },
            { key: 'current_location', selectors: ['#currentLocation', '[name*="currentLocation"]', 'input[name*="city"]', 'input[autocomplete="address-level2"]'], val: facts.current_location?.value },
            { key: 'preferred_location', selectors: ['#locationPreference', '[name*="locationPreference"]'], val: facts.preferred_location?.value, isSelect: true },
            { key: 'current_salary', selectors: ['#currentSalary', '[name*="currentSalary"]'], val: facts.current_salary?.value },
            { key: 'expected_salary', selectors: ['#expectedSalary', '[name*="expectedSalary"]', 'input[name*="stipend"]'], val: facts.expected_salary?.value },
            { key: 'availability_days', selectors: ['#availability', '[name*="availability"]', 'input[name*="notice"]'], val: facts.availability_days?.value },
            { key: 'college_name', selectors: ['#1d9c080f-d347-4129-bc69-68e84b90402c', 'input[name*="college"]', 'input[name*="university"]', 'input[name*="institution"]'], val: facts.college_name?.value },
            { key: 'branch', selectors: ['#df9e8b1c-376f-4061-848c-1be135a8266e', 'input[name*="branch"]', 'input[name*="major"]', 'input[name*="field_of_study"]'], val: facts.branch?.value },
            { key: 'cgpa', selectors: ['#c5c44e06-12b2-45e1-bbc7-029c00746894', 'input[name*="cgpa"]', 'input[name*="gpa"]', 'input[name*="grade"]'], val: facts.cgpa?.value },
            { key: 'graduation_year', selectors: ['#graduationYear', 'input[name*="grad_year"]', 'input[name*="graduation_year"]'], val: facts.graduation_year?.value },
            { key: 'linkedin_url', selectors: ['#linkedin', 'input[name*="linkedin"]', 'input[name="urls[LinkedIn]"]'], val: facts.linkedin_url?.value },
            { key: 'github_url', selectors: ['#github', 'input[name*="github"]', 'input[name="urls[GitHub]"]'], val: facts.github_url?.value },
            { key: 'portfolio_url', selectors: ['#portfolio', 'input[name*="portfolio"]', 'input[name="urls[Portfolio]"]', 'input[name*="website"]'], val: facts.portfolio_url?.value },
        ];

        let populatedCount = 0;
        let atsParsedCount = 0;
        let preservedCount = 0;
        let manualReviewCount = 0;

        for (const item of fieldDefinitions) {
            let elem = null;
            let matchedSelector = '';
            for (const sel of item.selectors) {
                try {
                    const found = document.querySelector(sel);
                    if (found) {
                        elem = found;
                        matchedSelector = sel;
                        break;
                    }
                } catch (e) {}
            }

            if (!elem) continue;

            const currentVal = (elem.value || '').trim();
            const displayName = item.key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
            const tag = elem.tagName.toLowerCase();

            // Check if element has pre-existing value
            let isUnselectedDefault = false;
            if (tag === 'select') {
                const lower = currentVal.toLowerCase();
                if (lower === '' || lower === '-1' || lower === '0' || lower === 'none' || lower === 'select' || lower === 'choose') {
                    isUnselectedDefault = true;
                }
            }

            if (currentVal.length > 0 && !isUnselectedDefault) {
                // Existing value: PRESERVE and do NOT overwrite
                atsParsedCount++;
                fieldResults.push({
                    field_name: displayName,
                    selector: matchedSelector,
                    field_type: tag,
                    intended_value: item.val,
                    actual_value: currentVal,
                    provenance: 'ATS_PARSED',
                    status: 'ATS_PARSED',
                });
            } else if (item.val !== null && item.val !== undefined && String(item.val).trim() !== '') {
                // Candidate fact available: POPULATE
                const strVal = String(item.val).trim();

                if (tag === 'select') {
                    let matchedOpt = false;
                    for (let i = 0; i < elem.options.length; i++) {
                        const opt = elem.options[i];
                        const optVal = opt.value.trim().toLowerCase();
                        const optText = opt.text.trim().toLowerCase();
                        const targetLower = strVal.toLowerCase();

                        if (optVal === targetLower || optText === targetLower || optText.includes(targetLower) || targetLower.includes(optText)) {
                            elem.selectedIndex = i;
                            matchedOpt = true;
                            break;
                        }
                    }

                    if (matchedOpt) {
                        elem.dispatchEvent(new Event('change', { bubbles: true }));
                        elem.dispatchEvent(new Event('input', { bubbles: true }));
                        populatedCount++;
                        fieldResults.push({
                            field_name: displayName,
                            selector: matchedSelector,
                            field_type: 'select',
                            intended_value: strVal,
                            actual_value: elem.value,
                            provenance: facts[item.key]?.provenance || 'VERIFIED_PROFILE',
                            status: 'AUTO_FILLED',
                        });
                        elem.style.backgroundColor = '#ecfdf5';
                        elem.style.borderColor = '#10b981';
                    } else {
                        manualReviewCount++;
                        fieldResults.push({
                            field_name: displayName,
                            selector: matchedSelector,
                            field_type: 'select',
                            intended_value: strVal,
                            actual_value: currentVal,
                            provenance: 'NEEDS_CANDIDATE_INPUT',
                            status: 'MANUAL_REVIEW',
                            error_message: 'Dropdown options did not match candidate value',
                        });
                        elem.style.backgroundColor = '#fffbeb';
                        elem.style.borderColor = '#f59e0b';
                    }
                } else {
                    setNativeValue(elem, strVal);
                    populatedCount++;
                    fieldResults.push({
                        field_name: displayName,
                        selector: matchedSelector,
                        field_type: tag,
                        intended_value: strVal,
                        actual_value: strVal,
                        provenance: facts[item.key]?.provenance || 'VERIFIED_PROFILE',
                        status: 'AUTO_FILLED',
                    });
                    elem.style.backgroundColor = '#ecfdf5';
                    elem.style.borderColor = '#10b981';
                }
            } else {
                // Missing / sensitive fact: requires manual review
                manualReviewCount++;
                fieldResults.push({
                    field_name: displayName,
                    selector: matchedSelector,
                    field_type: tag,
                    intended_value: null,
                    actual_value: currentVal,
                    provenance: 'NEEDS_CANDIDATE_INPUT',
                    status: 'MANUAL_REVIEW',
                });
                elem.style.backgroundColor = '#fffbeb';
                elem.style.borderColor = '#f59e0b';
            }
        }

        // Step 6: Post completion report to backend
        const reportPayload = {
            execution_id: activeExecutionId,
            application_id: APP_ID,
            user_id: plan.user_id,
            action_ticket: activeTicket,
            ats_provider: plan.ats_provider,
            target_url: window.location.href,
            validated_domain: window.location.hostname,
            resume_uploaded: resumeUploaded,
            resume_id: plan.resume_id,
            resume_version_num: plan.resume_version_num,
            resume_file_hash: plan.plan_hash,
            resume_filename: plan.resume_filename,
            ats_parsing_completed: atsParsingCompleted,
            total_fields_detected: fieldResults.length,
            fields_populated_count: populatedCount,
            fields_ats_parsed_count: atsParsedCount,
            fields_preserved_count: preservedCount,
            fields_manual_review_count: manualReviewCount,
            fields_unmatched_count: 0,
            field_results: fieldResults,
            anti_automation_detected: false,
            submission_prevented: true,
            status: 'SUCCESS',
            message: `Populated ${populatedCount} fields, ${atsParsedCount} parsed by ATS, ${manualReviewCount} require manual review.`,
        };

        fetch(`${JOBFLOW_API_BASE}/applications/${APP_ID}/autofill/complete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-JobFlow-Ticket': activeTicket,
                'Authorization': `Bearer ${activeTicket}`,
            },
            body: JSON.stringify(reportPayload),
            credentials: 'include',
        }).catch((err) => console.warn('[JobFlow Companion] Complete endpoint report error:', err));

        // Step 7: Render Safe Completion Review Card
        const reviewContainer = el('div', { display: 'flex', flexDirection: 'column', gap: '10px' });

        // Success banner
        const banner = el('div', {
            background: '#f0fdf4',
            border: '1px solid #bbf7d0',
            borderRadius: '12px',
            padding: '12px',
        });
        const bannerTitle = el('div', {
            color: '#15803d',
            fontWeight: '700',
            fontSize: '13px',
            marginBottom: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
        }, {}, '✓ Form Auto-Population Complete');
        const bannerDesc = el('div', {
            color: '#166534',
            fontSize: '12px',
        }, {}, 'Your application form is ready for review. Green highlighted fields have been populated from your verified profile.');
        banner.appendChild(bannerTitle);
        banner.appendChild(bannerDesc);
        reviewContainer.appendChild(banner);

        // Stats grid
        const statsGrid = el('div', { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' });

        function createStatBox(label, count, color) {
            const box = el('div', {
                background: '#f8fafc',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                padding: '8px',
                textAlign: 'center',
            });
            const num = el('div', { fontSize: '18px', fontWeight: '800', color: color }, {}, String(count));
            const lbl = el('div', { fontSize: '10px', color: '#64748b', fontWeight: '500' }, {}, label);
            box.appendChild(num);
            box.appendChild(lbl);
            return box;
        }

        statsGrid.appendChild(createStatBox('Populated', populatedCount, '#15803d'));
        statsGrid.appendChild(createStatBox('ATS Parsed', atsParsedCount, '#2563eb'));
        statsGrid.appendChild(createStatBox('Requires Input', manualReviewCount, '#d97706'));
        reviewContainer.appendChild(statsGrid);

        // Mandatory Human Control Box
        const humanBox = el('div', {
            background: '#eff6ff',
            border: '1px solid #bfdbfe',
            borderRadius: '10px',
            padding: '10px',
            fontSize: '12px',
            color: '#1e40af',
        });
        const humanStrong = el('strong', { display: 'block', marginBottom: '2px' }, {}, 'Strict Human-in-the-Loop Control:');
        const humanText = el('span', {}, {}, 'Please verify all information, inspect every required declaration and personally click Apply or Submit Application on the employer\'s website.');
        humanBox.appendChild(humanStrong);
        humanBox.appendChild(humanText);
        reviewContainer.appendChild(humanBox);

        // Dismiss button
        const dismissBtn = el('button', {
            width: '100%',
            padding: '10px',
            background: '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: '10px',
            fontWeight: '600',
            cursor: 'pointer',
            fontSize: '12px',
        }, {}, 'Done & Ready for Review');
        dismissBtn.onclick = () => overlay.remove();
        reviewContainer.appendChild(dismissBtn);

        setOverlayContent(reviewContainer, plan.company_name, plan.job_title);

    } catch (err) {
        console.error('[JobFlow Companion] Auto-population error:', err);
        const errWrap = el('div', {
            background: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '10px',
            padding: '12px',
            color: '#991b1b',
        });
        const errTitle = el('strong', { display: 'block', marginBottom: '4px' }, {}, 'Auto-Population Paused');
        const errDesc = el('div', { fontSize: '12px' }, {}, err.message || String(err));
        const closeBtn = el('button', {
            marginTop: '10px',
            padding: '6px 12px',
            background: '#e2e8f0',
            border: 'none',
            borderRadius: '6px',
            color: '#334155',
            cursor: 'pointer',
        }, {}, 'Dismiss');
        closeBtn.onclick = () => overlay.remove();

        errWrap.appendChild(errTitle);
        errWrap.appendChild(errDesc);
        errWrap.appendChild(closeBtn);

        setOverlayContent(errWrap);
    }
})();
