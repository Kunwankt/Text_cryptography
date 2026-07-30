(function () {
    'use strict';

    const ATTACK_NAMES = {
        brute_force: 'Brute Force',
        dictionary: 'Dictionary',
        rainbow_table: 'Rainbow Table',
        hybrid: 'Hybrid',
    };

    const ATTACK_ICONS = {
        brute_force: 'fa-terminal',
        dictionary: 'fa-book-open',
        rainbow_table: 'fa-database',
        hybrid: 'fa-gears',
    };

    const SIM_DURATION_MS = 3600; // length of the simulated attack (longer so we can count to 10 lakh smoothly)
    const TYPING_INTERVAL_MS = 10;
    const STATS_REFRESH_INTERVAL_MS = 30000;

    let breakdownChart = null;
    let currentSimToken = 0; // prevents race conditions when re-running quickly
    let statsRefreshTimer = null;
    let progressTimer = null;
    let attemptTimer = null;
    let countdownTimer = null;
    let typingTimers = [];
    // Remember the real attempt count from the last API response so the
    // rolling progress counter can count all the way to 10 lakh instead of
    // stopping at a small synthetic value.
    let pendingAttemptsTarget = 1000000;
    let isAttackRunning = false;

    function clearAllTimers() {
        if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
        if (attemptTimer) { clearInterval(attemptTimer); attemptTimer = null; }
        if (countdownTimer) { clearTimeout(countdownTimer); countdownTimer = null; }
        typingTimers.forEach((t) => clearTimeout(t));
        typingTimers = [];
    }

    function cancelRunningAttack() {
        if (!isAttackRunning) return;
        currentSimToken += 1;
        clearAllTimers();
        isAttackRunning = false;
        setProgress(0);
        const spinner = $('.attackSpinner');
        if (spinner) spinner.classList.add('d-none');
        const idleIcon = $('.attackStatusIconIdle');
        if (idleIcon) idleIcon.classList.remove('d-none');
        const status = $('#attackStatusText');
        if (status) status.textContent = 'Cancelled by user';
        const badge = $('#simModeBadge');
        if (badge) {
            badge.textContent = 'CANCELLED';
            badge.className = 'ms-2 small badge bg-dark border border-danger-subtle text-danger opacity-90';
        }
        toggleCancelButtons(false);
        const startBtn = $('#startAttackBtn');
        if (startBtn) startBtn.disabled = false;
        const startLabel = $('#startBtnLabel');
        if (startLabel) startLabel.textContent = 'START ATTACK';
        appendTerminalLine('<span class="prompt warn">$</span> <span style="color:#f59e0b">!! USER CANCELLED SEARCH — attack aborted before completion</span>');
        resetPipeline();
        activatePipelineStep(2);
        if (typeof showToast === 'function') showToast('Attack cancelled by user.', 'warn');
    }

    function toggleCancelButtons(show) {
        ['#cancelAttackBtn', '#cancelAttackBtnMobile'].forEach((sel) => {
            const el = $(sel);
            if (!el) return;
            if (show) el.classList.remove('d-none');
            else el.classList.add('d-none');
        });
    }

    function appendTerminalLine(htmlLine) {
        const out = $('#terminalOutput');
        if (!out) return;
        out.insertAdjacentHTML('beforeend', '\n' + htmlLine);
        const body = $('#terminalBody');
        if (body) body.scrollTop = body.scrollHeight;
    }

    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

    // --- Hints (Dictionary attack only) ---------------------------------
    const MAX_HINTS = 12;

    function parseHintsInput(raw) {
        if (!raw) return [];
        const seen = new Set();
        const out = [];
        String(raw).split(',').forEach((piece) => {
            let p = piece.trim().replace(/^[.,;:!?"'()[\]{}]+|[.,;:!?"'()[\]{}]+$/g, '');
            if (!p) return;
            p = p.replace(/\s+/g, ' ');
            const key = p.toLowerCase();
            if (seen.has(key) || p.length > 80) return;
            seen.add(key);
            out.push(p);
        });
        return out.slice(0, MAX_HINTS);
    }

    function classifyHint(text) {
        const digits = (text.match(/\d/g) || []).join('');
        const stripped = text.trim();
        if (digits.length >= 6 && stripped.length <= 16) return 'DOB/Date';
        if (stripped.length >= 12 || (stripped.length >= 8 && /\d/.test(stripped))) return 'Addr/Place';
        if (stripped.split(/\s+/).length >= 2) return 'Full Name';
        return 'Name/Word';
    }

    function renderHintsChips(hints, containerId, opts) {
        const container = containerId ? $(containerId) : null;
        if (!container) return;
        container.innerHTML = '';
        if (!hints || !hints.length) return;
        const palette = opts && opts.palette ? opts.palette : true;
        hints.forEach((h, i) => {
            const span = document.createElement('span');
            const idx = palette ? i % 5 : 4;
            const cls = palette ? [
                'bg-primary-subtle border border-primary text-primary-emphasis',
                'bg-success-subtle border border-success text-success-emphasis',
                'bg-info-subtle border border-info text-info-emphasis',
                'bg-warning-subtle border border-warning text-warning-emphasis',
                'bg-danger-subtle border border-danger text-danger-emphasis',
            ][idx] : 'bg-dark border border-secondary text-light';
            span.className = 'badge rounded-pill ' + cls;
            const kind = palette ? (' <span class="opacity-75 fw-normal">[' + classifyHint(h) + ']</span>') : '';
            span.innerHTML = '<i class="fas fa-lightbulb me-1 opacity-75"></i>' + escapeHtml(h) + kind;
            span.title = 'Hint #' + (i + 1) + ' · ' + classifyHint(h);
            container.appendChild(span);
        });
    }

    function syncHintsUi() {
        const hintsInput = $('#hintsInput');
        const wrap = $('#hintsWrap');
        // Empty or hidden input → show 0 count & empty chips.
        if (!wrap || !hintsInput) return;
        const raw = wrap.classList.contains('d-none') ? '' : (hintsInput.value || '');
        const hints = parseHintsInput(raw);

        const count = $('#hintsCount');
        if (count) count.textContent = String(hints.length);
        renderHintsChips(hints, '#hintsChipsWrap', { palette: true });
    }

    function showAttackPanel(attackId, attackName) {
        const panel = $('#simulationCard');
        if (!panel) return;
        panel.style.display = '';
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

        $('#simTitle').textContent = attackName + ' Attack — Simulation Console';
        $('#termAttackLabel').textContent = attackName + ' / ' + attackId;
        $('#attackStatusText').textContent = 'Idle';
        const spinner = $('.attackSpinner');
        if (spinner) spinner.classList.add('d-none');
        const idleIcon = $('.attackStatusIconIdle');
        if (idleIcon) idleIcon.classList.remove('d-none');

        // Reset mode badge to IDLE
        const modeBadge = $('#simModeBadge');
        if (modeBadge) {
            modeBadge.textContent = 'IDLE';
            modeBadge.className = 'ms-2 small badge bg-dark border border-success-subtle text-success opacity-75';
        }

        // Ensure cancel buttons are hidden when panel loads
        toggleCancelButtons(false);

        // Ensure start button is enabled + default label
        const startBtn = $('#startAttackBtn');
        const startLabel = $('#startBtnLabel');
        if (startBtn) startBtn.disabled = false;
        if (startLabel) startLabel.textContent = 'START ATTACK';

        const pwInput = $('#attackPasswordInput');
        if (pwInput) pwInput.dataset.selectedAttack = attackId;
        if (pwInput) pwInput.focus();

        // Hints: ONLY visible for Dictionary attack.
        const hintsWrap = $('#hintsWrap');
        if (hintsWrap) {
            if (attackId === 'dictionary') {
                hintsWrap.classList.remove('d-none');
            } else {
                hintsWrap.classList.add('d-none');
                const inp = $('#hintsInput');
                if (inp) inp.value = '';
            }
            syncHintsUi();
        }

        // Reset terminal / progress
        $('#terminalOutput').innerHTML =
            '<span class="prompt">$</span> ' + attackName + ' module loaded. Enter a password and press Start Attack.';
        $('#terminalBody').scrollTop = $('#terminalBody').scrollHeight;
        setProgress(0);
        $('#attemptCount').textContent = Number(0).toLocaleString('en-IN');

        resetPipeline();
        activatePipelineStep(2); // Attack Selected

        // If a cached last report exists, reveal Report toggle so user can also jump back.
        if (hasLastResult()) {
            const btn = $('#toggleReportBtn');
            if (btn) btn.style.display = '';
        }
    }

    function closeAttackPanel() {
        const panel = $('#simulationCard');
        if (panel) panel.style.display = 'none';
        // NOTE: Do NOT hide the result card here. The report must stay visible so
        // the user can read it after closing the noisy simulator panel. The user
        // can close the report separately via its own Close button.
    }

    function closeResultPanel() {
        const res = $('#resultCard');
        if (res) res.classList.add('d-none');
        // If a result is cached, keep the Report button visible so the user can
        // reopen the report any time.
        if (hasLastResult()) {
            const btn = $('#toggleReportBtn');
            if (btn) btn.style.display = '';
        }
    }

    // ----- Last-result cache (local to the tab) -------------------------
    const LAST_RESULT_KEY = 'attack_sim_last_result';

    function cacheLastResult(result) {
        try {
            sessionStorage.setItem(LAST_RESULT_KEY, JSON.stringify(result));
        } catch (e) {
            /* ignore */
        }
        const btn = $('#toggleReportBtn');
        if (btn) btn.style.display = '';
        const quick = $('#quickReportBtn');
        if (quick) quick.style.display = '';
    }

    function getLastResult() {
        try {
            const raw = sessionStorage.getItem(LAST_RESULT_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function hasLastResult() {
        return !!getLastResult();
    }

    function toggleReport() {
        const res = $('#resultCard');
        if (!res) return;
        if (res.classList.contains('d-none')) {
            const cached = getLastResult();
            if (cached) {
                renderResultCard(cached);
                // renderResultCard removes d-none; if it's a cached report, pipeline step 5 should still be active
                activatePipelineStep(5);
            } else {
                res.classList.remove('d-none');
            }
            res.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
            res.classList.add('d-none');
        }
    }

    function setProgress(pct) {
        pct = Math.max(0, Math.min(100, pct));
        $('#attackProgressBar').style.width = pct + '%';
        $('#progressPct').textContent = String(Math.round(pct));
    }

    function resetPipeline() {
        $$('.pipeline-step').forEach((step) => step.classList.remove('active', 'done'));
    }

    function activatePipelineStep(n) {
        const step = document.querySelector(`.pipeline-step[data-step="${n}"]`);
        if (!step) return;
        step.classList.remove('done');
        step.classList.add('active');
    }

    function markPipelineStepDone(n) {
        const step = document.querySelector(`.pipeline-step[data-step="${n}"]`);
        if (!step) return;
        step.classList.remove('active');
        step.classList.add('done');
    }

    function typeTextIntoTerminal(lines) {
        const token = currentSimToken;
        const out = $('#terminalOutput');
        const termBody = $('#terminalBody');
        if (out) {
            let buffer = out.innerHTML.trimEnd();
            if (!buffer.endsWith('\n')) buffer += '\n';
            out.innerHTML = buffer;
        }

        // Max typing cap: if there are many lines, truncate typing so the user
        // doesn't wait 10+ seconds. We just append the rest instantly.
        const SAFE_MAX_LINES = 18;

        return new Promise((resolve) => {
            let lineIdx = 0;
            let charIdx = 0;
            let lineHtml = '';
            let safetyTimer = null;
            let pendingTimers = [];

            function done() {
                pendingTimers.forEach((t) => clearTimeout(t));
                pendingTimers = [];
                if (safetyTimer != null) { clearTimeout(safetyTimer); safetyTimer = null; }
                resolve();
            }

            function tick() {
                if (token !== currentSimToken) { done(); return; }
                if (lineIdx >= lines.length) { done(); return; }
                const line = lines[lineIdx];
                if (charIdx === 0) {
                    lineHtml = '<span class="prompt">$</span> ';
                    if (out) out.insertAdjacentHTML('beforeend', lineHtml);
                }
                // After SAFE_MAX_LINES lines or for long lines, skip character typing
                // to avoid multi-second waits on big brute-force logs.
                const skipTyping = lineIdx > SAFE_MAX_LINES || line.length > 200;
                if (skipTyping) {
                    if (out) out.insertAdjacentText('beforeend', line);
                    charIdx = line.length;
                }
                if (charIdx < line.length) {
                    const ch = line.charAt(charIdx);
                    if (out) out.insertAdjacentText('beforeend', ch);
                    charIdx++;
                    if (termBody) termBody.scrollTop = termBody.scrollHeight;
                    const t = setTimeout(tick, TYPING_INTERVAL_MS);
                    pendingTimers.push(t);
                    typingTimers.push(t);
                } else {
                    if (out) out.insertAdjacentHTML('beforeend', '\n');
                    if (termBody) termBody.scrollTop = termBody.scrollHeight;
                    lineIdx++;
                    charIdx = 0;
                    const t = setTimeout(tick, 120);
                    pendingTimers.push(t);
                    typingTimers.push(t);
                }
            }

            // Absolute safety: max 1800ms for any typing block.
            safetyTimer = setTimeout(done, 1800);

            tick();
        });
    }

    function animateCountdown(startNum, onDone) {
        const token = currentSimToken;
        const card = $('#countdownCard');
        const numEl = $('#countdownNumber');
        let safetyTimer = null;
        let doneFired = false;

        function done() {
            if (doneFired) return;
            doneFired = true;
            if (safetyTimer != null) { clearTimeout(safetyTimer); safetyTimer = null; }
            if (card && token === currentSimToken) card.classList.add('d-none');
            onDone();
        }

        if (!card || !numEl) {
            done();
            return;
        }
        card.classList.remove('d-none');
        let n = startNum;
        numEl.textContent = String(n);
        const id = setInterval(() => {
            if (token !== currentSimToken) { clearInterval(id); done(); return; }
            n -= 1;
            if (n <= 0) {
                clearInterval(id);
                done();
                return;
            }
            if (numEl && token === currentSimToken) numEl.textContent = String(n);
        }, 600);
        // Safety: make sure countdown never hangs if setInterval doesn't tick.
        safetyTimer = setTimeout(done, (startNum * 600) + 800);
    }

    function progressSimulatedAttack(successPct, targetAttempts) {
        const outerToken = currentSimToken;
        const start = Date.now();
        const counterEl = $('#attemptCount');
        if (counterEl) counterEl.textContent = '0';
        const spinner = $('.attackSpinner');
        if (spinner) spinner.classList.remove('d-none');
        const idleIcon = $('.attackStatusIconIdle');
        if (idleIcon) idleIcon.classList.add('d-none');
        const status = $('#attackStatusText');
        if (status) status.textContent = 'Attacking...';
        activatePipelineStep(3);

        // Cap displayed target at 10 Crore so JS formatting + layout remain sane
        // even for the "impossible" strong passwords with 10^14+ attempts.
        const safeTarget = Math.max(1000000, Math.min(Number(targetAttempts) || 1000000, 1_000_000_000)); // 1B max

        return new Promise((resolve) => {
            let rafId = null;
            let safetyTimer = null;

            function finalize() {
                if (rafId != null) { cancelAnimationFrame(rafId); rafId = null; }
                if (safetyTimer != null) { clearTimeout(safetyTimer); safetyTimer = null; }
                // Snap exactly to the final target so the terminal log lines match.
                if (counterEl && outerToken === currentSimToken) {
                    counterEl.textContent = Number(safeTarget).toLocaleString('en-IN');
                }
                resolve();
            }

            function tick() {
                if (outerToken !== currentSimToken) { finalize(); return; }
                const elapsed = Date.now() - start;
                const ratio = Math.min(1, elapsed / SIM_DURATION_MS);
                setProgress(ratio * successPct);

                const ease = ratio < 0.85
                    ? Math.pow(ratio / 0.85, 0.65) * 0.9
                    : 0.9 + ((ratio - 0.85) / 0.15) * 0.1;
                const approxAttempts = Math.floor(ease * safeTarget);
                if (counterEl) counterEl.textContent = approxAttempts.toLocaleString('en-IN');

                if (ratio < 1) {
                    rafId = requestAnimationFrame(tick);
                } else {
                    finalize();
                }
            }

            // Belt + suspenders: absolute max safety timeout 500ms longer than sim
            safetyTimer = setTimeout(finalize, SIM_DURATION_MS + 500);

            rafId = requestAnimationFrame(tick);
        });
    }

    function updateStats(stats) {
        if (!stats) return;
        if ($('#statTotal')) $('#statTotal').textContent = String(stats.total_simulations || 0);
        if ($('#statStrong')) $('#statStrong').textContent = String(stats.strong_passwords_tested || 0);
        if ($('#statWeak')) $('#statWeak').textContent = String(stats.weak_passwords_tested || 0);
        if ($('#statAvg')) $('#statAvg').textContent = String(stats.average_security_score || 0);
    }

    async function refreshStats() {
        try {
            const res = await fetch('/api/attack/statistics', { method: 'GET' });
            const data = await res.json();
            if (data && data.success) updateStats(data.statistics);
        } catch (e) {
            /* ignore */
        }
    }

    function strengthToColor(strength) {
        switch (strength) {
            case 'Very Strong':
                return '#16a34a';
            case 'Strong':
                return '#22c55e';
            case 'Medium':
                return '#eab308';
            case 'Weak':
                return '#f97316';
            default:
                return '#dc2626';
        }
    }

    function riskToClass(risk) {
        switch (risk) {
            case 'Low':
                return 'bg-success text-light';
            case 'Medium':
                return 'bg-info text-light';
            case 'High':
                return 'bg-warning text-dark';
            case 'Critical':
                return 'bg-danger text-light';
            default:
                return 'bg-secondary text-light';
        }
    }

    function animateScoreRing(score) {
        const ring = $('#scoreRing');
        const scoreNum = $('#scoreNumber');
        const radius = 66;
        const circumference = 2 * Math.PI * radius; // ~414.69
        if (ring) ring.setAttribute('stroke-dasharray', String(circumference));
        const targetOffset = circumference * (1 - score / 100);

        const color = score >= 80 ? '#16a34a' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#dc2626';
        if (ring) ring.setAttribute('stroke', color);

        const duration = 900;
        const startT = performance.now();
        const startNum = 0;
        const startDash = circumference;

        function frame(t) {
            const ratio = Math.min(1, (t - startT) / duration);
            const eased = 1 - Math.pow(1 - ratio, 3);
            const curNum = Math.round(startNum + (score - startNum) * eased);
            const curDash = startDash + (targetOffset - startDash) * eased;
            if (ring) ring.setAttribute('stroke-dashoffset', String(curDash));
            if (scoreNum) scoreNum.textContent = String(curNum);
            if (ratio < 1) requestAnimationFrame(frame);
        }
        requestAnimationFrame(frame);
    }

    function renderBreakdown(result) {
        const bd = (result.security_breakdown || {});
        const lenScore = Math.max(0, Math.min(40, bd.length || 0));
        const varScore = Math.max(0, Math.min(45, bd.variety || 0));
        const randScore = Math.max(0, Math.min(35, bd.randomness || 0));

        $('#breakdownLen').textContent = String(lenScore);
        $('#breakdownVar').textContent = String(varScore);
        $('#breakdownRand').textContent = String(randScore);

        $('#bdLenBar').style.width = (lenScore / 40) * 100 + '%';
        $('#bdVarBar').style.width = (varScore / 45) * 100 + '%';
        $('#bdRandBar').style.width = (randScore / 35) * 100 + '%';

        const meter = $('#strengthMeter');
        if (meter) {
            meter.style.width = result.score + '%';
            meter.className = 'progress-bar ' + (
                result.score >= 80 ? 'bg-success'
                    : result.score >= 60 ? 'bg-info'
                        : result.score >= 40 ? 'bg-warning'
                            : 'bg-danger'
            );
        }

        const ctx = document.getElementById('breakdownChart');
        if (!ctx) return;
        if (breakdownChart) {
            breakdownChart.destroy();
            breakdownChart = null;
        }
        breakdownChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Length', 'Variety', 'Randomness'],
                datasets: [{
                    label: 'Security Score Components',
                    data: [lenScore, varScore, randScore],
                    backgroundColor: [
                        'rgba(13, 110, 253, 0.7)',
                        'rgba(25, 135, 84, 0.7)',
                        'rgba(234, 179, 8, 0.7)',
                    ],
                    borderColor: [
                        'rgba(13, 110, 253, 1)',
                        'rgba(25, 135, 84, 1)',
                        'rgba(234, 179, 8, 1)',
                    ],
                    borderWidth: 1,
                }],
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 45,
                        ticks: { color: '#ccc' },
                        grid: { color: 'rgba(255,255,255,0.08)' },
                    },
                    x: {
                        ticks: { color: '#ccc' },
                        grid: { color: 'rgba(255,255,255,0.08)' },
                    },
                },
            },
        });
    }

    function renderEducational(edu) {
        if (!edu) return;
        $('#eduWhyWorks').textContent = edu.why_works || '—';
        $('#eduWhyFails').textContent = edu.why_fails || '—';
        $('#eduDefend').textContent = edu.defend || '—';
        $('#eduBest').textContent = edu.best_practices || '—';
    }

    function renderTips(tips) {
        const list = $('#tipsList');
        if (!list) return;
        list.innerHTML = '';
        if (!tips || !tips.length) {
            list.innerHTML =
                '<li class="list-group-item bg-dark small border-secondary d-flex align-items-start gap-2">' +
                '<i class="fas fa-circle-check text-success mt-1"></i>' +
                '<span class="text-light">Excellent — no specific improvements detected. Keep using unique, long, random passwords + MFA.</span>' +
                '</li>';
            return;
        }
        tips.forEach((tip) => {
            const li = document.createElement('li');
            li.className = 'list-group-item bg-dark border-secondary d-flex align-items-start gap-2';
            li.innerHTML =
                '<i class="fas fa-circle-info text-info me-1 mt-1"></i>' +
                '<span class="text-light">' + escapeHtml(tip) + '</span>';
            list.appendChild(li);
        });
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function renderCategoryReport(result) {
        const tbody = $('#categoryReportBody');
        if (!tbody) return;
        const cats = Array.isArray(result.attack_report) ? result.attack_report : [];
        const totalCatsEl = $('#totalCats');
        const totalScanEl = $('#totalScanAttempts');
        const totalMatchesEl = $('#totalMatches');
        const totalSkipsEl = $('#totalSkips');

        if (!cats.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-light opacity-50 py-3">No category data for this attack type.</td></tr>';
            if (totalCatsEl) totalCatsEl.textContent = '0';
            if (totalScanEl) totalScanEl.textContent = '0';
            if (totalMatchesEl) totalMatchesEl.textContent = '0';
            if (totalSkipsEl) totalSkipsEl.textContent = '0';
            return;
        }

        tbody.innerHTML = '';
        let matches = 0;
        let skips = 0;
        let totalAttempts = 0;
        cats.forEach((cat, idx) => {
            totalAttempts += Number(cat.attempts) || 0;
            const isHit = !!cat.hit;
            const isSkipped = !!cat.skipped;
            if (isHit) matches += 1;
            if (isSkipped) skips += 1;

            const tr = document.createElement('tr');
            if (isHit) {
                tr.className = 'align-middle';
                tr.classList.add('row-match');
            } else if (isSkipped) {
                tr.className = 'align-middle';
                tr.classList.add('row-skipped');
            } else {
                tr.className = 'align-middle row-no-match';
            }

            // Priority badge
            const priority = cat.priority || (idx + 1);
            const priorityLabel = cat.category_name || ('Category ' + (idx + 1));
            let statusBadge = '';
            if (isHit) {
                statusBadge = '<span class="badge bg-danger text-light row-status-badge"><i class="fas fa-bullseye me-1"></i>MATCH</span>';
            } else if (isSkipped) {
                statusBadge = '<span class="badge bg-warning-subtle border border-warning text-warning-emphasis row-status-badge"><i class="fas fa-forward me-1"></i>SKIPPED</span>';
            } else {
                statusBadge = '<span class="badge bg-secondary-subtle border border-secondary text-light opacity-75 row-status-badge"><i class="fas fa-ban me-1"></i>No Match</span>';
            }

            const attemptsFmt = cat.attempts_formatted
                || (Number.isFinite(cat.attempts) ? formatAttemptsShort(cat.attempts) : '—');
            const attemptsRaw = Number.isFinite(cat.attempts) ? Number(cat.attempts).toLocaleString('en-IN') : '';
            const attemptsTitle = attemptsRaw ? ('title="' + attemptsRaw + ' candidates"') : '';

            const foundAt = (isHit && cat.hit_position)
                ? '<span class="font-monospace text-warning">' + Number(cat.hit_position).toLocaleString('en-IN') + '</span>'
                : isSkipped
                    ? '<span class="font-monospace text-warning-emphasis opacity-75 small">0</span>'
                    : '<span class="text-light opacity-40">—</span>';

            let description = cat.description || '';
            if (isSkipped && cat.skip_reason) {
                description = '<div class="text-light opacity-50 small">' + escapeHtml(description) +
                    '</div><div class="text-warning-emphasis small mt-1"><i class="fas fa-forward me-1"></i>' +
                    escapeHtml(cat.skip_reason) + '</div>';
            } else {
                description = escapeHtml(description);
            }

            tr.innerHTML =
                '<td class="text-center"><span class="badge bg-dark border border-success text-success fw-bold prio-badge">' + String(priority).padStart(2, '0') + '</span></td>' +
                '<td><div class="fw-semibold text-light small">' + escapeHtml(priorityLabel) + '</div>' +
                '<div class="small text-light opacity-50 font-monospace">ID: ' + escapeHtml(cat.category_id || '—') + '</div></td>' +
                '<td class="text-center" ' + attemptsTitle + '><div class="font-monospace text-info fw-bold small">' + escapeHtml(String(attemptsFmt)) + '</div>' +
                (attemptsRaw && !isSkipped ? '<div class="small text-light opacity-40">' + escapeHtml(attemptsRaw) + '</div>' :
                    (isSkipped ? '<div class="small text-warning-emphasis opacity-60">— skipped —</div>' : '')) +
                '</td>' +
                '<td class="text-center">' + statusBadge + '</td>' +
                '<td class="text-center">' + foundAt + '</td>' +
                '<td><div class="small text-light lh-sm">' + description + '</div></td>';
            tbody.appendChild(tr);
        });

        if (totalCatsEl) totalCatsEl.textContent = String(cats.length);
        if (totalScanEl) {
            totalScanEl.textContent = formatAttemptsShort(totalAttempts) || String(totalAttempts);
            totalScanEl.title = Number(totalAttempts).toLocaleString('en-IN') + ' total candidates';
        }
        if (totalMatchesEl) {
            totalMatchesEl.textContent = String(matches);
            totalMatchesEl.className = matches > 0
                ? 'fw-bold text-danger'
                : 'fw-bold text-success';
        }
        if (totalSkipsEl) {
            totalSkipsEl.textContent = String(skips);
            totalSkipsEl.className = skips > 0
                ? 'fw-bold text-info cyber-pulse'
                : 'fw-bold text-light opacity-70';
        }
    }

    function formatAttemptsShort(n) {
        n = Number(n) || 0;
        if (n < 1_000) return String(n);
        if (n < 1_000_000) return (n / 1_000).toFixed(1) + 'K';
        if (n < 1_000_000_000) return (n / 1_000_000).toFixed(1) + 'M';
        if (n < 1_000_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
        return (n / 1_000_000_000_000).toFixed(2) + 'T';
    }

    function renderResultCard(result) {
        const card = $('#resultCard');
        if (card) card.classList.remove('d-none');

        // Clear cracked / secure styling from prior runs.
        if (card) card.classList.remove('cracked');

        const isCracked = (result.success_rate_value != null && result.success_rate_value >= 95)
            || extractPct(result.success_rate) >= 95;
        if (card && isCracked) card.classList.add('cracked');

        $('#resAttack').textContent = result.attack || '—';

        // Hints (Dictionary attack personalized wordlist)
        const hintsRow = $('#resHintsRow');
        const hintsChips = $('#resHintsChips');
        const hintsUsed = Array.isArray(result.hints_used) && result.hints_used.length
            ? result.hints_used
            : null;
        if (hintsRow) {
            if (hintsUsed && hintsUsed.length) {
                hintsRow.style.display = '';
                renderHintsChips(hintsUsed, '#resHintsChips', { palette: false });
            } else {
                hintsRow.style.display = 'none';
                if (hintsChips) hintsChips.innerHTML = '';
            }
        }

        // --- Show how many tries it took ---
        const triesRaw = result.attempts_approx;
        const triesFmt = result.attempts_formatted;
        const triesEl = $('#resAttempts');
        if (triesEl) {
            if (triesFmt || Number.isFinite(triesRaw)) {
                const label = triesFmt || (Number.isFinite(triesRaw) ? Number(triesRaw).toLocaleString() : '—');
                const extra = (Number.isFinite(triesRaw) && triesRaw >= 1000)
                    ? ' (' + Number(triesRaw).toLocaleString() + ')'
                    : '';
                triesEl.textContent = label + extra;
                triesEl.title = Number.isFinite(triesRaw) ? 'Approximate tries: ' + Number(triesRaw).toLocaleString() : '';
            } else {
                triesEl.textContent = '—';
            }
        }
        // Update terminal footer attempt counter with final real number too.
        const finalTries = Number.isFinite(triesRaw) ? Number(triesRaw) : null;
        if (finalTries != null) {
            const counter = $('#attemptCount');
            if (counter) counter.textContent = finalTries.toLocaleString('en-IN');
        }

        $('#resSuccess').textContent = result.success_rate || '—';
        $('#resTime').textContent = result.estimated_time || '—';
        $('#resStrength').textContent = result.strength || '—';
        $('#resRisk').textContent = result.risk || '—';

        const badge = $('#strengthBadge');
        if (badge) {
            badge.textContent = result.strength || '—';
            const c = strengthToColor(result.strength);
            badge.style.backgroundColor = c;
            badge.style.color = '#000';
        }

        const riskBadge = $('#riskBadge');
        if (riskBadge) {
            riskBadge.className = 'badge fs-6 ' + riskToClass(result.risk);
            riskBadge.textContent = 'Risk Level: ' + (result.risk || 'Unknown');
        }

        const entropy = $('#entropyBits');
        if (entropy) entropy.textContent = String(result.entropy_bits || 0);

        renderTips(result.tips);
        renderEducational(result.educational);
        renderBreakdown(result);
        animateScoreRing(result.score || 0);

        // NEW: Render category-by-category breakdown table
        renderCategoryReport(result);

        // Final pipeline state
        activatePipelineStep(5);
        markPipelineStepDone(4);

        if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ============================================================
    // Report Download Handlers
    // ============================================================

    function getActivePayload() {
        const pwInput = $('#attackPasswordInput');
        const attackId = (pwInput && pwInput.dataset.selectedAttack) || 'brute_force';
        const password = pwInput ? pwInput.value : '';
        const hintsInput = $('#hintsInput');
        const rawHints = (attackId === 'dictionary' && hintsInput) ? (hintsInput.value || '') : '';
        const parsedHints = parseHintsInput(rawHints);
        const payload = { attack: attackId, password: password };
        if (parsedHints.length) payload.hints = parsedHints;
        return payload;
    }

    async function downloadReport(fmt) {
        const payload = getActivePayload();
        if (!payload.password) {
            // Fallback: if no password in input, try cached last result for download
            const cached = getLastResult();
            if (cached && cached._lastPayload) {
                return doDownloadRequest(cached._lastPayload, fmt);
            }
            if (typeof showToast === 'function') showToast('Enter a password first to generate its report.', 'error');
            else alert('Enter a password first.');
            return;
        }
        payload.format = fmt;
        return doDownloadRequest(payload, fmt);
    }

    async function doDownloadRequest(payload, fmt) {
        const token = ++currentSimToken;
        const url = '/api/attack/report/download';
        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken':
                        (window.getCsrfToken && window.getCsrfToken()) ||
                        getCsrfTokenMeta(),
                },
                body: JSON.stringify(payload),
            });
            if (token !== currentSimToken) return;
            if (!res.ok) {
                let errText = 'Download failed';
                try { const j = await res.json(); if (j && j.error) errText = j.error; } catch (_) { /* ignore */ }
                if (typeof showToast === 'function') showToast(errText, 'error');
                else alert(errText);
                return;
            }
            const blob = await res.blob();
            const disp = res.headers.get('Content-Disposition') || '';
            const m = disp.match(/filename="?([^"]+)"?/);
            const filename = m && m[1]
                ? m[1]
                : ('attack_report.' + (fmt === 'json' ? 'json' : 'txt'));
            const href = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = href;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(href), 2000);
            if (typeof showToast === 'function') {
                showToast('Report downloaded: ' + filename, 'success');
            }
        } catch (e) {
            console.error(e);
            if (typeof showToast === 'function') showToast('Network error during download.', 'error');
            else alert('Network error.');
        }
    }

    async function startAttack() {
        if (isAttackRunning) return;
        const pwInput = $('#attackPasswordInput');
        const attackId = (pwInput && pwInput.dataset.selectedAttack) || 'brute_force';
        const password = pwInput ? pwInput.value : '';
        if (!password) {
            if (typeof showToast === 'function') showToast('Please enter a password to simulate.', 'error');
            else alert('Please enter a password to simulate.');
            return;
        }

        const hintsInput = $('#hintsInput');
        const rawHints = (attackId === 'dictionary' && hintsInput) ? (hintsInput.value || '') : '';
        const parsedHints = parseHintsInput(rawHints);

        // === LOCK ATTACK STATE ===
        isAttackRunning = true;
        const token = ++currentSimToken;
        resetPipeline();
        activatePipelineStep(2);
        const resCard = $('#resultCard');
        if (resCard) resCard.classList.add('d-none');

        toggleCancelButtons(true);
        const startBtn = $('#startAttackBtn');
        const startLabel = $('#startBtnLabel');
        if (startBtn) startBtn.disabled = true;
        if (startLabel) startLabel.textContent = 'RUNNING…';
        const modeBadge = $('#simModeBadge');
        if (modeBadge) {
            modeBadge.textContent = 'ATTACKING';
            modeBadge.className = 'ms-2 small badge bg-dark border border-danger-subtle text-danger cyber-pulse opacity-90';
        }

        // Ultimate safety timer: regardless of any promise hangs or forgotten
        // callbacks, NO attack state can stay locked past ~9 seconds.
        let finalizeFired = false;
        const attackSafetyMaxMs = 9000;
        const safetyTimer = setTimeout(() => forceFinalizeState(true), attackSafetyMaxMs);

        function forceFinalizeState(timeoutAbort) {
            if (finalizeFired) return;
            finalizeFired = true;
            if (safetyTimer != null) { clearTimeout(safetyTimer); /* ignore */ }
            const stillAttacking = (token === currentSimToken && isAttackRunning);
            isAttackRunning = false;
            toggleCancelButtons(false);
            if (startBtn) startBtn.disabled = false;
            if (startLabel) startLabel.textContent = 'START ATTACK';
            // Clear spinner + put terminal back to idle
            const spinner = $('.attackSpinner');
            if (spinner) spinner.classList.add('d-none');
            const idleIcon = $('.attackStatusIconIdle');
            if (idleIcon) idleIcon.classList.remove('d-none');
            const statusText = $('#attackStatusText');
            if (modeBadge) {
                if (timeoutAbort) {
                    modeBadge.textContent = 'TIMEOUT';
                    modeBadge.className = 'ms-2 small badge bg-dark border border-warning-subtle text-warning opacity-90';
                    if (statusText) statusText.textContent = 'Timed out (continuing anyway)';
                } else if (!stillAttacking) {
                    // Don't overwrite good COMPLETE/CRACKED state if animateCountdown already ran
                }
            }
            if (timeoutAbort) {
                if (typeof showToast === 'function') showToast('Attack safety timeout hit — state released.', 'warn');
            }
        }

        let apiData;
        const payloadForCache = { attack: attackId, password: password };
        if (parsedHints.length) payloadForCache.hints = parsedHints;

        try {
            const payload = Object.assign({}, payloadForCache);
            const res = await fetch('/api/attack/simulate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken':
                        (window.getCsrfToken && window.getCsrfToken()) ||
                        getCsrfTokenMeta(),
                },
                body: JSON.stringify(payload),
            });
            apiData = await res.json();
        } catch (e) {
            if (token !== currentSimToken) { forceFinalizeState(false); return; }
            if (modeBadge) {
                modeBadge.textContent = 'ERROR';
                modeBadge.className = 'ms-2 small badge bg-dark border border-danger-subtle text-danger opacity-90';
            }
            forceFinalizeState(false);
            if (typeof showToast === 'function') showToast('Network error — try again.', 'error');
            else alert('Network error.');
            return;
        }

        if (token !== currentSimToken) { forceFinalizeState(false); return; }
        if (!apiData || !apiData.success) {
            const err = (apiData && apiData.error) || 'Failed to run simulation';
            forceFinalizeState(false);
            if (typeof showToast === 'function') showToast(err, 'error');
            else alert(err);
            return;
        }

        const result = apiData.result;
        result._lastPayload = Object.assign({}, payloadForCache);

        const successPct = Math.min(100, Math.max(0, result.success_rate_value != null
            ? result.success_rate_value
            : extractPct(result.success_rate)));

        const rawAttempts = Number(result.attempts_approx);
        pendingAttemptsTarget = Number.isFinite(rawAttempts) ? rawAttempts : 1000000;

        if (result.early_exited) {
            appendTerminalLine(
                '<span class="prompt warn">$</span> ' +
                '<span style="color:#22d3ee;font-weight:600;">' +
                '◉ EARLY EXIT — Password located in Category #' +
                String(result.first_hit_priority || '?') +
                ' (' + escapeHtml(result.first_hit_category_name || '') + ') ' +
                '— skipping remaining ' +
                String(result.skip_count || 0) + ' categories.</span>',
            );
        }

        const lines = (result.found_log && result.found_log.length)
            ? result.found_log
            : ['Running attack ...', 'Analyzing ...', 'Done.'];

        await typeTextIntoTerminal(lines.slice(0, Math.max(1, Math.ceil(lines.length / 2))));
        if (token !== currentSimToken) { forceFinalizeState(false); return; }
        markPipelineStepDone(2);

        await progressSimulatedAttack(successPct, pendingAttemptsTarget);
        if (token !== currentSimToken) { forceFinalizeState(false); return; }
        markPipelineStepDone(3);
        activatePipelineStep(4);

        await typeTextIntoTerminal(lines.slice(Math.ceil(lines.length / 2)));
        if (token !== currentSimToken) { forceFinalizeState(false); return; }

        setProgress(successPct);
        if (Number.isFinite(rawAttempts)) {
            const counter = $('#attemptCount');
            if (counter) counter.textContent = rawAttempts.toLocaleString('en-IN');
        }
        const spinner = $('.attackSpinner');
        if (spinner) spinner.classList.add('d-none');
        const idleIcon = $('.attackStatusIconIdle');
        if (idleIcon) idleIcon.classList.remove('d-none');
        const statusText = $('#attackStatusText');
        if (statusText) {
            statusText.textContent =
                successPct >= 95 ? 'Password Cracked'
                    : successPct >= 30 ? 'Completed — Password is Vulnerable'
                        : 'Completed — Password Resisted';
        }
        if (modeBadge) {
            modeBadge.textContent = successPct >= 95 ? 'CRACKED' : 'COMPLETE';
            modeBadge.className = 'ms-2 small badge bg-dark border ' +
                (successPct >= 95 ? 'border-danger text-danger' : 'border-success text-success') + ' opacity-90';
        }
        const termWrap = document.querySelector('.terminal-wrap');
        if (termWrap) {
            termWrap.classList.remove('cracked-flash');
            void termWrap.offsetWidth;
        }
        if (successPct >= 95) {
            appendTerminalLine('<span class="prompt success">$</span> <span class="attack-found">PASSWORD FOUND</span>');
            if (termWrap) termWrap.classList.add('cracked-flash');
        } else {
            appendTerminalLine('<span class="prompt info">$</span> Attack finished. See analysis report.');
        }

        markPipelineStepDone(4);

        // Countdown 3..2..1 then reveal
        animateCountdown(3, () => {
            if (token !== currentSimToken) { forceFinalizeState(false); return; }
            markPipelineStepDone(5);
            if (apiData.result.stats) updateStats(apiData.result.stats);
            cacheLastResult(result);
            renderResultCard(result);
            // Clear attack state only AFTER result card is revealed.
            forceFinalizeState(false);
            if (typeof showToast === 'function') {
                showToast(
                    'Simulation complete — Security Score: ' + result.score + '/100',
                    result.score >= 70 ? 'success' : 'error',
                );
            }
        });
    }

    function extractPct(text) {
        if (!text) return 0;
        const m = String(text).match(/(\d+(?:\.\d+)?)\s*%/);
        return m ? parseFloat(m[1]) : 0;
    }

    function getCsrfTokenMeta() {
        const m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.getAttribute('content') : '';
    }

    function wireEvents() {
        $$('.launch-attack-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-attack-id');
                const name = btn.getAttribute('data-attack-name') || ATTACK_NAMES[id] || id;
                showAttackPanel(id, name);
                if (typeof showToast === 'function') {
                    showToast(name + ' module loaded. Enter a password and press Start Attack.', 'success');
                }
            });
        });

        $$('.example-pw').forEach((btn) => {
            btn.addEventListener('click', () => {
                const pw = btn.getAttribute('data-value');
                const inp = $('#attackPasswordInput');
                if (inp && pw != null) inp.value = pw;
            });
        });

        const startBtn = $('#startAttackBtn');
        if (startBtn) startBtn.addEventListener('click', startAttack);

        // -------- Cancel buttons (clickable only during attack runs) --------
        const cancelBtn = $('#cancelAttackBtn');
        if (cancelBtn) cancelBtn.addEventListener('click', cancelRunningAttack);
        const cancelBtnMobile = $('#cancelAttackBtnMobile');
        if (cancelBtnMobile) cancelBtnMobile.addEventListener('click', cancelRunningAttack);

        const pwInput = $('#attackPasswordInput');
        if (pwInput) {
            pwInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    startAttack();
                }
            });
        }

        // --- Dictionary hints UI events ---
        const hintsInput = $('#hintsInput');
        if (hintsInput) {
            hintsInput.addEventListener('input', syncHintsUi);
            hintsInput.addEventListener('change', syncHintsUi);
            hintsInput.addEventListener('blur', syncHintsUi);
        }

        const clearHintsBtn = $('#clearHintsBtn');
        if (clearHintsBtn) {
            clearHintsBtn.addEventListener('click', () => {
                const inp = $('#hintsInput');
                if (!inp) return;
                inp.value = '';
                syncHintsUi();
                inp.focus();
            });
        }

        $$('.hint-preset').forEach((btn) => {
            btn.addEventListener('click', () => {
                const val = btn.getAttribute('data-value') || '';
                const inp = $('#hintsInput');
                if (!inp) return;
                inp.value = val;
                syncHintsUi();
                const start = $('#startAttackBtn');
                if (start) start.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                if (typeof showToast === 'function') {
                    showToast('Preset hints loaded — adjust or press Start Attack.', 'success');
                }
            });
        });

        const togglePw = $('#togglePwVisibility');
        if (togglePw) {
            togglePw.addEventListener('click', () => {
                const inp = $('#attackPasswordInput');
                if (!inp) return;
                const eye = togglePw.querySelector('i');
                if (inp.type === 'text') {
                    inp.type = 'password';
                    if (eye) {
                        eye.classList.remove('fa-eye-slash');
                        eye.classList.add('fa-eye');
                    }
                } else {
                    inp.type = 'text';
                    if (eye) {
                        eye.classList.remove('fa-eye');
                        eye.classList.add('fa-eye-slash');
                    }
                }
            });
        }

        const closeBtn = $('#closeSimulationBtn');
        if (closeBtn) closeBtn.addEventListener('click', closeAttackPanel);

        const closeResultBtn = $('#closeResultBtn');
        if (closeResultBtn) closeResultBtn.addEventListener('click', closeResultPanel);

        const reportBtn = $('#toggleReportBtn');
        if (reportBtn) reportBtn.addEventListener('click', toggleReport);

        const quickReportBtn = $('#quickReportBtn');
        if (quickReportBtn) quickReportBtn.addEventListener('click', toggleReport);

        // -------- BACK-TO-SIM (Re-run) button in result header — make it actually DO something --------
        const backToSimBtn = $('#backToSimBtn');
        if (backToSimBtn) {
            backToSimBtn.addEventListener('click', (e) => {
                e.preventDefault();
                const sim = $('#simulationCard');
                if (sim) {
                    sim.style.display = '';
                    sim.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
                const inp = $('#attackPasswordInput');
                if (inp) inp.focus();
                if (typeof showToast === 'function') {
                    showToast('Ready to re-run simulation — change any inputs and press Start.', 'success');
                }
            });
        }

        // --- Download Report buttons ---
        const dlTxtBtn = $('#downloadTxtBtn');
        if (dlTxtBtn) {
            dlTxtBtn.addEventListener('click', () => downloadReport('txt'));
        }
        const dlJsonBtn = $('#downloadJsonBtn');
        if (dlJsonBtn) {
            dlJsonBtn.addEventListener('click', () => downloadReport('json'));
        }

        // If the page was refreshed and a cached result exists, surface the
        // Report buttons so users can immediately reopen the last report.
        if (hasLastResult()) {
            if (reportBtn) reportBtn.style.display = '';
            if (quickReportBtn) quickReportBtn.style.display = '';
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', wireEvents);
    } else {
        wireEvents();
    }

    // Periodically refresh stats for leaderboard.
    if (typeof window !== 'undefined') {
        window.addEventListener('load', () => {
            statsRefreshTimer = setInterval(refreshStats, STATS_REFRESH_INTERVAL_MS);
        });
    }
})();
