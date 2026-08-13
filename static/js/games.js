/* ============================================================================
   Cryptography Games module — client side
   Fully defensive: every init/handler is wrapped in try/catch + null guards.
   All attacks/demos are purely educational / local / simulated.
   ============================================================================ */
(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Null-safe DOM helpers
  // ---------------------------------------------------------------------------
  function qs(id) {
    try {
      if (!id) return null;
      return document.getElementById(String(id));
    } catch (_e) { return null; }
  }
  function setText(elOrId, text) {
    const el = (typeof elOrId === "string") ? qs(elOrId) : elOrId;
    if (!el) return;
    try { el.textContent = (text == null ? "" : String(text)); } catch (_e) { /* ignore */ }
  }
  function showEl(elOrId) {
    const el = (typeof elOrId === "string") ? qs(elOrId) : elOrId;
    if (!el) return;
    try { el.classList.remove("d-none"); } catch (_e) {}
  }
  function hideEl(elOrId) {
    const el = (typeof elOrId === "string") ? qs(elOrId) : elOrId;
    if (!el) return;
    try { el.classList.add("d-none"); } catch (_e) {}
  }
  function addClass(elOrId, cls) {
    const el = (typeof elOrId === "string") ? qs(elOrId) : elOrId;
    if (!el || !cls) return;
    try { String(cls).split(/\s+/).forEach(c => c && el.classList.add(c)); } catch (_e) {}
  }
  function removeClass(elOrId, cls) {
    const el = (typeof elOrId === "string") ? qs(elOrId) : elOrId;
    if (!el || !cls) return;
    try { String(cls).split(/\s+/).forEach(c => c && el.classList.remove(c)); } catch (_e) {}
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // ---------------------------------------------------------------------------
  // Cipher helpers (mirror server crypto_games.py)
  // ---------------------------------------------------------------------------
  function caesarShift(c, shift, reverse) {
    try {
      if (!/[a-zA-Z]/.test(c)) return c;
      shift = ((shift % 26) + 26) % 26;
      if (reverse) shift = (26 - shift) % 26;
      const base = c === c.toUpperCase() ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
    } catch (_e) { return c; }
  }
  function caesarDecrypt(ct, shift) {
    try {
      return String(ct || "").split("").map(c => caesarShift(c, (shift | 0) % 26, true)).join("");
    } catch (_e) { return ct || ""; }
  }
  function normalizeAnswer(s) {
    try { return String(s || "").trim().replace(/\s+/g, " ").toUpperCase(); }
    catch (_e) { return ""; }
  }

  // ---------------------------------------------------------------------------
  // CSRF helpers (mirror app.js pattern)
  // ---------------------------------------------------------------------------
  function getCsrfToken() {
    try {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? (meta.getAttribute("content") || "") : "";
    } catch (_e) { return ""; }
  }
  function csrfFetch(url, opts) {
    opts = opts || {};
    const headers = Object.assign(
      { "Content-Type": "application/json", "X-CSRFToken": getCsrfToken() },
      (opts.headers || {})
    );
    return fetch(url, Object.assign({ credentials: "same-origin" }, opts, { headers: headers }));
  }

  // ---------------------------------------------------------------------------
  // Toasts — reuse window.showToast if available
  // ---------------------------------------------------------------------------
  function toastMessage(msg, variant) {
    try {
      if (typeof window.showToast === "function") {
        window.showToast(msg, variant || "success");
        return;
      }
      const container = document.getElementById("toastContainer");
      if (!container) { console.log("[toast]", variant || "info", msg); return; }
      const t = document.createElement("div");
      t.className = "toast " + (variant || "success");
      t.setAttribute("role", "status");
      t.innerHTML = '<div class="toast-header d-flex justify-content-between"><strong class="me-auto text-success">' +
        escapeHtml(variant === "error" ? "Error" : variant === "warning" ? "Warning" : "Info") +
        '</strong><button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button></div>' +
        '<div class="toast-body">' + escapeHtml(msg || "") + '</div>';
      container.appendChild(t);
      try {
        if (window.bootstrap && window.bootstrap.Toast) {
          new window.bootstrap.Toast(t, { delay: 4500 }).show();
        }
      } catch (_e) { /* ignore */ }
      setTimeout(function () { try { t.remove(); } catch (_e) {} }, 5000);
    } catch (_outer) { console.log("[toast]", variant, msg); }
  }

  // ---------------------------------------------------------------------------
  // Local best-score storage
  // ---------------------------------------------------------------------------
  const LS_KEY = "encryptsys.crypto_games.v1";
  function loadLocal() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return { best: {} };
      const d = JSON.parse(raw);
      if (!d || typeof d !== "object") return { best: {} };
      if (!d.best || typeof d.best !== "object") d.best = {};
      return d;
    } catch (_e) { return { best: {} }; }
  }
  function saveLocal(d) { try { localStorage.setItem(LS_KEY, JSON.stringify(d || {})); } catch (_e) {} }
  function updateBest(gameId, score) {
    try {
      const d = loadLocal();
      score = Number(score) | 0;
      if (!d.best[gameId] || score > Number(d.best[gameId] || 0)) d.best[gameId] = score;
      saveLocal(d);
      paintBestScores();
    } catch (_e) { /* ignore */ }
  }
  function paintBestScores() {
    try {
      const d = loadLocal();
      const nodes = document.querySelectorAll(".game-best");
      nodes.forEach(function (el) {
        try {
          const g = el.getAttribute && el.getAttribute("data-game-id");
          if (!g) return;
          const v = Number(d.best[g] || 0);
          if (!v) {
            el.textContent = "—";
            el.classList.add("empty");
          } else {
            el.textContent = String(v);
            el.classList.remove("empty");
          }
        } catch (_e) { /* per-node */ }
      });
    } catch (_e) { /* ignore */ }
  }

  // ---------------------------------------------------------------------------
  // Bootstrap modal — works without window.bootstrap
  // ---------------------------------------------------------------------------
  function openBootstrapModal(el) {
    try {
      if (!el) return;
      if (el.parentNode !== document.body) {
        try { document.body.appendChild(el); } catch (_e) {}
      }
      el.style.setProperty("z-index", "99980", "important");
      document.querySelectorAll(".modal-backdrop").forEach(function (bd) {
        try { bd.remove(); } catch (_e) {}
      });
      var ourBd = document.getElementById("__games_modal_backdrop");
      if (ourBd) { try { ourBd.remove(); } catch (_e) {} }
      try {
        if (window.bootstrap && window.bootstrap.Modal) {
          try {
            var oldInst = window.bootstrap.Modal.getInstance(el);
            if (oldInst && typeof oldInst.dispose === "function") oldInst.dispose();
          } catch (_e) {}
          try {
            var inst = window.bootstrap.Modal.getOrCreateInstance(el, { backdrop: false, keyboard: true, focus: true });
            if (inst && typeof inst.show === "function") {
              if (!el.__gamesBsHiddenBound) {
                el.__gamesBsHiddenBound = true;
                el.addEventListener("hidden.bs.modal", function () { closeBootstrapModal(el); });
              }
              inst.show();
            }
          } catch (_e2) {}
        }
      } catch (_outer) {}
      var bd = document.createElement("div");
      bd.id = "__games_modal_backdrop";
      bd.className = "modal-backdrop fade show __games_modal_backdrop_custom";
      bd.style.setProperty("z-index", "99970", "important");
      bd.style.setProperty("position", "fixed", "important");
      bd.style.setProperty("top", "0", "important");
      bd.style.setProperty("left", "0", "important");
      bd.style.setProperty("width", "100vw", "important");
      bd.style.setProperty("height", "100vh", "important");
      bd.style.setProperty("background-color", "rgba(0,0,0,0.7)", "important");
      bd.style.setProperty("pointer-events", "auto", "important");
      document.body.appendChild(bd);
      el.classList.add("show");
      el.setAttribute("aria-modal", "true");
      el.setAttribute("role", "dialog");
      el.style.setProperty("display", "block", "important");
      try { document.body.classList.add("modal-open"); document.body.style.overflow = "hidden"; } catch (_e) {}
      try { bd.addEventListener("click", function () { closeBootstrapModal(el); }, { once: true }); } catch (_e) {}
      el.querySelectorAll('[data-bs-dismiss="modal"]').forEach(function (closeBtn) {
        if (!closeBtn.__gamesFallbackBound) {
          closeBtn.__gamesFallbackBound = true;
          closeBtn.addEventListener("click", function (ev) {
            try { ev.preventDefault(); ev.stopPropagation(); } catch (_e) {}
            closeBootstrapModal(el);
          });
        }
      });
      if (!el.__gamesEscBound) {
        el.__gamesEscBound = true;
        document.addEventListener("keydown", function onEsc(e) {
          if (e.key === "Escape") {
            try { closeBootstrapModal(el); } catch (_e) {}
            try { document.removeEventListener("keydown", onEsc); } catch (_e) {}
          }
        });
      }
    } catch (_outer) { try { console.warn("openBootstrapModal error:", _outer); } catch (_e) {} }
  }
  function closeBootstrapModal(el) {
    try {
      if (!el) return;
      try {
        if (window.bootstrap && window.bootstrap.Modal && typeof window.bootstrap.Modal.getInstance === "function") {
          try {
            var inst = window.bootstrap.Modal.getInstance(el);
            if (inst && typeof inst.hide === "function") inst.hide();
          } catch (_e) {}
          try {
            var inst2 = window.bootstrap.Modal.getOrCreateInstance(el, { backdrop: false });
            if (inst2 && typeof inst2.dispose === "function") inst2.dispose();
          } catch (_e2) {}
        }
      } catch (_outer) {}
      el.classList.remove("show");
      el.removeAttribute("aria-modal");
      el.style.removeProperty("display");
      el.style.removeProperty("z-index");
      try { document.body.classList.remove("modal-open"); document.body.style.overflow = ""; } catch (_e) {}
      document.querySelectorAll(".modal-backdrop").forEach(function (bd) {
        try { bd.remove(); } catch (_e) {}
      });
      var ourBd = document.getElementById("__games_modal_backdrop");
      if (ourBd) { try { ourBd.remove(); } catch (_e) {} }
    } catch (_outer) { try { console.warn("closeBootstrapModal error:", _outer); } catch (_e) {} }
  }

  // ---------------------------------------------------------------------------
  // Shared runner state
  // ---------------------------------------------------------------------------
  const state = {
    gameId: null,
    difficulty: "easy",
    level: null,
    timerId: null,
    secondsLeft: 0,
    score: 0,
    lives: 3,
    hintsUsed: 0,
    hints: [],
    finished: false,
    answered: false,
    attempts: 0,
    maxAttempts: Infinity,
    crazyQuestionIndex: 0,
    crazyTotalQuestions: 5,
    crazyTotalCorrect: 0,
    crazySessionComplete: false,
  };

  function setStage(n) {
    try {
      document.querySelectorAll(".progress-pipeline .stage").forEach(function (el) {
        try {
          const num = Number(el.getAttribute("data-stage") || 0);
          el.classList.remove("active", "done");
          if (num < n) el.classList.add("done");
          if (num === n) el.classList.add("active");
        } catch (_e) {}
      });
    } catch (_e) {}
  }
  function renderTimer() {
    const el = qs("runnerTimer"); if (!el) return;
    try {
      const secs = Math.max(0, Number(state.secondsLeft) | 0);
      const m = Math.floor(secs / 60).toString().padStart(2, "0");
      const s = (secs % 60).toString().padStart(2, "0");
      el.textContent = m + ":" + s;
    } catch (_e) {}
  }
  function setTimer(seconds) {
    try {
      if (state.timerId) { clearInterval(state.timerId); state.timerId = null; }
      state.secondsLeft = Math.max(0, Number(seconds) | 0);
      renderTimer();
      if (seconds <= 0) return;
      state.timerId = setInterval(function () {
        try {
          if (state.finished || state.answered) { clearInterval(state.timerId); state.timerId = null; return; }
          state.secondsLeft = Math.max(0, Number(state.secondsLeft) - 1);
          renderTimer();
          if (state.secondsLeft <= 0) {
            clearInterval(state.timerId); state.timerId = null;
            onFailure("Time's up!");
          }
        } catch (_e) { try { if (state.timerId) clearInterval(state.timerId); } catch (_e2) {} }
      }, 1000);
    } catch (_e) {}
  }
  function renderLives() { setText("runnerLives", state.lives); }
  function renderHints() { setText("runnerHints", state.hintsUsed); }
  function renderScore() { setText("runnerScore", state.score); }

  function timeLimitFor(difficulty, gameId) {
    const table = { easy: 150, medium: 120, hard: 90 };
    const base = table[String(difficulty || "easy").toLowerCase()] || 120;
    if (String(gameId) === "encryption_race") return 45;
    if (String(gameId) === "find_vulnerability") return 180;
    if (String(gameId) === "daily_cipher") return 0;
    if (String(gameId) === "crazy_mode") return 300;
    return base;
  }
  function livesFor(difficulty, gameId) {
    const d = String(difficulty || "easy").toLowerCase();
    if (String(gameId) === "encryption_race") return 1;
    if (String(gameId) === "daily_cipher") return 3;
    if (String(gameId) === "crazy_mode") return 2;
    if (d === "easy") return 5;
    if (d === "medium") return 4;
    return 3;
  }

  // ---------------------------------------------------------------------------
  // Stats + rank bar
  // ---------------------------------------------------------------------------
  function getInit() {
    try {
      return (typeof window.__GAMES_INITIAL === "object" && window.__GAMES_INITIAL) ? window.__GAMES_INITIAL : {};
    } catch (_e) { return {}; }
  }
  function bootStats() {
    try {
      const GLOBAL_INIT = getInit();
      const stat = (GLOBAL_INIT && GLOBAL_INIT.stats) ? GLOBAL_INIT.stats : {};
      const xp = Number(stat.total_xp_earned || 0);
      const totalGames = Number(stat.total_games_played || 0);
      const winsTotal = Number(stat.wins_total || 0);
      const avgXp = (stat.average_xp_per_game != null) ? Number(stat.average_xp_per_game) : 0;
      const streak = Number(stat.daily_streak || 0);
      const acc = totalGames > 0 ? (Math.round(1000 * winsTotal / totalGames) / 10) : 0;
      setText("statTotalXP", xp);
      setText("statTotalGames", totalGames);
      setText("statWins", winsTotal);
      setText("statAvgXP", typeof avgXp === "number" ? (Math.round(avgXp * 10) / 10).toFixed(1).replace(/\.0$/, "") : "0");
      setText("statStreak", streak);
      setText("statAccuracy", acc + "%");

      const ranks = (GLOBAL_INIT && Array.isArray(GLOBAL_INIT.ranks)) ? GLOBAL_INIT.ranks.slice() : [];
      if (!ranks.length) return;
      let rank = ranks[0] || { name: "Novice", min_xp: 0, icon: "fa-seedling", title: "Code Apprentice" };
      let nextRank = null;
      for (let i = 0; i < ranks.length; i++) {
        try { if (xp >= Number(ranks[i].min_xp || 0)) rank = ranks[i]; else { nextRank = ranks[i]; break; } } catch (_e) {}
      }
      setText("statRankName", rank.name || "Novice");
      const prog = qs("rankProgressBar");
      const info = qs("rankProgressInfo");
      const nextName = qs("rankNextName");
      if (prog) { prog.style.width = (nextRank ? computeProgressWidth(rank, nextRank, xp) : "100") + "%"; }
      if (info) {
        info.textContent = nextRank
          ? (intoXp(rank, nextRank, xp) + " / " + (Math.max(0, Number(nextRank.min_xp || 0) - Number(rank.min_xp || 0)))) + " XP"
          : "MAX RANK ACHIEVED";
      }
      if (nextName) nextName.textContent = nextRank ? nextRank.name : rank.name;
    } catch (_outer) { /* NEVER let bootStats prevent button wiring */ console.warn("bootStats failed:", _outer); }
  }
  function computeProgressWidth(rank, nextRank, xp) {
    try {
      const span = Math.max(1, Number(nextRank.min_xp || 0) - Number(rank.min_xp || 0));
      const into = Math.max(0, Math.min(span, Number(xp || 0) - Number(rank.min_xp || 0)));
      return Math.max(0, Math.min(100, Math.round(100 * into / span)));
    } catch (_e) { return 0; }
  }
  function intoXp(rank, nextRank, xp) {
    try {
      const span = Math.max(1, Number(nextRank.min_xp || 0) - Number(rank.min_xp || 0));
      return Math.max(0, Math.min(span, Number(xp || 0) - Number(rank.min_xp || 0)));
    } catch (_e) { return 0; }
  }

  // ---------------------------------------------------------------------------
  // How-to-Play modal — triggered by (i) button on every game card
  // ---------------------------------------------------------------------------
  let _htpBootstrapModal = null;
  let _htpPendingGameId = null;
  function openHowToPlayModal(gameId) {
    try {
      if (!gameId) return;
      _htpPendingGameId = String(gameId);
      const INIT = getInit();
      const catalog = (INIT && Array.isArray(INIT.games)) ? INIT.games : [];
      const g = catalog.find(x => x && String(x.id) === String(gameId));
      const rulesEl = document.getElementById("htpRules");
      const exampleEl = document.getElementById("htpExample");
      const nameEl = document.getElementById("htpGameName");
      if (nameEl) nameEl.textContent = (g && g.name) ? String(g.name) : String(gameId);
      if (rulesEl) {
        const fallback = (g && g.long_description) ? String(g.long_description) : "No rules available for this game yet.";
        const rules = (g && g.how_to_play) ? String(g.how_to_play) : fallback;
        rulesEl.innerHTML = "";
        rulesEl.textContent = rules;
      }
      if (exampleEl) {
        const ex = (g && g.example) ? String(g.example) : (
          "Worked example not yet configured for " + String((g && g.name) || gameId) + ".\n" +
          "Click Play → a fresh challenge will be generated with algorithm badge, hints, and\n" +
          "automatic scoring. Every correct answer contributes XP and rank progress."
        );
        exampleEl.textContent = ex;
      }
      // Wire Play Now button
      const playBtn = document.getElementById("htpPlayNowBtn");
      if (playBtn) {
        playBtn.onclick = function htpPlayClick() {
          try {
            const diffSel = document.querySelector('.btn-diff-select.active[data-game-id="' + CSS.escape(String(_htpPendingGameId)) + '"]');
            const dfltDiff = (diffSel && diffSel.dataset && diffSel.dataset.diff) ? String(diffSel.dataset.diff) : "easy";
            const anyBtn = document.querySelector('.btn-play-game[data-game-id="' + CSS.escape(String(_htpPendingGameId)) + '"]');
            if (anyBtn) {
              try { (anyBtn.dataset || (anyBtn.dataset = {})).diff = dfltDiff; } catch (_e) {}
              anyBtn.click();
            } else {
              openRunner(String(_htpPendingGameId), dfltDiff);
            }
          } catch (_e) { console.warn("htp play-now failed:", _e); }
        };
      }
      // Open the BS5 modal
      const modalEl = document.getElementById("howToPlayModal");
      if (!modalEl) return;
      try {
        if (!_htpBootstrapModal || typeof bootstrap === "undefined") {
          if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
            _htpBootstrapModal = new bootstrap.Modal(modalEl, { backdrop: true, keyboard: true });
          } else {
            modalEl.classList.add("show");
            modalEl.style.display = "block";
            return;
          }
        }
        _htpBootstrapModal.show();
      } catch (_modalErr) { console.warn("htp modal show failed:", _modalErr); }
    } catch (_outer) { console.warn("openHowToPlayModal failed:", _outer); }
  }

  // ---------------------------------------------------------------------------
  // Global Leaderboard — render rows into #leaderboardTbody (PUBLIC, no auth)
  // ---------------------------------------------------------------------------
  function _fmtIN(n) {
    // Indian-notation number formatting (en-IN locale)
    try {
      const num = Number(n || 0);
      if (!isFinite(num)) return String(n || "0");
      try {
        if (typeof Intl !== "undefined" && Intl.NumberFormat) {
          return new Intl.NumberFormat("en-IN").format(num);
        }
      } catch (_i) {}
      return String(Math.round(num));
    } catch (_e) { return String(n || "0"); }
  }
  function _rankBadgeClass(rankName) {
    const r = String(rankName || "").toLowerCase();
    if (r.includes("legend") || r.includes("crypto legend") || r.includes("master")) return "warning";
    if (r.includes("expert") || r.includes("elite")) return "danger";
    if (r.includes("advance") || r.includes("senior")) return "info";
    if (r.includes("intermediate") || r.includes("apprentice")) return "primary";
    return "success";
  }
  function renderLeaderboard(rows) {
    try {
      const tbody = document.getElementById("leaderboardTbody");
      if (!tbody) return;
      const list = (Array.isArray(rows) ? rows.slice() : []).filter(Boolean);
      if (list.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="7" class="text-center py-4 text-light opacity-60">' +
          '<i class="fas fa-circle-info me-2"></i>No leaderboard data yet. ' +
          'Play a round to appear at the top!</td></tr>';
        return;
      }
      const frag = document.createDocumentFragment();
      list.forEach(function (row, idx) {
        const tr = document.createElement("tr");
        const rankNum = idx + 1;
        const isLocal = String(row.source || "").toLowerCase() === "local";
        // Row styling
        if (isLocal) tr.className = "table-warning";
        if (rankNum === 1) tr.classList.add("leaderboard-row-top1");
        else if (rankNum === 2) tr.classList.add("leaderboard-row-top2");
        else if (rankNum === 3) tr.classList.add("leaderboard-row-top3");

        // Col 1: rank number
        const tdRank = document.createElement("td");
        tdRank.className = "text-center px-3 py-3";
        const medal = (rankNum <= 3)
          ? ({ 1: "🥇", 2: "🥈", 3: "🥉" })[rankNum]
          : ("<span class=\"font-monospace text-light opacity-60\">#" + rankNum + "</span>");
        tdRank.innerHTML = medal;
        tr.appendChild(tdRank);

        // Col 2: player
        const tdName = document.createElement("td");
        tdName.className = "px-3 py-3";
        const adminBadge = (row.is_admin)
          ? ' <span class="badge bg-danger-subtle text-danger-emphasis border border-danger rounded-pill ms-1" style="font-size:0.6rem;">ADMIN</span>' : "";
        const localBadge = isLocal
          ? ' <span class="badge bg-warning-subtle text-warning-emphasis border border-warning rounded-pill ms-1" style="font-size:0.6rem;">THIS DEVICE</span>' : "";
        tdName.innerHTML = "<b class=\"text-white\">" + (String(row.display_name || "Anonymous").replace(/[<>]/g, "")) + "</b>" +
          (row.username ? '<br><small class="font-monospace text-light opacity-50">@' + String(row.username).replace(/[<>]/g, "") + "</small>" : "") +
          adminBadge + localBadge;
        tr.appendChild(tdName);

        // Col 3: rank badge
        const tdRk = document.createElement("td");
        tdRk.className = "px-3 py-3";
        const cls = _rankBadgeClass(row.rank);
        tdRk.innerHTML = '<span class="badge bg-' + cls + '-subtle border border-' + cls + ' text-' + cls + '-emphasis rounded-pill">' +
          String(row.rank || "Novice") + "</span>";
        tr.appendChild(tdRk);

        // Col 4: XP (right aligned, Indian formatting)
        const tdXP = document.createElement("td");
        tdXP.className = "text-end px-3 py-3";
        tdXP.innerHTML = "<b class=\"text-success font-monospace\">" + _fmtIN(row.xp || 0) + "</b>";
        tr.appendChild(tdXP);

        // Col 5: Wins (center)
        const tdWins = document.createElement("td");
        tdWins.className = "text-center px-3 py-3";
        tdWins.innerHTML = "<span class=\"font-monospace text-info\">" + _fmtIN(row.wins || 0) + "</span>";
        tr.appendChild(tdWins);

        // Col 6: Streak (center, flame color scale)
        const tdSt = document.createElement("td");
        tdSt.className = "text-center px-3 py-3";
        const stNum = Number(row.streak || 0);
        const stColor = stNum >= 7 ? "danger" : (stNum >= 3 ? "warning" : "primary");
        tdSt.innerHTML = '<span class="font-monospace text-' + stColor + '">' + _fmtIN(stNum) + "</span>";
        tr.appendChild(tdSt);

        // Col 7: Crazy best (center, danger if >0)
        const tdCM = document.createElement("td");
        tdCM.className = "text-center px-3 py-3";
        const cmNum = Number(row.crazy_best || 0);
        if (cmNum <= 0) {
          tdCM.innerHTML = '<span class="text-light opacity-30 small">—</span>';
        } else {
          tdCM.innerHTML =
            '<span class="badge bg-danger-subtle border border-danger text-danger-emphasis rounded-pill font-monospace" title="Crazy Mode Best Score">' +
            "☠️ " + _fmtIN(cmNum) + "</span>";
        }
        tr.appendChild(tdCM);

        frag.appendChild(tr);
      });
      tbody.innerHTML = "";
      tbody.appendChild(frag);
    } catch (_outer) { console.warn("renderLeaderboard failed:", _outer); }
  }
  async function refreshLeaderboard() {
    try {
      const tbody = document.getElementById("leaderboardTbody");
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-light opacity-60"><i class="fas fa-sync-alt fa-spin me-2"></i>Refreshing…</td></tr>';
      }
      const r = await fetch("/api/games/leaderboard?limit=20", { credentials: "same-origin" });
      const data = await r.json().catch(function () { return null; });
      if (data && data.success && Array.isArray(data.leaderboard)) {
        renderLeaderboard(data.leaderboard);
      } else if (data && !data.success) {
        throw new Error(data.error || "Leaderboard fetch failed");
      } else {
        // Fallback: use __GAMES_INITIAL.leaderboard if server fetch failed
        const INIT = getInit();
        if (INIT && Array.isArray(INIT.leaderboard)) renderLeaderboard(INIT.leaderboard);
        else throw new Error("Invalid leaderboard response");
      }
    } catch (_e) {
      // Last-ditch fallback: use initial SSR leaderboard
      try {
        const INIT = getInit();
        if (INIT && Array.isArray(INIT.leaderboard)) renderLeaderboard(INIT.leaderboard);
        else {
          const tbody = document.getElementById("leaderboardTbody");
          if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-light opacity-60"><i class="fas fa-triangle-exclamation me-2 text-warning"></i>' +
            'Could not load leaderboard: ' + String(_e.message || _e).replace(/[<>]/g, "") + "</td></tr>";
        }
      } catch (_f) {}
      console.warn("refreshLeaderboard failed:", _e);
    }
  }

  function pushServerStats(patch) {
    try {
      if (!patch || typeof patch !== "object") return;
      function merge(elOrId, newVal) {
        if (newVal == null) return;
        const el = (typeof elOrId === "string") ? qs(elOrId) : elOrId;
        if (!el) return;
        try { el.textContent = String(newVal); } catch (_e) {}
      }
      merge("statTotalXP", patch.total_xp_earned);
      merge("statTotalGames", patch.total_games_played);
      merge("statWins", patch.total_wins);
      if (patch.accuracy_pct != null) merge("statAccuracy", (Number(patch.accuracy_pct) || 0) + "%");
      merge("statStreak", patch.daily_streak);
      const xpN = Number(patch.total_xp_earned);
      const gamesN = Number(patch.total_games_played || 0);
      const avg = (gamesN > 0 && Number.isFinite(xpN)) ? (xpN / gamesN) : 0;
      const avgEl = qs("statAvgXP");
      if (avgEl) avgEl.textContent = (Math.round(avg * 10) / 10).toFixed(1).replace(/\.0$/, "") || "0";
      if (patch.rank && patch.rank.name) setText("statRankName", patch.rank.name);
    } catch (_e) {}
  }

  // ---------------------------------------------------------------------------
  // Event delegation fallback (ALWAYS WORKS — even if buttons render after init)
  // ---------------------------------------------------------------------------
  function wireDelegatedEvents() {
    try {
      if (document.body && !document.body.__gamesDelegatedBound) {
        document.body.__gamesDelegatedBound = true;
        document.body.addEventListener("click", function (ev) {
          try {
            const t = ev.target;
            if (!t || !t.closest) return;

            const diffBtn = t.closest(".btn-diff-select");
            if (diffBtn) {
              ev.preventDefault();
              const gid = diffBtn.getAttribute ? diffBtn.getAttribute("data-game-id") : null;
              const diff = diffBtn.getAttribute ? diffBtn.getAttribute("data-diff") : null;
              if (gid) {
                const sameSibs = document.querySelectorAll('.btn-diff-select[data-game-id="' + gid + '"]');
                sameSibs.forEach(function (b) { b.classList.remove("active"); });
                diffBtn.classList.add("active");
                const play = document.querySelector('.btn-play-game[data-game-id="' + gid + '"]');
                if (play && diff) play.setAttribute("data-diff", diff);
              }
              return;
            }

            const playBtn = t.closest(".btn-play-game");
            if (playBtn) {
              ev.preventDefault();
              const gid = playBtn.getAttribute ? playBtn.getAttribute("data-game-id") : null;
              const diff = (playBtn.getAttribute ? playBtn.getAttribute("data-diff") : null) || "easy";
              if (!gid) { toastMessage("Couldn't identify game", "error"); return; }
              openRunner(gid, String(diff).toLowerCase());
              return;
            }
          } catch (_e) { console.warn("Delegated click failed:", _e); }
        });
      }
    } catch (_outer) { console.warn("wireDelegatedEvents failed:", _outer); }
  }

  // ---------------------------------------------------------------------------
  // Wire: card difficulty selectors + Play buttons (robust — works re-entrant)
  // ---------------------------------------------------------------------------
  function wireDifficultyAndPlayButtons() {
    try {
      document.querySelectorAll(".btn-diff-select").forEach(function (btn) {
        try {
          const gid = btn.getAttribute && btn.getAttribute("data-game-id");
          if (!gid || btn.__gamesDiffBound) return;
          btn.__gamesDiffBound = true;
          btn.addEventListener("click", function (ev) {
            try {
              if (ev && typeof ev.stopPropagation === "function") ev.stopPropagation();
              const sameSibs = document.querySelectorAll('.btn-diff-select[data-game-id="' + gid + '"]');
              sameSibs.forEach(function (b) { b.classList.remove("active"); });
              btn.classList.add("active");
              const play = document.querySelector('.btn-play-game[data-game-id="' + gid + '"]');
              if (play) {
                const diff = btn.getAttribute && btn.getAttribute("data-diff");
                if (diff) play.setAttribute("data-diff", diff);
              }
            } catch (_e) { /* per click */ }
          });
          const first = document.querySelectorAll('.btn-diff-select[data-game-id="' + gid + '"]')[0];
          if (first === btn && !first.classList.contains("active")) first.classList.add("active");
        } catch (_e) { /* per button */ }
      });

      document.querySelectorAll(".btn-play-game").forEach(function (btn) {
        try {
          if (btn.__gamesPlayBound) return;
          btn.__gamesPlayBound = true;
          btn.addEventListener("click", function (ev) {
            try {
              if (ev && typeof ev.stopPropagation === "function") ev.stopPropagation();
              const gid = btn.getAttribute ? btn.getAttribute("data-game-id") : null;
              const diff = (btn.getAttribute ? btn.getAttribute("data-diff") : null) || "easy";
              if (!gid) { toastMessage("Couldn't identify game", "error"); return; }
              openRunner(gid, String(diff).toLowerCase());
            } catch (inner) { console.error("Play click failed:", inner); toastMessage("Couldn't open game: " + inner.message, "error"); }
          });
        } catch (_e) { /* per button */ }
      });
    } catch (_outer) { console.warn("wireDifficultyAndPlayButtons failed:", _outer); }
  }

  function wireRunnerFooterButtons() {
    try {
      const hintBtn = qs("btnRevealHint");
      if (hintBtn && !hintBtn.__gamesBoundReveal) {
        hintBtn.__gamesBoundReveal = true;
        hintBtn.addEventListener("click", function () {
          try {
            const list = qs("runnerHintList");
            if (!list) return;
            const items = list.querySelectorAll("li");
            for (let i = 0; i < items.length; i++) {
              try {
                if (items[i].getAttribute("data-revealed") === "1") continue;
                const txt = items[i].getAttribute("data-hint") || "";
                if (!txt) continue;
                items[i].textContent = txt;
                items[i].style.color = "#fef3c7";
                items[i].setAttribute("data-revealed", "1");
                state.hintsUsed += 1;
                renderHints();
                return;
              } catch (_e) { /* per item */ }
            }
            try { hintBtn.disabled = true; } catch (_e) {}
          } catch (_outer) { console.warn(_outer); }
        });
      }
      const retry = qs("btnRetryGame");
      if (retry && !retry.__gamesBoundRetry) {
        retry.__gamesBoundRetry = true;
        retry.addEventListener("click", function () { try { openRunner(state.gameId || "crack_cipher", state.difficulty || "easy"); } catch (_e) {} });
      }
      const next = qs("btnNextGame");
      if (next && !next.__gamesBoundNext) {
        next.__gamesBoundNext = true;
        next.addEventListener("click", function () { try { openRunner(state.gameId || "crack_cipher", state.difficulty || "easy"); } catch (_e) {} });
      }
    } catch (_outer) { console.warn("wireRunnerFooterButtons failed:", _outer); }
  }

  // ---------------------------------------------------------------------------
  // Open runner -> fetch level -> beginChallenge
  // ---------------------------------------------------------------------------
  function openRunner(gameId, difficulty) {
    try {
      if (!gameId) { toastMessage("Missing game id", "error"); return; }
      state.gameId = String(gameId);
      state.difficulty = String(difficulty || "easy").toLowerCase();
      state.finished = false;
      state.answered = false;
      state.attempts = 0;
      state.maxAttempts = Infinity;
      state.hintsUsed = 0;
      state.hints = [];
      state.score = 0;
      state.lives = livesFor(state.difficulty, state.gameId);
      state.crazyQuestionIndex = 0;
      state.crazyTotalQuestions = 5;
      state.crazyTotalCorrect = 0;
      state.crazySessionComplete = false;

      // Reset quit button to normal label (Done & Dusted overwritten later if applicable)
      try {
        var qbtn = qs("btnQuitGame");
        if (qbtn) {
          qbtn.innerHTML = '<i class="fas fa-door-open me-1"></i>Quit';
          qbtn.classList.remove("btn-success", "btn-outline-danger");
          qbtn.classList.add("btn-outline-secondary");
        }
      } catch (_e) {}

      const INIT = getInit();
      const catalog = (INIT && Array.isArray(INIT.games)) ? INIT.games : [];
      const meta = (catalog.find(function (g) { return g && g.id === state.gameId; })) || { name: state.gameId };
      setText("runnerGameName", meta.name || state.gameId);
      const diffBadge = qs("runnerGameDiff");
      if (diffBadge) {
        if (state.gameId === "daily_cipher") {
          const dn = (INIT && INIT.daily && INIT.daily.daily_number) ? INIT.daily.daily_number : "";
          diffBadge.textContent = "Daily" + (dn ? (" #" + dn) : "");
        } else {
          diffBadge.textContent = (state.difficulty || "play").toUpperCase();
        }
      }
      setText("runnerFooterMsg", "Loading level…");
      try { qs("btnRetryGame").classList.add("d-none"); } catch (_e) {}

      // Reset visual state
      hideEl("runnerResultCard");
      removeClass("runnerResultCard", "success failure");
      const resultBody = qs("runnerResultBody"); if (resultBody) resultBody.innerHTML = "";
      hideEl("runnerHintsCard");
      const hl = qs("runnerHintList"); if (hl) hl.innerHTML = "";
      hideEl("runnerAlgoBadge");
      hideEl("runnerTargetInfo");

      setStage(1);
      renderLives(); renderHints(); renderScore(); renderTimer();

      const modalEl = document.getElementById("gameRunnerModal");
      if (!modalEl) { toastMessage("Couldn't find game runner modal in DOM", "error"); return; }
      openBootstrapModal(modalEl);

      const seed = Math.floor(Math.random() * 1e9);
      let url = "/api/games/level/" + encodeURIComponent(state.gameId) + "?seed=" + seed;
      if (!["daily_cipher", "encryption_race", "find_vulnerability"].includes(state.gameId)) {
        url += "&difficulty=" + encodeURIComponent(state.difficulty);
      }
      fetch(url, { credentials: "same-origin" })
        .then(function (r) { try { return r.json(); } catch (_e) { return { success: false, error: "Invalid server response" }; } })
        .then(function (data) {
          try {
            if (!data || !data.success) throw new Error((data && data.error) ? data.error : "Failed to load level");
            state.level = data.level || {};
            beginChallenge();
          } catch (e) {
            console.error("beginChallenge failed:", e);
            setText("runnerFooterMsg", "Error starting game: " + e.message);
            const ct = qs("runnerCiphertext"); if (ct) ct.textContent = e.message;
            toastMessage("Error starting game: " + e.message, "error");
          }
        })
        .catch(function (err) {
          console.error("fetch level failed:", err);
          setText("runnerFooterMsg", "Network error: " + err.message);
          const ct = qs("runnerCiphertext"); if (ct) ct.textContent = err.message;
          toastMessage("Couldn't load level from server", "error");
        });
    } catch (_outer) {
      console.error("openRunner failed:", _outer);
      toastMessage("Couldn't open game: " + _outer.message, "error");
    }
  }

  // ---------------------------------------------------------------------------
  // beginChallenge -> fills prompt + badges + answer slot
  // ---------------------------------------------------------------------------
  function beginChallenge() {
    try {
      const lvl = state.level || {};
      setStage(2);
      if (Array.isArray(lvl.hints)) state.hints = lvl.hints.slice();

      const tl = timeLimitFor(state.difficulty, state.gameId);
      setTimer(tl);

      if (Number.isFinite(Number(lvl.max_attempts)) && Number(lvl.max_attempts) > 0) {
        state.maxAttempts = Number(lvl.max_attempts);
      }

      // Badges: algo + target
      const algoBadge = qs("runnerAlgoBadge");
      if (algoBadge && lvl.algo) {
        algoBadge.textContent = String(lvl.algo);
        algoBadge.classList.remove("d-none");
      }
      const targetInfo = qs("runnerTargetInfo");
      if (targetInfo) {
        let txt = "";
        if (state.gameId === "brute_force") {
          txt = "Len=" + lvl.target_password_length + " · " + lvl.character_space + " · Max " + state.maxAttempts + " guesses";
        } else if (state.gameId === "key_guessing" && lvl.public_key) {
          txt = "n=" + lvl.public_key.n + ", e=" + lvl.public_key.e;
        } else if (state.gameId === "hash_detective" && lvl.hash) {
          txt = "hash length " + String(lvl.hash).length + " hex chars";
        } else if (state.gameId === "encryption_race") {
          txt = "Payload " + lvl.payload_bytes + " bytes";
        }
        if (txt) {
          targetInfo.textContent = txt;
          targetInfo.classList.remove("d-none");
        }
      }

      // Prompt text + ciphertext
      const code = qs("runnerCode"); if (code) code.innerHTML = "";
      const ct = qs("runnerCiphertext");
      if (ct) {
        ct.textContent = "";
        try { ct.style.whiteSpace = "pre-wrap"; ct.removeAttribute("style"); } catch (_e) {}
      }
      fillGamePrompt(code, ct, state.gameId, lvl);

      // Hints list
      const hintsCard = qs("runnerHintsCard");
      if (state.hints.length > 0 && hintsCard) {
        hintsCard.classList.remove("d-none");
        const list = qs("runnerHintList");
        if (list) {
          list.innerHTML = "";
          state.hints.forEach(function (h) {
            try {
              const li = document.createElement("li");
              li.textContent = "?????";
              li.setAttribute("data-hint", String(h));
              li.style.color = "rgba(148,163,184,0.55)";
              list.appendChild(li);
            } catch (_e) {}
          });
        }
        try { qs("btnRevealHint").disabled = false; } catch (_e) {}
      }

      // Answer slot
      const slot = qs("runnerAnswerSlot");
      if (slot) {
        slot.innerHTML = "";
        buildAnswerSlot(slot, state.gameId, lvl);
      }

      setStage(3);
      setText("runnerFooterMsg", "Good luck! Submit your answer when ready.");
    } catch (_outer) { console.error("beginChallenge failed:", _outer); toastMessage("Error loading game challenge: " + _outer.message, "error"); }
  }

  function fillGamePrompt(code, ct, gameId, lvl) {
    try {
      gameId = String(gameId || "");
      switch (gameId) {
        case "crack_cipher":
          if (code) code.innerHTML = '<p class="mb-2"><b class="text-warning">Mission:</b> Decrypt the ciphertext below using the scheme described in the badge. Type the recovered plaintext.</p>';
          if (ct) ct.textContent = String(lvl.ciphertext || "");
          break;
        case "guess_cipher":
          if (code) code.innerHTML = '<p class="mb-2"><b class="text-warning">Mission:</b> Identify which cipher produced the ciphertext. Do not worry about decrypting — just choose the correct scheme.</p>';
          if (ct) ct.textContent = String(lvl.ciphertext || "");
          break;
        case "brute_force":
          if (code) code.innerHTML =
            `<p class="mb-2"><b class="text-warning">Mission:</b> A weak demo password was chosen. Guess it within <b>${state.maxAttempts}</b> attempts — correct characters will highlight green, wrong ones red.</p>`;
          if (ct) ct.textContent = "PASSWORD LENGTH: " + lvl.target_password_length + "   [HIDDEN " + "*".repeat(Number(lvl.target_password_length || 0)) + "]";
          break;
        case "cipher_puzzle":
          if (code) {
            const cluesHtml = Array.isArray(lvl.clues)
              ? lvl.clues.map(function (c) { return `<li class="text-light mb-1">${escapeHtml(c)}</li>`; }).join("")
              : "";
            code.innerHTML = `<p class="mb-2"><b class="text-warning">Clues:</b></p><ul class="mb-0">${cluesHtml}</ul>`;
          }
          if (ct) ct.textContent = String(lvl.ciphertext || "");
          break;
        case "key_guessing":
          if (code) code.innerHTML = `<p class="mb-2"><b class="text-warning">Toy RSA factoring demo.</b> Given n and e, find one prime factor (p or q). Optional: also recover the demo plaintext integer.</p>` +
            `<p class="mb-0 small text-light opacity-75">Real RSA uses 2048-bit n = ~617-digit primes. These are tiny (4-8 bit) so factoring by hand is possible.</p>`;
          if (ct) ct.textContent =
            "PUBLIC KEY:  n = " + (lvl.public_key ? lvl.public_key.n : "?") +
            ",   e = " + (lvl.public_key ? lvl.public_key.e : "?") + "\n" +
            "CIPHERTEXT (integer): " + (lvl.ciphertext_integer != null ? lvl.ciphertext_integer : "?") + "   = plaintext^e mod n";
          break;
        case "hash_detective":
          if (code) code.innerHTML = `<p class="mb-2"><b class="text-warning">Two steps:</b> (1) Identify the algorithm from the hash; (2) crack the preimage from a tiny educational rainbow table.</p>` +
            `<p class="mb-0 small text-light opacity-75">Heuristics: 32 hex = MD5, 40 = SHA-1, 64 = SHA-256, 128 = SHA-512.</p>`;
          if (ct) ct.textContent = String(lvl.hash || "");
          break;
        case "encryption_race":
          if (code) code.innerHTML = `<p class="mb-2"><b class="text-warning">Prediction!</b> Which primitive finishes encrypting/signing a <b>${lvl.payload_bytes}</b>-byte payload first?</p>` +
            `<p class="mb-0 small text-light opacity-75">Uses realistic orders of magnitude for teaching. No heavy compute runs locally.</p>`;
          if (ct) ct.textContent = "A) " + (lvl.candidate_a || "") + "\nB) " + (lvl.candidate_b || "");
          break;
        case "find_vulnerability":
          if (code) code.innerHTML =
            `<p class="mb-2"><b class="text-warning">${escapeHtml(lvl.title || "")}</b> ` +
            `<span class="badge bg-danger-subtle border border-danger text-danger-emphasis rounded-pill">Severity: ${escapeHtml(lvl.severity || "")}</span> ` +
            `<span class="badge bg-info-subtle border border-info text-info-emphasis rounded-pill">${escapeHtml(lvl.cwe || "")}</span></p>` +
            `<p class="mb-0 small text-light opacity-75">Pick the correct technical explanation of the crypto flaw.</p>`;
          if (ct) {
            ct.style.whiteSpace = "pre";
            ct.className = "text-warning mt-3 mb-0 p-3 rounded bg-black-75 border border-danger";
            ct.textContent = String(lvl.code || "");
          }
          break;
        case "daily_cipher":
          if (code) code.innerHTML = `<p class="mb-2"><b class="text-warning">Daily Cipher #${escapeHtml(lvl.daily_number || "")}</b> · ${escapeHtml(lvl.date || "")} · difficulty: <b>${escapeHtml((lvl.difficulty || "").toUpperCase())}</b>` +
            ` · Bonus <span class="text-success">+15 XP</span> today.</p>` +
            `<p class="mb-0 small text-light opacity-75">Cipher scheme: <b>${escapeHtml(lvl.algo || "")}</b></p>`;
          if (ct) ct.textContent = String(lvl.ciphertext || "");
          break;
        case "crazy_mode":
          if (code) {
            const qn = lvl.question_number || "?";
            const mx = lvl.max_questions || "?";
            const catBadge = lvl.category
              ? `<span class="badge bg-danger-subtle border border-danger text-danger-emphasis rounded-pill ms-2">${escapeHtml(lvl.category.toUpperCase())}</span>`
              : "";
            code.innerHTML =
              `<p class="mb-2">` +
                `<span class="badge bg-danger border border-danger text-white rounded-pill px-3 py-2 fs-6">🔥 CRAZY MODE 🔥 — Question ${escapeHtml(qn)} / ${escapeHtml(mx)}</span>` +
                catBadge +
              `</p>` +
              `<p class="mb-3 text-light">` +
                `<b class="text-danger">RULES:</b> 2 wrong → <span class="text-danger fw-bold">HORRIFIC CRASH</span>. All correct → <span class="text-warning fw-bold">TRUMPET CONGRATULATIONS + LIGHT SHOW!</span> 5 MINUTES PER QUESTION. NO HINTS. YOU HAVE BEEN WARNED.` +
              `</p>` +
              `<p class="mb-0"><b class="text-warning">QUESTION:</b></p>`;
          }
          if (ct) {
            ct.style.whiteSpace = "pre-wrap";
            ct.className = "text-warning mt-2 mb-0 p-4 rounded bg-gradient-red border border-danger font-lg-1";
            ct.textContent = String(lvl.question || "");
          }
          break;
        default:
          if (ct) ct.textContent = JSON.stringify(lvl, null, 2);
      }
    } catch (_outer) { console.warn("fillGamePrompt failed:", _outer); }
  }

  // ===========================================================================
  // CRAZY MODE — audio synthesis (no external files) + crash/victory FX
  // ===========================================================================
  var _crazyAudioCtx = null;
  function crazyEnsureAudio() {
    try {
      if (_crazyAudioCtx) return _crazyAudioCtx;
      var AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      _crazyAudioCtx = new AC();
      return _crazyAudioCtx;
    } catch (_e) { return null; }
  }
  function crazyPlayHorrorCrash() {
    try {
      var ctx = crazyEnsureAudio();
      if (!ctx) return;
      if (ctx.state === "suspended") try { ctx.resume(); } catch (_e) {}
      var now = ctx.currentTime;
      var dur = 3.6;

      // =============================================================
      // INDIAN HORROR LAYER — bansuri, dholak dread, ghungroo dread
      // =============================================================

      // 1) BANSURI (bamboo flute) dissonant eerie wails (double-layered)
      for (var bans = 0; bans < 2; bans++) {
        (function (idx) {
          var b = ctx.createOscillator();
          var bg = ctx.createGain();
          var bf = ctx.createBiquadFilter();
          bf.type = "bandpass"; bf.frequency.value = 1400 + idx * 200; bf.Q.value = 7;
          b.type = "sine";  // clean bansuri base with vibrato
          b.frequency.setValueAtTime(260 + idx * 80, now);
          b.frequency.exponentialRampToValueAtTime(900 + idx * 120, now + 0.8);
          b.frequency.exponentialRampToValueAtTime(140 + idx * 50, now + dur);
          // bansuri 3.5-5 Hz slow wobble = eerie
          try {
            var vib = ctx.createOscillator();
            var vg = ctx.createGain();
            vib.frequency.value = 3.5 + idx * 1.5;
            vg.gain.value = 18;
            vib.connect(vg); vg.connect(b.frequency);
            vib.start(now); vib.stop(now + dur);
          } catch (_v) {}
          bg.gain.setValueAtTime(0.0001, now);
          bg.gain.exponentialRampToValueAtTime(0.22 / (idx + 1), now + 0.08);
          bg.gain.exponentialRampToValueAtTime(0.0001, now + dur);
          b.connect(bf); bf.connect(bg); bg.connect(ctx.destination);
          b.start(now); b.stop(now + dur + 0.05);
        })(bans);
      }

      // 2) Siren / dissonant scream oscillator trio
      for (var i = 0; i < 3; i++) {
        (function (idx) {
          var o = ctx.createOscillator();
          var g = ctx.createGain();
          var f = ctx.createBiquadFilter();
          f.type = "bandpass"; f.frequency.value = 1000; f.Q.value = 5;
          o.type = idx === 0 ? "sawtooth" : (idx === 1 ? "square" : "triangle");
          o.frequency.setValueAtTime(idx === 0 ? 180 : (idx === 1 ? 320 : 540), now);
          o.frequency.exponentialRampToValueAtTime(idx === 0 ? 900 : (idx === 1 ? 1300 : 180), now + 0.6);
          o.frequency.exponentialRampToValueAtTime(idx === 0 ? 120 : (idx === 1 ? 220 : 80), now + dur);
          g.gain.setValueAtTime(0.0001, now);
          g.gain.exponentialRampToValueAtTime(0.35 / (idx + 1), now + 0.05);
          g.gain.exponentialRampToValueAtTime(0.0001, now + dur);
          o.connect(f); f.connect(g); g.connect(ctx.destination);
          o.start(now);
          o.stop(now + dur + 0.1);
        })(i);
      }

      // 3) DHOLAK / DAMARU deep dread thuds (matra-style accents at 5 points)
      try {
        var dholPats = [0.0, 0.55, 1.2, 2.0, 2.75];
        for (var dp = 0; dp < dholPats.length; dp++) {
          (function (dIdx) {
            var t = now + dholPats[dIdx];
            var drum = ctx.createOscillator();
            var dg = ctx.createGain();
            var dFilt = ctx.createBiquadFilter();
            dFilt.type = "lowpass"; dFilt.frequency.value = 420; dFilt.Q.value = 2;
            drum.type = "sine";
            drum.frequency.setValueAtTime(140, t);
            drum.frequency.exponentialRampToValueAtTime(48, t + 0.18);
            dg.gain.setValueAtTime(0.0001, t);
            dg.gain.exponentialRampToValueAtTime(dIdx === 0 ? 0.85 : 0.55, t + 0.008);
            dg.gain.exponentialRampToValueAtTime(0.0001, t + 0.22);
            drum.connect(dFilt); dFilt.connect(dg); dg.connect(ctx.destination);
            drum.start(t); drum.stop(t + 0.25);
          })(dp);
        }
      } catch (_dholErr) {}

      // 4) GHUNGROO (anklet bells) horror jingle cluster (high freq metal dread)
      try {
        var bellBufferSize = Math.floor(ctx.sampleRate * 1.8);
        var bellBuf = ctx.createBuffer(1, bellBufferSize, ctx.sampleRate);
        var bellData = bellBuf.getChannelData(0);
        for (var bj = 0; bj < bellBufferSize; bj++) {
          var env = Math.max(0, 1 - bj / bellBufferSize);
          var ping = (Math.random() < 0.012) ? ((Math.random() * 2 - 1) * 0.9) : 0;
          bellData[bj] = ping * env;
        }
        var bellSrc = ctx.createBufferSource();
        bellSrc.buffer = bellBuf;
        var bellGain = ctx.createGain();
        bellGain.gain.setValueAtTime(0.35, now + 0.1);
        bellGain.gain.exponentialRampToValueAtTime(0.0001, now + 1.9);
        var bellFilt = ctx.createBiquadFilter();
        bellFilt.type = "highpass"; bellFilt.frequency.value = 4000;
        bellSrc.connect(bellFilt); bellFilt.connect(bellGain); bellGain.connect(ctx.destination);
        bellSrc.start(now + 0.08); bellSrc.stop(now + 2.0);
      } catch (_ghung) {}

      // 5) Static noise burst (hissing horror)
      try {
        var bufferSize = Math.floor(ctx.sampleRate * dur);
        var noiseBuffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
        var data = noiseBuffer.getChannelData(0);
        for (var j = 0; j < bufferSize; j++) {
          data[j] = (Math.random() * 2 - 1) * (1 - j / bufferSize);
        }
        var noise = ctx.createBufferSource();
        noise.buffer = noiseBuffer;
        var nGain = ctx.createGain();
        nGain.gain.setValueAtTime(0.4, now);
        nGain.gain.exponentialRampToValueAtTime(0.0001, now + dur);
        var nFilt = ctx.createBiquadFilter();
        nFilt.type = "highpass"; nFilt.frequency.value = 2000;
        noise.connect(nFilt); nFilt.connect(nGain); nGain.connect(ctx.destination);
        noise.start(now);
        noise.stop(now + dur);
      } catch (_e1) {}

      // 6) Deep sub-bass crash thump
      try {
        var bass = ctx.createOscillator();
        var bg = ctx.createGain();
        bass.type = "sine";
        bass.frequency.setValueAtTime(80, now);
        bass.frequency.exponentialRampToValueAtTime(30, now + 1.2);
        bg.gain.setValueAtTime(0.0001, now);
        bg.gain.exponentialRampToValueAtTime(0.9, now + 0.02);
        bg.gain.exponentialRampToValueAtTime(0.0001, now + 2.5);
        bass.connect(bg); bg.connect(ctx.destination);
        bass.start(now); bass.stop(now + 2.6);
      } catch (_e2) {}

      // 7) Periodic clang every 0.6s
      try {
        for (var k = 0; k < 5; k++) {
          var t0 = now + k * 0.6;
          var cl = ctx.createOscillator();
          var cg = ctx.createGain();
          cl.type = "square";
          cl.frequency.setValueAtTime(80 + Math.random() * 200, t0);
          cg.gain.setValueAtTime(0.0001, t0);
          cg.gain.exponentialRampToValueAtTime(0.25, t0 + 0.005);
          cg.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.3);
          cl.connect(cg); cg.connect(ctx.destination);
          cl.start(t0); cl.stop(t0 + 0.32);
        }
      } catch (_e3) {}
    } catch (_outer) { console.warn("horror crash audio failed", _outer); }
  }
  function crazyPlayTrumpetVictory() {
    try {
      var ctx = crazyEnsureAudio();
      if (!ctx) return;
      if (ctx.state === "suspended") try { ctx.resume(); } catch (_e) {}
      var now = ctx.currentTime;

      // =============================================================
      // INDIAN CELEBRATION LAYER — shehnai, tabla bols, manjira, nagada
      // =============================================================

      // 1) SHEHNAI (double-reed wedding blessing) — raga Yaman style phrase
      //    Ni-Re-Ga-Ma#-Pa-Dha-Ni-Sa'  (raga Yaman Ni = N4, Re = R2, Ga=G2, Ma=MA, Pa=P, Dha=D2, Ni=N4)
      var shehnaiNotes = [
        // Opening blessing: Ni Dha Ni Sa' (slow)
        { f: 493.88, t: 0.0,  d: 0.25, g: 0.28 },  // Ni4  B4
        { f: 587.33, t: 0.28, d: 0.22, g: 0.28 },  // Re5  D5
        { f: 659.25, t: 0.52, d: 0.22, g: 0.30 },  // Ga5  E5
        { f: 740.00, t: 0.76, d: 0.25, g: 0.32 },  // Ma#5 F#5 (teevra ma — Yaman signature)
        // Climax climb to high Sa'
        { f: 659.25, t: 1.05, d: 0.18, g: 0.34 },  // Ga
        { f: 740.00, t: 1.25, d: 0.18, g: 0.36 },  // Ma#
        { f: 783.99, t: 1.45, d: 0.22, g: 0.38 },  // Pa5  G5
        { f: 880.00, t: 1.69, d: 0.25, g: 0.40 },  // Dha5 A5
        { f: 987.77, t: 1.96, d: 0.3,  g: 0.42 },  // Ni5  B5
        { f: 1046.50,t: 2.28, d: 0.9,  g: 0.52 },  // Sa'6 C6 — BIG FINAL BLESSING HOLD
      ];
      shehnaiNotes.forEach(function (n) {
        var o = ctx.createOscillator();
        var g = ctx.createGain();
        var f = ctx.createBiquadFilter();
        // shehnai: bandpass + soft clipping for double-reed timbre
        f.type = "bandpass"; f.frequency.value = 1750; f.Q.value = 4.5;
        o.type = "sawtooth";  // rich harmonics for shehnai sound
        o.frequency.setValueAtTime(n.f, now + n.t);
        // 7.5 Hz fast vibrato (characteristic shehnai wobble)
        try {
          var sc = ctx.createOscillator();
          var sg = ctx.createGain();
          sc.frequency.value = 7.5;
          sg.gain.value = n.f * 0.022;
          sc.connect(sg); sg.connect(o.frequency);
          sc.start(now + n.t); sc.stop(now + n.t + n.d);
        } catch (_v2) {}
        g.gain.setValueAtTime(0.0001, now + n.t);
        g.gain.exponentialRampToValueAtTime(n.g, now + n.t + 0.035);  // tongued attack
        g.gain.exponentialRampToValueAtTime(0.0001, now + n.t + n.d);
        o.connect(f); f.connect(g); g.connect(ctx.destination);
        o.start(now + n.t); o.stop(now + n.t + 0.02);
      });

      // 2) TABLA BOLS — tintal-style 8-matra theka pattern (21 bols)
      //    Na = treble (dayan), Ta = mid, Tin = closed treble, Dha = bass (bayan)+treble
      var TABLA_PATS = [
        {t:0.08,g:0.55,f:380,dur:0.06,type:"Na"},
        {t:0.20,g:0.45,f:320,dur:0.05,type:"Tin"},
        {t:0.32,g:0.70,f:120,dur:0.08,type:"Dha"},
        {t:0.46,g:0.50,f:360,dur:0.05,type:"Na"},
        {t:0.58,g:0.45,f:290,dur:0.05,type:"Ta"},
        {t:0.70,g:0.75,f:110,dur:0.09,type:"Dha"},
        {t:0.84,g:0.55,f:370,dur:0.05,type:"Na"},
        {t:0.96,g:0.50,f:310,dur:0.05,type:"Tin"},
        {t:1.08,g:0.70,f:120,dur:0.08,type:"Dha"},
        {t:1.22,g:0.55,f:360,dur:0.05,type:"Na"},
        {t:1.34,g:0.85,f:105,dur:0.10,type:"Dha"},
        {t:1.50,g:0.75,f:115,dur:0.09,type:"Dha"},
        // Sam (1st beat return — BIG emphasis)
        {t:1.68,g:0.90,f:100,dur:0.12,type:"Dha"},
        {t:1.88,g:0.60,f:380,dur:0.06,type:"Na"},
        {t:2.00,g:0.55,f:320,dur:0.05,type:"Tin"},
        {t:2.12,g:0.85,f:110,dur:0.10,type:"Dha"},
        // Celebration fast dhir-dhir run
        {t:2.30,g:0.50,f:340,dur:0.04,type:"Na"},
        {t:2.38,g:0.45,f:300,dur:0.04,type:"Tin"},
        {t:2.46,g:0.50,f:340,dur:0.04,type:"Na"},
        {t:2.54,g:0.45,f:300,dur:0.04,type:"Tin"},
        {t:2.62,g:0.55,f:340,dur:0.04,type:"Na"},
        {t:2.70,g:0.50,f:300,dur:0.04,type:"Tin"},
      ];
      try {
        TABLA_PATS.forEach(function (bp) {
          var to = ctx.createOscillator();
          var tg = ctx.createGain();
          var tf = ctx.createBiquadFilter();
          var startT = now + bp.t;
          tf.type = (bp.type === "Dha") ? "lowpass" : "bandpass";
          tf.frequency.value = (bp.type === "Dha") ? 650 : 1400;
          tf.Q.value = (bp.type === "Dha") ? 1.8 : 6;
          to.type = (bp.type === "Dha") ? "sine" : "triangle";
          to.frequency.setValueAtTime(bp.f, startT);
          to.frequency.exponentialRampToValueAtTime(bp.f * (bp.type === "Dha" ? 0.45 : 0.75), startT + bp.dur);
          tg.gain.setValueAtTime(0.0001, startT);
          tg.gain.exponentialRampToValueAtTime(bp.g, startT + 0.004);
          tg.gain.exponentialRampToValueAtTime(0.0001, startT + bp.dur);
          to.connect(tf); tf.connect(tg); tg.connect(ctx.destination);
          to.start(startT); to.stop(startT + bp.dur + 0.01);
        });
      } catch (_tabla) {}

      // 3) MANJIRA (tiny hand-cymbals) tinkle accents at 6 points
      try {
        var manjTs = [0.08, 0.58, 1.08, 1.68, 2.12, 2.62];
        manjTs.forEach(function (mt) {
          var mj = ctx.createOscillator();
          var mg = ctx.createGain();
          var mf = ctx.createBiquadFilter();
          mf.type = "highpass"; mf.frequency.value = 6000; mf.Q.value = 3;
          mj.type = "triangle";
          mj.frequency.setValueAtTime(6600 + Math.random() * 1200, now + mt);
          mg.gain.setValueAtTime(0.0001, now + mt);
          mg.gain.exponentialRampToValueAtTime(0.18, now + mt + 0.003);
          mg.gain.exponentialRampToValueAtTime(0.0001, now + mt + 0.08);
          mj.connect(mf); mf.connect(mg); mg.connect(ctx.destination);
          mj.start(now + mt); mj.stop(now + mt + 0.1);
        });
      } catch (_manj) {}

      // 4) Trumpet fanfare layer (C5 → E5 → G5 → C6 triumphant)
      var notes = [
        { f: 523.25, t: 0.0,  d: 0.25, g: 0.35 }, // C5
        { f: 659.25, t: 0.3,  d: 0.25, g: 0.35 }, // E5
        { f: 783.99, t: 0.6,  d: 0.25, g: 0.35 }, // G5
        { f: 1046.50,t: 0.9,  d: 0.7,  g: 0.45 }, // C6 hold
        { f: 783.99, t: 1.7,  d: 0.2,  g: 0.3 },  // G5
        { f: 1046.50,t: 1.95, d: 0.8,  g: 0.55 }, // C6 big finish
      ];
      notes.forEach(function (n) {
        var o = ctx.createOscillator();
        var g = ctx.createGain();
        var f = ctx.createBiquadFilter();
        f.type = "lowpass"; f.frequency.value = 2200; f.Q.value = 3;
        o.type = "triangle";
        o.frequency.setValueAtTime(n.f, now + n.t);
        g.gain.setValueAtTime(0.0001, now + n.t);
        g.gain.exponentialRampToValueAtTime(n.g, now + n.t + 0.03);
        g.gain.exponentialRampToValueAtTime(0.0001, now + n.t + n.d);
        // Brass vibrato
        try {
          var lfo = ctx.createOscillator();
          var lfoGain = ctx.createGain();
          lfo.frequency.value = 5;
          lfoGain.gain.value = n.f * 0.015;
          lfo.connect(lfoGain); lfoGain.connect(o.frequency);
          lfo.start(now + n.t); lfo.stop(now + n.t + n.d);
        } catch (_e) {}
        o.connect(f); f.connect(g); g.connect(ctx.destination);
        o.start(now + n.t); o.stop(now + n.t + 0.02);
      });

      // 5) Timpani thump on fanfare start
      try {
        var timp = ctx.createOscillator();
        var tg = ctx.createGain();
        timp.type = "sine"; timp.frequency.setValueAtTime(120, now);
        timp.frequency.exponentialRampToValueAtTime(60, now + 0.4);
        tg.gain.setValueAtTime(0.0001, now);
        tg.gain.exponentialRampToValueAtTime(0.5, now + 0.01);
        tg.gain.exponentialRampToValueAtTime(0.0001, now + 0.5);
        timp.connect(tg); tg.connect(ctx.destination);
        timp.start(now); timp.stop(now + 0.55);
      } catch (_e) {}

      // 6) Sparkle high synths on top (18 sparkles)
      try {
        for (var s = 0; s < 18; s++) {
          var st = now + 0.2 + s * 0.11;
          var so = ctx.createOscillator();
          var sg = ctx.createGain();
          so.type = "sine";
          so.frequency.value = 1600 + Math.random() * 3500;
          sg.gain.setValueAtTime(0.0001, st);
          sg.gain.exponentialRampToValueAtTime(0.08, st + 0.01);
          sg.gain.exponentialRampToValueAtTime(0.0001, st + 0.2);
          so.connect(sg); sg.connect(ctx.destination);
          so.start(st); so.stop(st + 0.22);
        }
      } catch (_e) {}

      // 7) NAGADA DHOLKI drum-roll crescendo (28 accelerating rolls to climax)
      try {
        var rollEnd = now + 3.0;
        var rollStart = now + 2.20;
        var steps = 28;
        for (var ri = 0; ri < steps; ri++) {
          (function (rIdx) {
            var frac = rIdx / Math.max(1, steps - 1);
            var rt = rollStart + frac * (rollEnd - rollStart);
            var ro = ctx.createOscillator();
            var rg = ctx.createGain();
            var rFilt = ctx.createBiquadFilter();
            rFilt.type = "bandpass"; rFilt.frequency.value = 780; rFilt.Q.value = 1.5;
            ro.type = "triangle";
            ro.frequency.setValueAtTime(260 - 80 * frac, rt);
            ro.frequency.exponentialRampToValueAtTime(150 - 40 * frac, rt + 0.03);
            rg.gain.setValueAtTime(0.0001, rt);
            rg.gain.exponentialRampToValueAtTime(0.22 + 0.42 * frac, rt + 0.003);
            rg.gain.exponentialRampToValueAtTime(0.0001, rt + 0.035);
            ro.connect(rFilt); rFilt.connect(rg); rg.connect(ctx.destination);
            ro.start(rt); ro.stop(rt + 0.04);
          })(ri);
        }
      } catch (_nagada) {}
    } catch (_outer) { console.warn("trumpet victory audio failed", _outer); }
  }
  function crazyTriggerCrashVisual() {
    try {
      // Full-screen CRASH overlay with static, shake, and red flashing
      var overlay = document.createElement("div");
      overlay.id = "__crazy_crash_overlay__";
      overlay.style.cssText =
        "position:fixed; inset:0; z-index:99999; background:#1a0000; " +
        "display:flex; align-items:center; justify-content:center; color:#ff0033; " +
        "font-family:monospace; font-weight:900; text-align:center; " +
        "pointer-events:none; overflow:hidden; user-select:none;";
      overlay.innerHTML =
        '<div style="animation:crazy-shake 0.3s infinite; position:relative; z-index:3;">' +
          '<h1 style="font-size:22vw; line-height:0.9; margin:0; letter-spacing:-6px; ' +
          'text-shadow:0 0 40px #ff0040,0 0 80px #ff0040,0 0 160px #990000; ' +
          'animation:crazy-crash-blink 0.12s infinite alternate;">💀 CRASH 💀</h1>' +
          '<div style="font-size:6vw; margin-top:3vh; color:#ff6677; ' +
          'text-shadow:0 0 20px #ff0033;">SYSTEM FAILURE — YOU FAILED CRAZY MODE</div>' +
          '<div style="font-size:2.5vw; margin-top:4vh; color:#ffcc00; opacity:0.9;">' +
          '☠ HORROR. TERMINAL. IRRECOVERABLE. ☠</div>' +
        '</div>';
      // Static + scanline layers
      var staticEl = document.createElement("div");
      staticEl.style.cssText =
        "position:absolute; inset:0; opacity:0.35; mix-blend-mode:screen; " +
        "background-image:repeating-linear-gradient(0deg,rgba(255,0,0,0.12) 0px,rgba(255,0,0,0.12) 1px,transparent 1px,transparent 3px); " +
        "animation:crazy-flicker 0.05s infinite; pointer-events:none;";
      var skulls = "";
      for (var s = 0; s < 30; s++) {
        skulls += '<div style="position:absolute; left:' + Math.random()*100 + '%; top:' + Math.random()*100 + '%;' +
          ' font-size:' + (Math.random()*5+2) + 'vw; opacity:' + (Math.random()*0.5+0.3) + ';' +
          ' transform:rotate(' + (Math.random()*360) + 'deg); animation:crazy-blink 0.2s infinite;">💀</div>';
      }
      var skullsEl = document.createElement("div");
      skullsEl.innerHTML = skulls;
      skullsEl.style.cssText = "position:absolute; inset:0; pointer-events:none; z-index:2;";
      // Background red flashes
      var flash = document.createElement("div");
      flash.style.cssText =
        "position:absolute; inset:0; pointer-events:none; z-index:1; " +
        "animation:crazy-red-flash 0.2s infinite alternate; background:rgba(255,0,0,0.15);";
      overlay.appendChild(flash);
      overlay.appendChild(staticEl);
      overlay.appendChild(skullsEl);

      // Shake CSS keyframes (inject if missing)
      if (!document.getElementById("__crazy_crash_css__")) {
        var style = document.createElement("style");
        style.id = "__crazy_crash_css__";
        style.textContent =
          "@keyframes crazy-shake {" +
          "  0% { transform:translate(0,0) rotate(0); }" +
          "  20% { transform:translate(-20px,12px) rotate(-2deg); }" +
          "  40% { transform:translate(16px,-18px) rotate(1.5deg); }" +
          "  60% { transform:translate(-18px,-14px) rotate(-1.8deg); }" +
          "  80% { transform:translate(22px,10px) rotate(2deg); }" +
          "  100% { transform:translate(0,0) rotate(0); }}" +
          "@keyframes crazy-crash-blink {" +
          "  0% { color:#ff0033; opacity:0.9; transform:scale(1); }" +
          "  100% { color:#ffff00; opacity:1; transform:scale(1.06); }}" +
          "@keyframes crazy-flicker {" +
          "  0% { opacity:0.35; } 50% { opacity:0.55; } 100% { opacity:0.25; }}" +
          "@keyframes crazy-red-flash {" +
          "  0% { background:rgba(255,0,0,0.05); }" +
          "  50% { background:rgba(255,0,0,0.35); }" +
          "  100% { background:rgba(120,0,0,0.15); }}" +
          "@keyframes crazy-blink { 0%,100% { opacity:1; } 50% { opacity:0.3; }}";
        document.head.appendChild(style);
      }

      document.body.appendChild(overlay);
      // Screen shake the body too
      var origTransform = document.body.style.transform || "";
      document.body.style.transition = "transform 0.05s";
      var shakes = 0;
      var shakeInt = setInterval(function () {
        shakes++;
        var x = (Math.random() - 0.5) * 30;
        var y = (Math.random() - 0.5) * 30;
        document.body.style.transform = "translate(" + x + "px," + y + "px)";
        if (shakes > 22) {
          clearInterval(shakeInt);
          document.body.style.transform = origTransform;
        }
      }, 60);
      setTimeout(function () { try { overlay.remove(); } catch (_e) {} }, 4200);
    } catch (_e) { console.warn("crash visual failed", _e); }
  }
  function crazyTriggerVictoryVisual() {
    try {
      if (!document.getElementById("__crazy_crash_css__")) {
        var s0 = document.createElement("style");
        s0.id = "__crazy_crash_css__";
        s0.textContent = "@keyframes crazy-shake{}";
        document.head.appendChild(s0);
      }
      var vStyle = document.getElementById("__crazy_victory_css__");
      if (!vStyle) {
        vStyle = document.createElement("style");
        vStyle.id = "__crazy_victory_css__";
        vStyle.textContent =
          "@keyframes crazy-rainbow {" +
          "  0% { background:rgba(255,0,0,0.22); }" +
          "  14% { background:rgba(255,140,0,0.22); }" +
          "  28% { background:rgba(255,235,0,0.22); }" +
          "  42% { background:rgba(0,220,0,0.22); }" +
          "  57% { background:rgba(0,200,255,0.22); }" +
          "  71% { background:rgba(130,80,255,0.22); }" +
          "  85% { background:rgba(255,80,220,0.22); }" +
          "  100% { background:rgba(255,0,0,0.22); }}" +
          "@keyframes crazy-zoom {" +
          "  0% { transform:scale(0.2) rotate(-20deg); opacity:0; }" +
          "  30% { transform:scale(1.25) rotate(5deg); opacity:1; }" +
          "  60% { transform:scale(1) rotate(-2deg); }" +
          "  100% { transform:scale(1.05) rotate(0); }}" +
          "@keyframes crazy-pop {" +
          "  0% { transform:translate(-50%,-50%) scale(0.2); opacity:0; }" +
          "  100% { transform:translate(-50%,-50%) scale(1); opacity:1; }}";
        document.head.appendChild(vStyle);
      }
      var overlay = document.createElement("div");
      overlay.style.cssText =
        "position:fixed; inset:0; z-index:99998; pointer-events:none; user-select:none; " +
        "animation:crazy-rainbow 0.4s linear infinite;";
      overlay.id = "__crazy_victory_overlay__";

      var centerText = document.createElement("div");
      centerText.style.cssText =
        "position:absolute; left:50%; top:50%; transform:translate(-50%,-50%); " +
        "text-align:center; z-index:10; animation:crazy-zoom 0.9s cubic-bezier(.2,1.5,.4,1) both;";
      centerText.innerHTML =
        '<h1 style="font-size:15vw; line-height:0.95; margin:0; font-weight:900; ' +
        'background:linear-gradient(90deg,#ff00cc,#ffcc00,#00ff88,#00bbff,#aa00ff); ' +
        '-webkit-background-clip:text; background-clip:text; color:transparent; ' +
        'filter:drop-shadow(0 0 20px rgba(255,255,255,0.6)) drop-shadow(0 0 60px rgba(255,200,0,0.5)); ' +
        'font-family:sans-serif;">🎉 PERFECT! 🎉</h1>' +
        '<div style="font-size:5vw; margin-top:3vh; font-weight:800; ' +
        'background:linear-gradient(90deg,#fff0aa,#00ffcc); ' +
        '-webkit-background-clip:text; background-clip:text; color:transparent;">' +
        '🏆 CRAZY MODE BEATEN — YOU ARE A CYBER LEGEND 🏆</div>' +
        '<div style="font-size:2.8vw; margin-top:2.5vh; color:#ffffff; font-weight:600; ' +
        'text-shadow:0 0 15px #00ff88,0 0 30px #00aa66;">' +
        '🎺 TRUMPETS FLARE · CONFETTI BURSTS · SITE GOES CRAZY 🎺</div>';
      overlay.appendChild(centerText);

      // Confetti burst — 250+ colorful particles
      for (var i = 0; i < 280; i++) {
        (function (idx) {
          var c = document.createElement("div");
          var colors = ["#ff0055","#ffcc00","#00ff88","#00bbff","#aa55ff","#ff8800","#ff66bb","#88ff00","#ffffff"];
          var col = colors[idx % colors.length];
          var shapes = ["0%","35%","50%","20%"];
          var size = Math.random()*16 + 6;
          var dx = (Math.random() - 0.5) * 100;
          var dy = (Math.random() - 0.9) * 120;
          var rot = Math.random() * 720 - 360;
          var dur = (Math.random() * 2) + 2;
          var delay = Math.random() * 0.4;
          c.style.cssText =
            "position:absolute; left:50%; top:50%; width:" + size + "px; height:" + size + "px; " +
            "background:" + col + "; border-radius:" + shapes[Math.floor(Math.random()*shapes.length)] + "; " +
            "z-index:5; box-shadow:0 0 10px " + col + "; opacity:0;";
          overlay.appendChild(c);
          requestAnimationFrame(function () {
            c.style.transition = "left " + dur + "s ease-out, top " + dur + "s cubic-bezier(.2,.8,.3,1), " +
              "transform " + dur + "s ease-out, opacity " + (dur * 0.9) + "s ease-out";
            c.style.opacity = "1";
            setTimeout(function () {
              c.style.left = "calc(50% + " + dx + "vw)";
              c.style.top = "calc(50% + " + dy + "vh)";
              c.style.transform = "rotate(" + rot + "deg)";
              c.style.opacity = "0";
            }, 10);
          });
        })(i);
      }

      // 12 corner flashes
      for (var f = 0; f < 12; f++) {
        (function (idx) {
          var fl = document.createElement("div");
          fl.style.cssText =
            "position:absolute; inset:0; pointer-events:none; " +
            "background:radial-gradient(circle at " + (Math.random()*100) + "% " + (Math.random()*100) + "%, " +
            "rgba(255,255,255,0.85), transparent 55%); opacity:0;";
          overlay.appendChild(fl);
          setTimeout(function () {
            fl.style.transition = "opacity 0.15s ease-out";
            fl.style.opacity = "1";
            setTimeout(function () { fl.style.opacity = "0"; }, 180);
          }, idx * 120);
        })(f);
      }

      document.body.appendChild(overlay);
      setTimeout(function () { try { overlay.remove(); } catch (_e) {} }, 5500);
    } catch (_e) { console.warn("victory visual failed", _e); }
  }
  // ===========================================================================
  // END CRAZY MODE FX
  // ===========================================================================


  // ---------------------------------------------------------------------------
  // Answer builders: 9 game-specific answer interaction UIs
  // ---------------------------------------------------------------------------
  function buildAnswerSlot(slot, gameId, lvl) {
    try {
      slot.innerHTML = "";
      switch (String(gameId || "")) {
        case "crack_cipher":
        case "cipher_puzzle":
        case "daily_cipher":
          slot.appendChild(buildCrackAnswer(gameId));
          break;
        case "guess_cipher":
          slot.appendChild(buildMcq(lvl.options || [], correctGuessCipher));
          break;
        case "brute_force":
          slot.appendChild(buildGuessAnswer());
          break;
        case "key_guessing":
          slot.appendChild(buildFactorAnswer(lvl));
          break;
        case "hash_detective":
          slot.appendChild(buildHashDetective(lvl));
          break;
        case "encryption_race":
          slot.appendChild(buildMcq([lvl.candidate_a, lvl.candidate_b], function (choice) {
            const win = String(choice) === String(lvl.faster_algorithm);
            finishRound(win, { reason: win ? "Prediction correct!" : "Prediction was wrong." });
          }));
          break;
        case "find_vulnerability":
          slot.appendChild(buildMcq(lvl.options || [], function (choice, idx, buttons) {
            const correctIdx = Number(lvl.correct_index);
            const win = Number(idx) === correctIdx;
            buttons.forEach(function (b, i) {
              try {
                if (i === correctIdx) b.classList.add("correct");
                else if (Number(i) === Number(idx) && !win) b.classList.add("incorrect");
              } catch (_e) {}
            });
            finishRound(win, { reason: win ? "Found the vulnerability — nice code review eye." : "That's a plausible issue, but not the intended critical flaw." });
          }));
          break;
        case "crazy_mode":
          try { state.crazyTotalQuestions = Number(lvl.max_questions || state.crazyTotalQuestions || 5); } catch (_e) {}
          slot.appendChild(buildMcq(lvl.choices || [], function (choice, idx, buttons) {
            try {
              const expected = normalizeAnswer(lvl.correct_answer);
              const chosen = normalizeAnswer(choice);
              const win = chosen === expected;
              // Mark correct / incorrect on the buttons for feedback
              var correctIdx = -1;
              try {
                correctIdx = (lvl.choices || []).findIndex(function (c) {
                  return normalizeAnswer(c) === expected;
                });
              } catch (_e2) { correctIdx = -1; }
              buttons.forEach(function (b, i) {
                try {
                  if (i === correctIdx) b.classList.add("correct");
                  else if (Number(i) === Number(idx) && !win) b.classList.add("incorrect");
                } catch (_e3) {}
              });
              crazyProcessAnswer(win, lvl);
            } catch (_e) { console.warn(_e); finishRound(false); }
          }));
          break;
      }
      setStage(3);
    } catch (_outer) { console.error("buildAnswerSlot failed:", _outer); toastMessage("Error building answer panel: " + _outer.message, "error"); }
  }

  function crazyProcessAnswer(correctThisQuestion, lvl) {
    try {
      lvl = lvl || state.level || {};
      var qIdx = Number(state.crazyQuestionIndex) | 0;
      var total = Number(state.crazyTotalQuestions) | 0;
      if (total < 1) total = 5;

      if (correctThisQuestion) {
        state.crazyTotalCorrect = Number(state.crazyTotalCorrect || 0) + 1;
      } else {
        state.lives = Math.max(0, Number(state.lives) - 1);
        renderLives();
      }
      state.attempts = Number(state.attempts || 0) + 1;

      var lastQuestion = qIdx >= (total - 1);
      var failed = state.lives <= 0;

      // Update footer message with progression info
      var statusMsg = "";
      if (failed) {
        statusMsg = "💀 2 WRONG — SYSTEM FAILURE. CRAZY MODE CRASH IMMINENT.";
      } else if (correctThisQuestion && lastQuestion) {
        statusMsg = "🔥 ALL " + total + " QUESTIONS CORRECT — VICTORY FLARES ENGAGED!";
      } else if (correctThisQuestion) {
        statusMsg = "✔ CORRECT. Loading next insane question… (" + (qIdx + 1) + "/" + total + ")";
      } else {
        statusMsg = "✘ WRONG. Remaining lives: " + state.lives + ". Loading next… (" + (qIdx + 1) + "/" + total + ")";
      }
      setText("runnerFooterMsg", statusMsg);

      // --- Path 1: FAILURE (2 wrong) → CRASH FX, then end the round as FAILED ---
      if (failed) {
        try {
          crazyTriggerCrashVisual();
        } catch (_e1) {}
        try {
          setTimeout(function () {
            try { crazyPlayHorrorCrash(); } catch (_e2) {}
          }, 120);
        } catch (_e3) {}
        setTimeout(function () {
          try {
            finishRound(false, {
              reason: "Crazy Mode FAILED — 2 incorrect guesses triggered terminal crash. Horror show activated.",
              explanation: "Only 2 lives in Crazy Mode. Every question must be correct OR you face THE CRASH. Study the education page and come back!",
              crazyCrash: true,
            });
          } catch (_e) { console.warn(_e); }
          crazyMarkDoneAndDusted();
        }, 2800);
        return;
      }

      // --- Path 2: LAST QUESTION CORRECT → VICTORY FX, then SUCCESS round with big XP ---
      if (lastQuestion && correctThisQuestion) {
        try {
          crazyTriggerVictoryVisual();
        } catch (_e4) {}
        try {
          setTimeout(function () {
            try { crazyPlayTrumpetVictory(); } catch (_e5) {}
          }, 80);
        } catch (_e6) {}
        setTimeout(function () {
          try {
            var correctCount = Number(state.crazyTotalCorrect || 0);
            var perfectBonus = correctCount >= total ? 1500 : 0;
            state.score = 3000 + correctCount * 250 + perfectBonus;
            renderScore();
            finishRound(true, {
              reason: "Crazy Mode DEFEATED — " + correctCount + "/" + total + " correct. You are a true Cyber Legend!",
              explanation: "Perfect streak through Crazy Mode. Trigonometric ciphers, rainbow tables, zero-day crypto flaws — nothing phases you. 🏆",
              bonusXp: (500 + perfectBonus),
              crazyVictory: true,
            });
          } catch (_e) { console.warn(_e); }
          crazyMarkDoneAndDusted();
        }, 3200);
        return;
      }

      // --- Path 3: Still alive, MORE QUESTIONS → fetch next Crazy question ---
      qIdx = qIdx + 1;
      state.crazyQuestionIndex = qIdx;
      state.finished = false;
      state.answered = false;

      // Reset answer slot + badges + result for next question
      try {
        hideEl("runnerResultCard");
        removeClass("runnerResultCard", "success failure");
        var rb = qs("runnerResultBody");
        if (rb) rb.innerHTML = "";
        showEl("btnRetryGame");
      } catch (_e7) {}

      setTimeout(function () {
        try { crazyLoadNextQuestion(qIdx, total); }
        catch (_e8) { console.warn("crazyLoadNext failed:", _e8); }
      }, 900);
    } catch (_outer) {
      console.warn("crazyProcessAnswer failed:", _outer);
      try { finishRound(false); crazyMarkDoneAndDusted(); } catch (_f) {}
    }
  }

  function crazyLoadNextQuestion(qIdx, total) {
    try {
      setStage(1);
      setText("runnerFooterMsg", "Loading Crazy Mode question " + (qIdx + 1) + " / " + total + " …");
      var seed = Math.floor(Math.random() * 1e9);
      var url = "/api/games/level/crazy_mode?seed=" + seed +
                "&q=" + encodeURIComponent(String(qIdx)) +
                "&total=" + encodeURIComponent(String(total));
      fetch(url, { credentials: "same-origin" })
        .then(function (r) { try { return r.json(); } catch (_e) { return { success: false }; } })
        .then(function (data) {
          try {
            if (!data || !data.success) {
              setText("runnerFooterMsg", "Server failed to load next Crazy question.");
              return;
            }
            state.level = data.level || {};
            beginChallenge();
          } catch (_e) { console.warn(_e); setText("runnerFooterMsg", "Next question load failed: " + _e.message); }
        })
        .catch(function (err) {
          setText("runnerFooterMsg", "Network error — check connection (" + (err && err.message ? err.message : "?") + ")");
        });
    } catch (_e) { console.warn(_e); }
  }

  function crazyMarkDoneAndDusted() {
    try {
      var qbtn = qs("btnQuitGame");
      if (qbtn) {
        qbtn.innerHTML = '<i class="fas fa-check-double me-1"></i>Done and Dusted';
        qbtn.classList.remove("btn-outline-secondary", "btn-outline-danger");
        qbtn.classList.add("btn-success");
        try { qbtn.setAttribute("data-bs-dismiss", "modal"); } catch (_e) {}
      }
      state.crazySessionComplete = true;
    } catch (_e) { /* ignore */ }
  }

  function buildCrackAnswer() {
    const wrap = document.createElement("div");
    wrap.innerHTML =
      `<label class="form-label">Decrypted plaintext (case &amp; spaces insensitive):</label>
       <div class="input-group mb-3">
         <input type="text" id="crackAnswerInput" class="form-control" placeholder="Paste or type the plaintext you recovered" autocomplete="off" spellcheck="false">
         <button class="btn btn-success" id="crackSubmitBtn">Submit</button>
       </div>`;
    const input = wrap.querySelector("#crackAnswerInput");
    const submit = wrap.querySelector("#crackSubmitBtn");
    const doSubmit = function () {
      try {
        if (state.answered) return;
        const expected = String((state.level && state.level.plaintext_answer) || "");
        const attempt = input ? (input.value || "") : "";
        const nAttempt = normalizeAnswer(attempt);
        const nExpected = normalizeAnswer(expected);
        let win = nAttempt === nExpected;
        if (!win && state.level && state.level.algo === "Caesar" && state.level.ciphertext) {
          for (let s = 1; s < 26 && !win; s++) {
            try {
              if (normalizeAnswer(caesarDecrypt(state.level.ciphertext, s)) === nAttempt) win = true;
            } catch (_e) {}
          }
        }
        finishRound(win, { reason: win ? "Correct plaintext — excellent cryptanalysis!" : "Not matching — keep working: re-check the scheme and key." });
      } catch (_e) { console.warn(_e); }
    };
    if (submit) submit.addEventListener("click", doSubmit);
    if (input) input.addEventListener("keydown", function (e) { try { if (e.key === "Enter") doSubmit(); } catch (_e) {} });
    return wrap;
  }

  function buildMcq(options, onSelect, opts) {
    opts = opts || {};
    const wrap = document.createElement("div");
    wrap.className = "answer-mcq";
    const buttons = [];
    (options || []).forEach(function (opt, idx) {
      try {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "btn btn-outline-success";
        const label = (opts.labelKey ? (opt[opts.labelKey] || String(opt)) : String(opt));
        b.textContent = String.fromCharCode(65 + idx) + ") " + label;
        b.addEventListener("click", function () {
          try {
            if (state.answered) return;
            state.answered = true;
            onSelect(label, idx, buttons);
          } catch (_e) { console.warn(_e); }
        });
        buttons.push(b);
        wrap.appendChild(b);
      } catch (_e) {}
    });
    return wrap;
  }

  function correctGuessCipher(_choice, idx, buttons) {
    try {
      const lvl = state.level || {};
      const correctAlgo = String(lvl.correct_algo || lvl.correctAlgorithm || "");
      const options = Array.isArray(lvl.options) ? lvl.options : [];
      const win = options[idx] === correctAlgo;
      buttons.forEach(function (b, i) {
        try {
          if (options[i] === correctAlgo) b.classList.add("correct");
          else if (i === idx && !win) b.classList.add("incorrect");
        } catch (_e) {}
      });
      finishRound(win, { reason: win ? "Right — pattern matches the cipher." : "Wrong choice — study the patterns in /education." });
    } catch (_e) { console.warn(_e); finishRound(false); }
  }

  function buildGuessAnswer() {
    const wrap = document.createElement("div");
    wrap.innerHTML =
      `<label class="form-label">Your guess (<span id="bfRemain">${Number(state.maxAttempts)}</span> left, ${Number(state.lives)} lives)</label>
       <div class="input-group mb-3">
         <input type="text" id="bfInput" class="form-control" maxlength="24" autocomplete="off" spellcheck="false" placeholder="Try: 1234 / pass1 / zebra7...">
         <button class="btn btn-success" id="bfSubmit">Guess</button>
       </div>
       <div id="bfAttemptsLog" class="attempts-log"></div>`;
    const input = wrap.querySelector("#bfInput");
    const btn = wrap.querySelector("#bfSubmit");
    const log = wrap.querySelector("#bfAttemptsLog");
    if (log) log.innerHTML = `<div class="attempt-line"><span class="text-info">[SYSTEM]</span> Awaiting your first guess.</div>`;
    function matchHtml(guess, target) {
      try {
        const L = Math.min(guess.length, target.length);
        let h = "";
        for (let i = 0; i < L; i++) {
          const cls = (guess[i] || "").toLowerCase() === (target[i] || "").toLowerCase() ? "attempt-match-pos" : "attempt-match-no";
          h += `<span class="${cls}">${escapeHtml(guess[i] || "")}</span>`;
        }
        for (let i = L; i < guess.length; i++) h += `<span class="attempt-match-no">${escapeHtml(guess[i])}</span>`;
        return h;
      } catch (_e) { return ""; }
    }
    function addLine(html) {
      try {
        if (!log) return;
        const d = document.createElement("div");
        d.className = "attempt-line";
        d.innerHTML = html;
        log.appendChild(d);
        log.scrollTop = log.scrollHeight;
      } catch (_e) {}
    }
    function submit() {
      try {
        if (state.finished || state.answered) return;
        const val = (input && input.value ? input.value : "").trim();
        if (!val) return;
        state.attempts += 1;
        const target = String((state.level && state.level.answer) || "");
        const win = val.toLowerCase() === target.toLowerCase();
        addLine(`<span class="text-warning">#${state.attempts}</span> ${escapeHtml(val)} — ${win ? '<span class="text-success fw-bold">CORRECT! Password found.</span>' : matchHtml(val, target)}`);
        if (win) { finishRound(true, { reason: "Cracked within attempt budget." }); return; }
        state.lives = Math.max(0, Number(state.lives) - 1);
        renderLives();
        if (input) input.value = "";
        const remainEl = wrap.querySelector("#bfRemain");
        if (remainEl) remainEl.textContent = String(Math.max(0, Number(state.maxAttempts) - state.attempts));
        const labelEl = wrap.querySelector("label.form-label");
        if (labelEl) labelEl.textContent = `Your guess (${Math.max(0, Number(state.maxAttempts) - state.attempts)} left, ${state.lives} lives)`;
        if (state.attempts >= state.maxAttempts || state.lives <= 0) {
          finishRound(false, { reason: `Out of ${state.attempts >= state.maxAttempts ? "attempts" : "lives"}. Demo password was ${JSON.stringify(target)}.` });
        }
      } catch (_e) { console.warn(_e); }
    }
    if (btn) btn.addEventListener("click", submit);
    if (input) input.addEventListener("keydown", function (e) { try { if (e.key === "Enter") submit(); } catch (_e) {} });
    return wrap;
  }

  function buildFactorAnswer(lvl) {
    const wrap = document.createElement("div");
    wrap.innerHTML =
      `<p class="small text-light opacity-75 mb-2">Submit <b>one prime factor</b> of n = ${(lvl.public_key && lvl.public_key.n != null) ? lvl.public_key.n : "?"} (either p or q). Optional: recover plaintext integer for +20% XP.</p>
       <div class="row g-3">
         <div class="col-12 col-md-5">
           <label class="form-label">Factor (integer)</label>
           <div class="input-group">
             <input type="number" id="kgFactor" class="form-control" placeholder="Try: 2, 3, 5, 7, 11, 13, 17, 19, 23...">
             <button class="btn btn-success" id="kgSubmit">Submit Factor</button>
           </div>
           <small class="text-light opacity-50">Attempts remaining: <span id="kgRemain">${state.maxAttempts}</span></small>
         </div>
         <div class="col-12 col-md-7">
           <label class="form-label">Optional — plaintext integer (extra XP)</label>
           <input type="number" id="kgPlaintext" class="form-control" placeholder="Once you know d, compute pow(c, d, n).">
         </div>
       </div>
       <div id="kgLog" class="attempts-log mt-3"></div>`;
    const factor = wrap.querySelector("#kgFactor");
    const plain = wrap.querySelector("#kgPlaintext");
    const btn = wrap.querySelector("#kgSubmit");
    const log = wrap.querySelector("#kgLog");
    const remainEl = wrap.querySelector("#kgRemain");
    if (log) log.innerHTML = `<div class="attempt-line"><span class="text-info">[INFO]</span> Hint: try the smallest primes by hand — real RSA would make this infeasible.</div>`;
    function line(html) {
      try {
        if (!log) return;
        const d = document.createElement("div");
        d.className = "attempt-line";
        d.innerHTML = html;
        log.appendChild(d);
        log.scrollTop = log.scrollHeight;
      } catch (_e) {}
    }
    function submit() {
      try {
        if (state.finished || state.answered) return;
        const f = Number(factor && factor.value);
        if (!Number.isFinite(f) || !Number.isInteger(f) || f < 2) return;
        state.attempts += 1;
        const n = Number((lvl.public_key && lvl.public_key.n) || 0);
        const correctFactor = (n > 1 && f > 1 && (n % f) === 0) ? true : (f === Number(lvl.correct_prime_factor));
        line(`<span class="text-warning">#${state.attempts}</span> candidate = <b>${f}</b> — ${correctFactor ? '<span class="text-success fw-bold">YES, n is divisible by this factor.</span>' : '<span class="text-danger">no.</span>'}`);
        if (remainEl) remainEl.textContent = String(Math.max(0, state.maxAttempts - state.attempts));
        if (!correctFactor) {
          state.lives = Math.max(0, Number(state.lives) - 1);
          renderLives();
        }
        const pGuess = Number(plain && plain.value);
        const correctPlain = Number.isFinite(pGuess) && Number.isInteger(pGuess) && pGuess === Number(lvl.correct_plaintext);
        if (correctFactor || correctPlain) {
          finishRound(true, {
            reason: correctFactor ? "Factor discovered!" : "Plaintext recovered via direct guess!",
            bonusXp: correctPlain ? Math.round(Number(lvl.xp || 0) * 0.2) : 0,
            explanation: correctPlain
              ? `Nailed both: factored n AND recovered plaintext = ${lvl.correct_plaintext}. Real RSA uses 2048-bit n → trial division is impossible.`
              : `Factor found: ${f}. For extra XP, also solve d = e^-1 mod (p-1)(q-1) and compute plaintext = pow(c, d, n).`
          });
          return;
        }
        if (state.attempts >= state.maxAttempts || state.lives <= 0) {
          finishRound(false, { reason: `Out of ${state.attempts >= state.maxAttempts ? "attempts" : "lives"}. One factor was ${lvl.correct_prime_factor}.` });
        }
      } catch (_e) { console.warn(_e); }
    }
    if (btn) btn.addEventListener("click", submit);
    return wrap;
  }

  function buildHashDetective(lvl) {
    const wrap = document.createElement("div");
    wrap.innerHTML =
      `<label class="form-label">Step 1 — Identify the algorithm</label>
       <div id="hdStep1" class="answer-mcq mb-4"></div>
       <div class="mb-3 d-none" id="hdStep2Wrap">
         <label class="form-label">Step 2 — Crack the preimage</label>
         <div class="input-group mb-2">
           <input type="text" id="hdPreimage" class="form-control" placeholder="Guess the original text that produced the hash" autocomplete="off" spellcheck="false">
           <button class="btn btn-success" id="hdSubmit2">Submit Preimage</button>
         </div>
         <small class="text-light opacity-50">Case-sensitive.</small>
       </div>`;
    const step1 = wrap.querySelector("#hdStep1");
    const buttons = [];
    const algos = Array.isArray(lvl.algorithm_options) ? lvl.algorithm_options : ["md5", "sha1", "sha256"];
    const lengths = { md5: "32 hex", sha1: "40 hex", sha256: "64 hex", sha512: "128 hex" };
    const correctAlgo = String(lvl.correct_algorithm || "");
    algos.forEach(function (a, i) {
      try {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "btn btn-outline-success";
        b.textContent = String.fromCharCode(65 + i) + ") " + a.toUpperCase() + "  (" + (lengths[a] || "") + ")";
        step1.appendChild(b);
        buttons.push(b);
        b.addEventListener("click", function () {
          try {
            if (b.__hdDone) return;
            const win = a === correctAlgo;
            buttons.forEach(function (bb, j) {
              try {
                bb.__hdDone = true;
                bb.disabled = true;
                if (algos[j] === correctAlgo) bb.classList.add("correct");
                else if (j === i && !win) bb.classList.add("incorrect");
              } catch (_e) {}
            });
            if (!win) {
              state.lives = Math.max(0, Number(state.lives) - 1);
              renderLives();
              if (state.lives <= 0) {
                state.answered = true;
                finishRound(false, { reason: `Wrong algorithm. Correct was ${correctAlgo.toUpperCase()}.` });
                return;
              }
            }
            const step2 = wrap.querySelector("#hdStep2Wrap");
            if (step2) step2.classList.remove("d-none");
            const preBtn = wrap.querySelector("#hdSubmit2");
            const preInput = wrap.querySelector("#hdPreimage");
            if (preBtn && !preBtn.__hdBound) {
              preBtn.__hdBound = true;
              const submit = function () {
                try {
                  if (state.answered) return;
                  const v = (preInput && preInput.value || "").trim();
                  state.answered = true;
                  const expected = String(lvl.preimage_answer || "");
                  const win2 = v === expected;
                  finishRound(true, {
                    partial: !win2,
                    halfScore: !win2,
                    reason: win2
                      ? `Both correct: algorithm + preimage.`
                      : `Algorithm correct (${correctAlgo.toUpperCase()}). Preimage answer was ${JSON.stringify(expected)} — ${String(lvl.note || "")}.`,
                  });
                } catch (_e) { console.warn(_e); }
              };
              preBtn.addEventListener("click", submit);
              if (preInput) preInput.addEventListener("keydown", function (e) { try { if (e.key === "Enter") submit(); } catch (_e) {} });
            }
          } catch (_e) { console.warn(_e); }
        });
      } catch (_e) {}
    });
    return wrap;
  }

  // ---------------------------------------------------------------------------
  // End-of-round handling
  // ---------------------------------------------------------------------------
  function onFailure(msg) {
    try {
      if (state.finished) return;
      if (String(state.gameId) === "crazy_mode") {
        crazyProcessAnswer(false, state.level || {});
        return;
      }
      finishRound(false, { reason: msg || "Round ended without a correct answer." });
    } catch (_e) {
      try { finishRound(false); } catch (_f) {}
    }
  }

  function finishRound(won, opts) {
    try {
      if (state.finished) return;
      opts = opts || {};
      state.finished = true;
      state.answered = true;
      if (state.timerId) { clearInterval(state.timerId); state.timerId = null; }
      const lvl = state.level || {};
      setStage(4);

      // Score math
      const baseXP = Number(lvl.xp || 0);
      let xpAward = baseXP;
      if (opts.halfScore) xpAward = Math.round(xpAward / 2);
      if (opts.bonusXp) xpAward += Number(opts.bonusXp);
      const tl = timeLimitFor(state.difficulty, state.gameId);
      const timeRatio = tl > 0 ? Math.max(0.2, state.secondsLeft / Math.max(1, tl)) : 1;
      const livesRatio = Math.max(0.1, Number(state.lives) / Math.max(1, livesFor(state.difficulty, state.gameId)));
      const hintPenalty = Math.max(0, 1 - 0.08 * Number(state.hintsUsed));
      xpAward = won
        ? Math.max(0, Math.round(xpAward * (0.5 + 0.3 * timeRatio + 0.2 * livesRatio) * hintPenalty))
        : Math.round(baseXP * 0.05);
      // Crazy Mode overrides — large bonuses already baked into state.score via crazyProcessAnswer
      if (String(state.gameId) === "crazy_mode") {
        if (opts.crazyVictory) {
          xpAward = Math.max(xpAward, 2000);
        }
      }
      const score = won
        ? Math.max(100, (String(state.gameId) === "crazy_mode" && Number(state.score) > 0)
            ? Number(state.score)
            : Math.round(1000 * (0.4 + 0.3 * timeRatio + 0.2 * livesRatio) * hintPenalty))
        : Math.min(50, 50 + state.attempts * 3);
      state.score = score;
      renderScore();

      const card = qs("runnerResultCard");
      showEl(card);
      addClass(card, won ? "success" : "failure");
      const body = qs("runnerResultBody");
      const algoOrGame = String(lvl.algo || (state.gameId === "encryption_race" ? "Race result" : "Round summary"));
      const expectedPlain =
        lvl.plaintext_answer || lvl.answer ||
        (lvl.preimage_answer ? lvl.preimage_answer : (
          state.gameId === "key_guessing" ? ("factor: " + lvl.correct_prime_factor + " · plaintext: " + lvl.correct_plaintext) : "—"
        ));
      const riskBadge = won
        ? '<span class="badge bg-success-subtle border border-success text-success-emphasis rounded-pill px-3 py-2"><i class="fas fa-shield-halved me-1"></i>Low risk</span>'
        : '<span class="badge bg-danger-subtle border border-danger text-danger-emphasis rounded-pill px-3 py-2"><i class="fas fa-triangle-exclamation me-1"></i>' + (score > 40 ? "Medium risk" : "High risk") + '</span>';
      if (body) {
        body.innerHTML =
          `<div class="row g-3 mb-3">
            <div class="col-6 col-md-3">
              <div class="small stat-card-label text-uppercase">Result</div>
              <h4 class="mb-0 ${won ? "text-success" : "text-danger"} fw-bold">${won ? "✔ COMPLETE" : "✘ FAILED"}</h4>
            </div>
            <div class="col-6 col-md-3">
              <div class="small stat-card-label text-uppercase">Score</div>
              <h4 class="mb-0 text-warning fw-bold font-monospace">${score}</h4>
            </div>
            <div class="col-6 col-md-3">
              <div class="small stat-card-label text-uppercase">XP Earned</div>
              <h4 class="mb-0 text-info fw-bold font-monospace">+${xpAward}</h4>
            </div>
            <div class="col-6 col-md-3">
              <div class="small stat-card-label text-uppercase">Risk</div>
              <div>${riskBadge}</div>
            </div>
          </div>
          <div class="card bg-dark border border-secondary glass-card mb-3">
            <div class="card-body small">
              <div class="row g-2">
                <div class="col-md-4"><b class="text-warning">Challenge:</b> ${escapeHtml(algoOrGame)}</div>
                <div class="col-md-4"><b class="text-warning">Expected:</b> <span class="font-monospace text-success">${escapeHtml(String(expectedPlain))}</span></div>
                <div class="col-md-4"><b class="text-warning">Hints used:</b> ${state.hintsUsed}</div>
              </div>
              <hr class="border-secondary my-2">
              <p class="mb-0 text-light">${escapeHtml(opts.reason || "")}</p>
              ${opts.explanation ? `<p class="mb-0 text-light opacity-85 mt-2"><i class="fas fa-lightbulb me-1 text-info"></i>${escapeHtml(opts.explanation)}</p>` : ""}
            </div>
          </div>
          ${renderEducational(state.gameId, lvl, won)}`;
      }
      try { showEl("btnRetryGame"); } catch (_e) {}
      toastMessage((won ? "✔ Won +" : "Partial +") + xpAward + " XP", won ? "success" : "warning");
      try {
        const bp = document.querySelector(`.btn-play-game[data-game-id="${state.gameId}"]`);
        if (bp) {
          const t = document.createElement("div");
          t.className = "xp-pop";
          t.textContent = "+" + xpAward + " XP";
          const r = bp.getBoundingClientRect();
          t.style.left = (window.scrollX + r.left + r.width / 2 - 30) + "px";
          t.style.top = (window.scrollY + r.top - 10) + "px";
          document.body.appendChild(t);
          setTimeout(function () { try { t.remove(); } catch (_e) {} }, 1200);
        }
      } catch (_e) {}
      updateBest(state.gameId, score);

      const daily_date = state.gameId === "daily_cipher" && lvl.date ? lvl.date : null;
      try {
        csrfFetch("/api/games/complete", {
          method: "POST",
          body: JSON.stringify({
            game_id: state.gameId, won: !!won, xp: xpAward, score: score, daily_date: daily_date,
          }),
        })
          .then(function (r) { try { return r.json(); } catch (_e) { return null; } })
          .then(function (d) {
            try {
              if (!d || !d.success) return;
              pushServerStats(d.statistics || {});
              bootStats();
            } catch (_e) {}
          })
          .catch(function () { /* offline fine for education sim */ });
      } catch (_e) {}

      setText("runnerFooterMsg", won ? "Nice work. Click New Round for another challenge." : "Keep practicing — Retry or New Round below.");

      // Any finished game → replace Quit with Done & Dusted (spec requirement)
      try { crazyMarkDoneAndDusted(); } catch (_fx) {}
    } catch (_outer) { console.error("finishRound failed:", _outer); }
  }

  function renderEducational(gameId, lvl, won) {
    try {
      const why = {
        crack_cipher: "Classic ciphers (Caesar, Atbash, Vigenère, monoalphabetic) have tiny key spaces or leak letter frequencies. Modern cryptanalysis breaks them in milliseconds.",
        guess_cipher: "Different ciphers leave characteristic patterns: Caesar preserves word lengths/structure, Atbash is its own inverse, Vigenère has keyword-periodic structure.",
        brute_force: "Short, numeric-only, or all-lowercase passwords collapse under even modest guessing. Real attackers enumerate billions/second using GPUs.",
        cipher_puzzle: "Known-plaintext, probable words, and crossword-style clue solving let analysts break hand ciphers without keys.",
        key_guessing: "RSA security rests entirely on factoring hardness. Tiny n = factored instantly; modern RSA-2048 is infeasible to factor.",
        hash_detective: "Unsalted fast hashes for passwords mean one precomputed table works against every company ever. Always use slow salted KDFs for passwords.",
        encryption_race: "Symmetric AEAD (AES-GCM, ChaCha20-Poly1305) is ~3+ orders of magnitude faster than asymmetric. Use asymmetric only for KEY EXCHANGE, never payload encryption.",
        find_vulnerability: "Each vulnerability corresponds to a real CWE. Read OWASP's Cryptographic Storage Cheat Sheet.",
        daily_cipher: "Daily practice builds cryptanalytic intuition faster than cramming. Consistency wins.",
      }[String(gameId || "")] || "";
      const tips = [
        "Use a password manager with unique, long random passwords per account.",
        "Enable MFA everywhere it's offered (prefer FIDO2 / WebAuthn over SMS).",
        "Store passwords with Argon2id / bcrypt / PBKDF2 (high work factor + unique per-user salt).",
        "Prefer AES-GCM or ChaCha20-Poly1305 for authenticated encryption.",
        "Rotate secrets via a secret manager; NEVER hardcode keys in source.",
        "Never roll your own cipher — use audited, standard constructions.",
      ];
      const defense = won ? "Defense: the following would block exactly these attacks in real systems." : "Defense: memorize this checklist — these are what defeat the simulated attacker.";
      return `<div class="card bg-dark border border-secondary glass-card">
        <div class="card-header border-secondary">
          <h6 class="mb-0 text-white"><i class="fas fa-graduation-cap me-2 text-info"></i>Educational Debrief</h6>
        </div>
        <div class="card-body small">
          <p class="mb-2"><b class="text-warning">Why this attack works:</b> ${escapeHtml(why)}</p>
          <p class="mb-2"><b class="text-warning">Why weak passwords/choices fail:</b> Humans are predictable — patterns, dates, leet-speak mutations, names, keyboard rows all fit inside precomputed wordlists.</p>
          <p class="mb-3"><b class="text-warning">How to defend:</b> ${escapeHtml(defense)}</p>
          <div class="mb-2"><b class="text-warning">Best practices:</b></div>
          <ul class="mb-0 ps-3 text-light">
            ${tips.map(function (t) { return "<li>" + escapeHtml(t) + "</li>"; }).join("")}
          </ul>
        </div>
      </div>`;
    } catch (_e) { return ""; }
  }

  // ---------------------------------------------------------------------------
  // DOM ready — attach handlers regardless of init errors in other modules
  // ---------------------------------------------------------------------------
  function onReady() {
    try { wireDelegatedEvents(); } catch (e0) { console.warn("wireDelegatedEvents threw:", e0); }
    try { bootStats(); } catch (e1) { console.warn("bootStats threw:", e1); }
    try { paintBestScores(); } catch (e2) { console.warn("paintBestScores threw:", e2); }
    try { wireDifficultyAndPlayButtons(); } catch (e3) { console.warn("wireDifficulty... threw:", e3); }
    try { wireRunnerFooterButtons(); } catch (e4) { console.warn("wireRunnerFooter... threw:", e4); }
    /* ---------- PUBLIC LEADERBOARD: SSR paint first, then async refresh via API ---------- */
    try {
      const INIT = getInit();
      if (INIT && Array.isArray(INIT.leaderboard)) try { renderLeaderboard(INIT.leaderboard); } catch (_e) { console.warn(_e); }
      try { setTimeout(function () { try { if (typeof refreshLeaderboard === "function") refreshLeaderboard(); } catch (_la) { console.warn(_la); } }, 450); } catch (_la) {}
    } catch (_leaderboardInitErr) { console.warn("leaderboard init failed:", _leaderboardInitErr); }
    try { setTimeout(function () { try { wireDelegatedEvents(); } catch (_e) {} try { wireDifficultyAndPlayButtons(); } catch (_e) {} try { wireRunnerFooterButtons(); } catch (_e) {} }, 300); } catch (_e) {}
    try { setTimeout(function () { try { bootStats(); } catch (_e) {} try { paintBestScores(); } catch (_e) {} try { wireDifficultyAndPlayButtons(); } catch (_e) {} }, 1000); } catch (_e) {}
    try { setTimeout(function () { try { bootStats(); } catch (_e) {} }, 2000); } catch (_e) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", onReady, { once: true });
  } else {
    try { onReady(); } catch (_e) { /* always try deferred fallback */ try { setTimeout(onReady, 0); } catch (_e2) {} }
  }

})();
