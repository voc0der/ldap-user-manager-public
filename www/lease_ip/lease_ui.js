(function () {
  const clientIp = window.LEASE_IP?.clientIp || null;
  const isAdmin  = !!window.LEASE_IP?.isAdmin;
  const API      = '/lease_ip/api.php';

  // === Generic fetch helper (existing pattern) =================================
  const STATE_CHANGING_OPS = ['add', 'delete', 'clear', 'prune'];

  const callOne = async (name, value, extraHeaders) => {
    const isStateChanging = STATE_CHANGING_OPS.includes(name);

    let res;
    if (isStateChanging) {
      // Use POST with CSRF token for state-changing operations
      const body = { [name]: value ?? '' };
      res = await fetch(API, {
        method: 'POST',
        credentials: 'include',
        headers: Object.assign({
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'X-CSRF-Token': window.CSRF_TOKEN || ''
        }, (extraHeaders || {})),
        body: JSON.stringify(body)
      });
    } else {
      // Use GET for read-only operations (list, geo)
      const url = API + '?' + encodeURIComponent(name) + '=' + encodeURIComponent(value ?? '');
      res = await fetch(url, {
        credentials: 'include',
        headers: Object.assign({ 'Cache-Control': 'no-store' }, (extraHeaders || {})),
      });
    }

    let data;
    try { data = await res.json(); } catch { data = { ok: false, error: 'Invalid JSON from API' }; }
    if (!res.ok || data.ok === false) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  };

  // === Small utils =============================================================
  const nowMs = () => Date.now();

  const getTimestampMs = (ent) => {
    if (ent.ts !== undefined && ent.ts !== null) {
      const n = Number(ent.ts);
      if (Number.isFinite(n)) {
        return (n > 2e12 ? n : (n > 2e9 ? n : n * 1000));
      }
      const d1 = Date.parse(ent.ts);
      if (!Number.isNaN(d1)) return d1;
    }
    if (ent.timestamp) {
      const d2 = Date.parse(ent.timestamp);
      if (!Number.isNaN(d2)) return d2;
    }
    return NaN;
  };

  const fmtRemaining = (ms) => {
    if (!Number.isFinite(ms)) return '—';
    if (ms <= 0) return 'expired';
    const totalMin = Math.floor(ms / 60000);
    const d = Math.floor(totalMin / 1440);
    const h = Math.floor((totalMin - d * 1440) / 60);
    const m = totalMin - d * 1440 - h * 60;
    let out = '';
    if (d) out += d + 'd ';
    if (h || d) out += h + 'h ';
    out += m + 'm';
    return out.trim();
  };

  // === Test Connection popup (same pattern as account_manager role popup) ======
  const TestConnectionUI = (() => {
    const TEST_URL = '/lease_ip/test_connection.php?embed=1&render_menu=0';
    const STYLE_ID = 'lum-lease-test-popup-style';
    const POPUP_ID = 'lum-lease-test-popup';
    const OVERLAY_ID = 'lum-lease-test-popup-overlay';

    let anchorEl = null;

    const ensureStyle = () => {
      if (document.getElementById(STYLE_ID)) return;
      const style = document.createElement('style');
      style.id = STYLE_ID;
      style.textContent = `
#${POPUP_ID} {
  position: fixed;
  z-index: 99999;
  width: min(920px, calc(100vw - 28px));
  min-width: 300px;
  max-height: calc(100vh - 28px);
  background: linear-gradient(
    135deg,
    var(--gradient-header, rgba(127,209,255,0.16)) 0%,
    var(--gradient-end, rgba(18,24,32,0.96)) 100%
  ), var(--bg-tertiary, #121820);
  border: 1px solid var(--border-hover, rgba(127,209,255,0.35));
  box-shadow: 0 0 24px var(--shadow-glow, rgba(42,139,220,0.35)), inset 0 0 20px rgba(255,255,255,0.04);
  border-radius: 14px;
  color: var(--text-primary, #cfe9ff);
  display: none;
  overflow: hidden;
}
#${POPUP_ID}.visible {
  display: block;
}
#${POPUP_ID} .popup-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-primary, rgba(127,209,255,0.2));
}
#${POPUP_ID} .popup-title {
  font-size: 14px;
  font-weight: 600;
  letter-spacing: 0.25px;
  color: var(--accent, #7fd1ff);
}
#${POPUP_ID} .popup-close {
  background: transparent;
  border: 1px solid var(--border-primary, rgba(127,209,255,0.3));
  color: var(--accent, #7fd1ff);
  cursor: pointer;
  border-radius: 4px;
  width: 24px;
  height: 24px;
  font-size: 16px;
  line-height: 1;
  padding: 0;
}
#${POPUP_ID} .popup-close:hover {
  background: var(--gradient-header, rgba(127,209,255,0.1));
  border-color: var(--accent, #7fd1ff);
}
#${POPUP_ID} .popup-body {
  height: min(72vh, 640px);
  min-height: 340px;
}
#${POPUP_ID} .popup-frame {
  width: 100%;
  height: 100%;
  border: 0;
  background: transparent;
}
#${OVERLAY_ID} {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 99998;
  display: none;
}
#${OVERLAY_ID}.visible {
  display: block;
}
@media (max-width: 768px) {
  #${POPUP_ID} {
    width: calc(100vw - 18px);
    max-height: calc(100vh - 18px);
  }
  #${POPUP_ID} .popup-body {
    height: min(76vh, 620px);
    min-height: 300px;
  }
}`;
      document.head.appendChild(style);
    };

    const popupEl = () => document.getElementById(POPUP_ID);
    const overlayEl = () => document.getElementById(OVERLAY_ID);

    const positionPopup = () => {
      const popup = popupEl();
      if (!popup || !anchorEl) return;

      const rect = anchorEl.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;

      const popupWidth = popup.offsetWidth || Math.min(920, viewportWidth - 28);
      const popupHeight = popup.offsetHeight || Math.min(640, viewportHeight - 28);

      let left = rect.left + (rect.width / 2) - (popupWidth / 2);
      let top = rect.bottom + 10;

      if (left + popupWidth > viewportWidth - 10) {
        left = viewportWidth - popupWidth - 10;
      }
      if (left < 10) {
        left = 10;
      }
      if (top + popupHeight > viewportHeight - 10) {
        top = Math.max(10, rect.top - popupHeight - 10);
      }

      popup.style.left = Math.round(left) + 'px';
      popup.style.top = Math.round(top) + 'px';
    };

    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        close();
      }
    };

    const onReposition = () => {
      if (popupEl()) {
        positionPopup();
      }
    };

    function close() {
      const popup = popupEl();
      const overlay = overlayEl();
      popup?.classList.remove('visible');
      overlay?.remove();
      popup?.remove();
      anchorEl = null;
      document.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', onReposition);
      window.removeEventListener('scroll', onReposition, true);
    }

    const open = (anchor) => {
      close();
      ensureStyle();
      anchorEl = anchor;

      const overlay = document.createElement('div');
      overlay.id = OVERLAY_ID;
      overlay.className = 'visible';

      const popup = document.createElement('div');
      popup.id = POPUP_ID;
      popup.innerHTML = `
        <div class="popup-header">
          <div class="popup-title">Lease IP Connection Test</div>
          <button class="popup-close" type="button" title="Close">&times;</button>
        </div>
        <div class="popup-body">
          <iframe class="popup-frame" title="Lease IP Connection Test"></iframe>
        </div>
      `;

      document.body.appendChild(overlay);
      document.body.appendChild(popup);

      const iframe = popup.querySelector('iframe');
      const joiner = TEST_URL.includes('?') ? '&' : '?';
      iframe.src = TEST_URL + joiner + '_ts=' + Date.now();

      positionPopup();
      setTimeout(() => popup.classList.add('visible'), 10);

      overlay.addEventListener('click', close);
      popup.querySelector('.popup-close')?.addEventListener('click', close);
      document.addEventListener('keydown', onKeyDown);
      window.addEventListener('resize', onReposition);
      window.addEventListener('scroll', onReposition, true);
    };

    const bindButtons = () => {
      const buttons = document.querySelectorAll('.btn-test-connection');
      buttons.forEach((btn) => {
        btn.addEventListener('click', () => open(btn));
      });
    };

    return { bindButtons };
  })();

  // === Shared Geo Popover (admin-only attach, safe no-op for users) ============
  const GeoUI = (window.LUMGeo && typeof window.LUMGeo.createPopover === 'function')
    ? window.LUMGeo.createPopover({ apiBase: API })
    : null;

  // === User toggle IP button ===================================================
  TestConnectionUI.bindButtons();

  const btnToggleIp = document.getElementById('btn-toggle-ip');
  const setBusy = (el, busy) => el && (el.disabled = !!busy);

  let refreshMine = null;
  let adminSoftRefresh = null;
  let ipInTable = false; // Track if user's IP is in the table

  const updateToggleButton = (hasIp) => {
    if (!btnToggleIp) return;
    ipInTable = hasIp;
    if (hasIp) {
      btnToggleIp.textContent = 'Remove my IP';
      btnToggleIp.className = 'btn btn-soft btn-pill';
    } else {
      btnToggleIp.textContent = 'Add my IP';
      btnToggleIp.className = 'btn btn-primary btn-pill';
    }
  };

  btnToggleIp?.addEventListener('click', async () => {
    setBusy(btnToggleIp, true);
    try {
      if (ipInTable) {
        // Remove IP
        await callOne('delete', clientIp || '');
      } else {
        // Add IP
        await callOne('add', clientIp || '');
      }
      if (typeof refreshMine === 'function') refreshMine({ force: true });
      if (typeof adminSoftRefresh === 'function') adminSoftRefresh({ force: true });
    } catch (e) {
      console.error('Toggle IP failed:', e.message);
    } finally { setBusy(btnToggleIp, false); }
  });

  // === "MY LEASES" (non-admins) ===============================================
  (function initMyLeasesIfPresent() {
    const myTbody = document.getElementById('my-tbody');
    if (!myTbody) return;
    const myCount = document.getElementById('my-count');
    const myRefreshBtn = document.getElementById('my-refresh');
    const myStatus = document.getElementById('my-status');

    let myEtag = '';
    let myHash = '';
    let myPoll = null;

    const renderRows = (entries) => {
      myTbody.innerHTML = '';
      const ttlHrs = 96;
      const now = nowMs();
      for (const ent of entries) {
        const tr = document.createElement('tr');

        const tdUser = document.createElement('td');
        tdUser.textContent = ent.user || ent.label || ent.host || 'unknown';

        const tdSource = document.createElement('td');
        tdSource.textContent = (ent.source && String(ent.source).trim()) ? ent.source : '—';

        const tdTs = document.createElement('td');
        tdTs.textContent = ent.timestamp || '';

        const tdIp = document.createElement('td');
        // Show IP; for admins only we attach geo. For non-admin table we leave plain.
        const myIpCode = document.createElement('code');
        myIpCode.textContent = ent.ip || '';
        tdIp.appendChild(myIpCode);

        const tdExp = document.createElement('td');
        let expText = '—';
        let expTitle = '';
        if (ent.static === true) {
          expText = 'static';
        } else {
          const tsms = getTimestampMs(ent);
          if (Number.isFinite(tsms)) {
            const expAt = tsms + ttlHrs * 3600000;
            expText = fmtRemaining(expAt - now);
            expTitle = new Date(expAt).toLocaleString();
          }
        }
        tdExp.textContent = expText;
        if (expTitle) tdExp.title = expTitle;

        const tdAct = document.createElement('td');
        tdAct.className = 'text-right';

        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete';
        delBtn.className = 'btn btn-default btn-sm';
        delBtn.addEventListener('click', async () => {
          delBtn.disabled = true;
          try {
            await callOne('delete', ent.ip);
            await refreshMine({ force: true });
            myStatus.textContent = `Deleted ${ent.ip}`;
          } catch (e) {
            myStatus.textContent = 'Delete failed: ' + e.message;
          } finally { delBtn.disabled = false; }
        });

        const staticBtn = document.createElement('button');
        staticBtn.textContent = (ent.static === true) ? 'Unset Static' : 'Set Static';
        staticBtn.className = 'btn btn-default btn-sm';
        staticBtn.style.marginLeft = '0.5rem';
        staticBtn.addEventListener('click', async () => {
          staticBtn.disabled = true;
          try {
            const makeStatic = !(ent.static === true);
            await callOne('add', ent.ip, { 'X-LUM-Static': makeStatic ? '1' : '0' });
            await refreshMine({ force: true });
            myStatus.textContent = makeStatic ? `Marked static: ${ent.ip}` : `Unmarked static: ${ent.ip}`;
          } catch (e) {
            myStatus.textContent = 'Static toggle failed: ' + e.message;
          } finally {
            staticBtn.disabled = false;
          }
        });

        tdAct.appendChild(delBtn);
        tdAct.appendChild(staticBtn);

        tr.appendChild(tdUser);
        tr.appendChild(tdSource);
        tr.appendChild(tdTs);
        tr.appendChild(tdIp);
        tr.appendChild(tdExp);
        tr.appendChild(tdAct);
        myTbody.appendChild(tr);
      }
      myCount.textContent = String(entries.length);

      // Update toggle button based on whether client IP is in the table
      const hasMyIp = entries.some(e => e.ip === clientIp);
      updateToggleButton(hasMyIp);
    };

    const hashEntries = (entries) => {
      try { return JSON.stringify(entries); } catch { return String(entries?.length || 0); }
    };

    refreshMine = async function ({ force = false } = {}) {
      const headers = { 'Cache-Control': 'no-store' };
      if (!force && myEtag) headers['If-None-Match'] = myEtag;

      const res = await fetch(API + '?list=1', { credentials: 'include', headers });
      if (res.status === 304) {
        myStatus.textContent = `Up to date · ${new Date().toLocaleTimeString()}`;
        return;
      }
      if (!res.ok) { myStatus.textContent = `HTTP ${res.status}`; return; }

      let data;
      try { data = await res.json(); } catch { myStatus.textContent = 'Invalid JSON from API'; return; }
      if (data.ok === false) { myStatus.textContent = data.error || 'API error'; return; }

      const et = res.headers.get('ETag') || '';
      if (et) myEtag = et;

      const entries = (data.entries || []);
      const h = hashEntries(entries);
      if (force || h !== myHash) {
        renderRows(entries);
        myHash = h;
        myStatus.textContent = `Updated · ${new Date().toLocaleTimeString()}`;
      } else {
        myStatus.textContent = `No changes · ${new Date().toLocaleTimeString()}`;
      }
    };

    function startMyPoller() {
      if (myPoll) clearInterval(myPoll);
      myPoll = setInterval(() => refreshMine({ force: false }), document.hidden ? 60000 : 20000);
    }

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) refreshMine({ force: true });
    });
    myRefreshBtn?.addEventListener('click', () => refreshMine({ force: true }));

    refreshMine({ force: true });
    startMyPoller();
  })();

  // === Admin live list (adds GeoUI on IP cells) ================================
  (function initAdminIfPresent() {
    const tbody = document.getElementById('tbody');
    if (!tbody) return;

    const count = document.getElementById('count');
    const btnRefresh = document.getElementById('btn-refresh');
    const btnClear = document.getElementById('btn-clear');
    const btnPrune = document.getElementById('btn-prune');
    const pruneHours = document.getElementById('prune-hours');
    const adminStatus = document.getElementById('admin-status');
    const manualIp = document.getElementById('manual-ip');
    const manualStatic = document.getElementById('manual-static');
    const btnAddManual = document.getElementById('btn-add-manual');

    let currentEntries = [];
    let lastHash = '';
    let lastEtag = '';
    let pollTimer = null;
    let countdownTimer = null;
    let inFlight = null;
    let backoffMs = 0;

    const POLL_VISIBLE_MS = 15000;
    const POLL_HIDDEN_MS  = 60000;
    const COUNTDOWN_TICK_MS = 10000;

    const setStatus = (msg) => { adminStatus.textContent = msg || ''; };

    const renderRows = (entries) => {
      tbody.innerHTML = '';
      const ttlHrs = parseFloat(pruneHours?.value || '96');
      const now = nowMs();

      for (const ent of entries) {
        const tr = document.createElement('tr');

        const tdUser = document.createElement('td');
        tdUser.textContent = ent.user || ent.label || ent.host || 'unknown';

        const tdSource = document.createElement('td');
        tdSource.textContent = (ent.source && String(ent.source).trim()) ? ent.source : '—';

        const tdTs = document.createElement('td');
        tdTs.textContent = ent.timestamp || '';

        const tdIp = document.createElement('td');
        // Make the IP clickable with geo popup for admins
        if (ent.ip) {
          const ipCode = document.createElement('code');
          ipCode.textContent = ent.ip;
          const ipSpan = document.createElement('a');
          ipSpan.href = '#';
          ipSpan.appendChild(ipCode);
          tdIp.appendChild(ipSpan);
          if (isAdmin && GeoUI) GeoUI.attach(ipSpan, ent.ip);
        } else {
          tdIp.textContent = '';
        }

        const tdExp = document.createElement('td');
        let expText = '—';
        let expTitle = '';
        if (ent.static === true) {
          expText = 'static';
        } else {
          const tsms = getTimestampMs(ent);
          if (Number.isFinite(tsms)) {
            const expAt = tsms + ttlHrs * 3600000;
            expText = fmtRemaining(expAt - now);
            expTitle = new Date(expAt).toLocaleString();
          }
        }
        tdExp.textContent = expText;
        if (expTitle) tdExp.title = expTitle;

        const tdAct = document.createElement('td');
        tdAct.className = 'text-right';

        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete';
        delBtn.className = 'btn btn-default btn-sm';
        delBtn.addEventListener('click', async () => {
          delBtn.disabled = true;
          try {
            await callOne('delete', ent.ip);
            await adminSoftRefresh({ force: true });
            setStatus(`Deleted ${ent.ip}`);
          } catch (e) {
            setStatus('Delete failed: ' + e.message);
          } finally {
            delBtn.disabled = false;
          }
        });

        const staticBtn = document.createElement('button');
        staticBtn.textContent = (ent.static === true) ? 'Unset Static' : 'Set Static';
        staticBtn.className = 'btn btn-default btn-sm';
        staticBtn.style.marginLeft = '0.5rem';
        staticBtn.addEventListener('click', async () => {
          staticBtn.disabled = true;
          try {
            const makeStatic = !(ent.static === true);
            await callOne('add', ent.ip, { 'X-LUM-Static': makeStatic ? '1' : '0' });
            await adminSoftRefresh({ force: true });
            setStatus(makeStatic ? `Marked static: ${ent.ip}` : `Unmarked static: ${ent.ip}`);
          } catch (e) {
            setStatus('Static toggle failed: ' + e.message);
          } finally {
            staticBtn.disabled = false;
          }
        });

        tdAct.appendChild(delBtn);
        tdAct.appendChild(staticBtn);

        tr.appendChild(tdUser);
        tr.appendChild(tdSource);
        tr.appendChild(tdTs);
        tr.appendChild(tdIp);
        tr.appendChild(tdExp);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
      count.textContent = String(entries.length);

      // Update toggle button based on whether client IP is in the table
      const hasMyIp = entries.some(e => e.ip === clientIp);
      updateToggleButton(hasMyIp);
    };

    const hashEntries = (entries) => {
      try { return JSON.stringify(entries); } catch { return String(entries?.length || 0); }
    };

    const fetchList = async (opts = {}) => {
      const { signal } = opts;
      const url = API + '?list=1';
      const headers = { 'Cache-Control': 'no-store' };
      if (lastEtag) headers['If-None-Match'] = lastEtag;

      const res = await fetch(url, { credentials: 'include', headers, signal });
      if (res.status === 304) {
        return { entries: null, etag: lastEtag, notModified: true };
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      let data;
      try { data = await res.json(); } catch { throw new Error('Invalid JSON from API'); }
      if (data.ok === false) throw new Error(data.error || 'API error');

      const etag = res.headers.get('ETag') || '';
      return { entries: (data.entries || []), etag, notModified: false };
    };

    const applyEntriesIfChanged = (entries, { force = false } = {}) => {
      if (!entries) return false;
      const h = hashEntries(entries);
      if (!force && h === lastHash) return false;
      currentEntries = entries;
      lastHash = h;
      renderRows(currentEntries);
      return true;
    };

    async function softRefresh({ force = false } = {}) {
      try { inFlight?.abort(); } catch {}
      inFlight = new AbortController();

      if (force) setStatus('Updating...'); else setStatus('');
      try {
        const { entries, etag, notModified } = await fetchList({ signal: inFlight.signal });
        if (etag) lastEtag = etag;

        if (notModified) {
          setStatus(`Up to date · ${new Date().toLocaleTimeString()}`);
        } else {
          const changed = applyEntriesIfChanged(entries, { force });
          setStatus(`Updated ${changed ? '' : '(no changes)'} · ${new Date().toLocaleTimeString()}`);
        }
        backoffMs = 0;
      } catch (e) {
        backoffMs = Math.min((backoffMs ? backoffMs * 2 : 2000), 60000);
        setStatus(`Connection issue: ${e.message}. Retrying in ${Math.round(backoffMs / 1000)}s…`);
        scheduleNextPoll(backoffMs);
      }
    }
    adminSoftRefresh = softRefresh;

    function pollIntervalMs() { return document.hidden ? POLL_HIDDEN_MS : POLL_VISIBLE_MS; }
    function clearPoller() { if (pollTimer) { clearTimeout(pollTimer); clearInterval(pollTimer); pollTimer = null; } }
    function startPoller() { clearPoller(); pollTimer = setInterval(() => softRefresh({ force: false }), pollIntervalMs()); }
    function scheduleNextPoll(ms) { clearPoller(); pollTimer = setTimeout(() => { softRefresh({ force: false }).finally(() => startPoller()); }, ms); }

    function startCountdownTicker() {
      if (countdownTimer) clearInterval(countdownTimer);
      countdownTimer = setInterval(() => {
        if (currentEntries && currentEntries.length) renderRows(currentEntries);
      }, COUNTDOWN_TICK_MS);
    }

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) { softRefresh({ force: true }).finally(startPoller); }
      else { startPoller(); }
    });

    window.addEventListener('online', () => softRefresh({ force: true }));
    window.addEventListener('offline', () => setStatus('Offline'));

    btnRefresh?.setAttribute('title', 'Manual refresh (auto-refresh is on)');
    btnRefresh?.addEventListener('click', () => softRefresh({ force: true }));

    btnClear?.addEventListener('click', async () => {
      if (!confirm('Clear ALL entries?')) return;
      btnClear.disabled = true;
      try {
        await callOne('clear', '1');
        await softRefresh({ force: true });
        setStatus('Cleared all');
      } catch (e) {
        setStatus('Clear failed: ' + e.message);
      } finally {
        btnClear.disabled = false;
      }
    });

    btnPrune?.addEventListener('click', async () => {
      const n = parseInt(pruneHours.value, 10);
      if (!(n > 0)) return setStatus('Enter a positive hour count.');
      btnPrune.disabled = true;
      try {
        await callOne('prune', String(n));
        await softRefresh({ force: true });
        setStatus(`Pruned entries older than ${n} hours`);
      } catch (e) {
        setStatus('Prune failed: ' + e.message);
      } finally {
        btnPrune.disabled = false;
      }
    });

    manualIp?.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') { ev.preventDefault(); btnAddManual?.click(); }
    });

    btnAddManual?.addEventListener('click', async () => {
      const ip = (manualIp?.value || '').trim();
      if (!ip) { setStatus('Enter an IP address.'); return; }
      btnAddManual.disabled = true;
      try {
        const hdrs = manualStatic?.checked ? { 'X-LUM-Static': '1' } : undefined;
        const r = await callOne('add', ip, hdrs);
        await softRefresh({ force: true });
        setStatus((r.result === 'exists') ? `Already present: ${r.ip}` : `Added: ${r.ip}`);
        manualIp.value = '';
        if (manualStatic) manualStatic.checked = false;
      } catch (e) {
        setStatus('Add failed: ' + e.message);
      } finally {
        btnAddManual.disabled = false;
      }
    });

    // Kickoff admin list
    softRefresh({ force: true });
    startPoller();
    startCountdownTicker();
  })();
})();
