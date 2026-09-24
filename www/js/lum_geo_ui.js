(function () {
  'use strict';

  if (window.LUMGeo && typeof window.LUMGeo.createPopover === 'function') {
    return;
  }

  const DEFAULT_API = '/lease_ip/api.php';
  const STYLE_ID = 'lum-geo-style';
  const FRONT_TTL_MS = 600000;
  const HOVER_DELAY_MS = 220;
  const CLOSE_DELAY_MS = 180;

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch];
    });
  }

  function normalizeIpForLookup(value) {
    let raw = String(value == null ? '' : value).trim();
    if (!raw || raw === '?') {
      return '';
    }
    if (raw.indexOf('/') !== -1) {
      raw = raw.split('/')[0].trim();
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) {
      const parts = raw.split('.').map(function (v) {
        return parseInt(v, 10);
      });
      if (parts.length === 4 && parts.every(function (p) {
        return p >= 0 && p <= 255;
      })) {
        return raw;
      }
      return '';
    }
    if (raw.indexOf(':') !== -1 && /^[0-9a-fA-F:]+$/.test(raw)) {
      return raw;
    }
    return '';
  }

  function injectStyleOnce() {
    if (document.getElementById(STYLE_ID)) {
      return;
    }
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = '\n'
      + '#lum-geo-pop {\n'
      + '  position: fixed; z-index: 99999; min-width: 280px; max-width: 520px;\n'
      + '  background: linear-gradient(\n'
      + '    135deg,\n'
      + '    var(--gradient-header, rgba(127,209,255,0.16)) 0%,\n'
      + '    var(--gradient-end, rgba(18,24,32,0.96)) 100%\n'
      + '  ), var(--bg-tertiary, #121820);\n'
      + '  backdrop-filter: blur(2px);\n'
      + '  border: 1px solid var(--border-hover, rgba(127,209,255,0.35));\n'
      + '  box-shadow: 0 0 24px var(--shadow-glow, rgba(42,139,220,0.35)), inset 0 0 20px rgba(255,255,255,0.04);\n'
      + '  border-radius: 14px; padding: 10px 12px 12px 12px; color: var(--text-primary, #cfe9ff);\n'
      + '}\n'
      + '#lum-geo-pop .cg-head {\n'
      + '  display:flex; align-items:center; gap:8px; margin-bottom:6px;\n'
      + '  text-transform:uppercase; letter-spacing: .45px; font-size: 12px; color:var(--accent, #9fd1ff);\n'
      + '}\n'
      + '#lum-geo-pop .cg-ip { font-family: monospace; background:var(--gradient-header, rgba(16,32,48,.7)); padding:2px 6px; border-radius: 8px; border:1px solid var(--border-primary, rgba(127,209,255,.35)); color:var(--accent, #a9e1ff); }\n'
      + '#lum-geo-pop .cg-grid {\n'
      + '  display:grid; grid-template-columns: 128px 1fr; gap:6px 12px; font-size: 12.5px;\n'
      + '}\n'
      + '#lum-geo-pop .cg-key { color:var(--text-muted, #9fb6c9); text-transform:uppercase; letter-spacing:.3px; }\n'
      + '#lum-geo-pop .cg-val { color:var(--text-primary, #e5f4ff); overflow-wrap:anywhere; }\n'
      + '#lum-geo-pop .cg-bad { color:#ffb3b3; }\n'
      + '#lum-geo-pop .cg-warn { color:#ffdf9a; }\n'
      + '#lum-geo-pop .cg-flags { display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }\n'
      + '#lum-geo-pop .chip {\n'
      + '  font-size: 11px; border-radius: 999px; padding:2px 8px; border:1px solid var(--border-primary, rgba(255,255,255,.18));\n'
      + '  background: var(--gradient-header, rgba(255,255,255,.04)); color:var(--text-primary, #bfe9ff);\n'
      + '}\n'
      + '#lum-geo-pop .chip.negative { background: rgba(255,80,80,.12); border-color: rgba(255,80,80,.35); color:#ffdcdc; }\n'
      + '#lum-geo-pop .chip.warn { background: rgba(255,200,60,.10); border-color: rgba(255,200,60,.35); color:#fff0cc; }\n'
      + '#lum-geo-pop .cg-foot { margin-top:8px; display:flex; gap:8px; justify-content:flex-end; }\n'
      + '#lum-geo-pop .btn-mini {\n'
      + '  font-size: 11px; padding: 4px 8px; border-radius: 10px; background:var(--gradient-start, #121820); color:var(--text-primary, #cfe9ff);\n'
      + '  border:1px solid var(--border-primary, rgba(255,255,255,.12)); cursor:pointer;\n'
      + '}\n'
      + '#lum-geo-pop .btn-mini:hover { background:var(--gradient-header, #17202b); border-color:var(--border-hover, rgba(127,209,255,.35)); }\n'
      + '.lum-ip-geo {\n'
      + '  cursor: help; border-bottom: 1px dotted var(--border-hover, rgba(127,209,255,.65)); color:var(--accent, #a9e1ff); text-decoration:none;\n'
      + '}\n'
      + '.lum-ip-geo:hover { color:var(--text-primary, #e9f7ff); }\n'
      + '#lum-geo-arrow {\n'
      + '  position: fixed; width: 0; height: 0; border: 8px solid transparent; z-index: 99998;\n'
      + '  border-right-color: var(--border-hover, rgba(127,209,255,0.35));\n'
      + '}\n'
      + '@media (max-width: 480px) {\n'
      + '  #lum-geo-pop { max-width: 90vw; }\n'
      + '  #lum-geo-pop .cg-grid { grid-template-columns: 100px 1fr; }\n'
      + '}\n';
    document.head.appendChild(style);
  }

  function createPopover(options) {
    options = options || {};
    const apiBase = typeof options.apiBase === 'string' && options.apiBase.trim()
      ? options.apiBase.trim()
      : DEFAULT_API;
    const frontTtlMs = Number.isFinite(options.frontTtlMs) && options.frontTtlMs > 0
      ? options.frontTtlMs
      : FRONT_TTL_MS;
    const hoverDelayMs = Number.isFinite(options.hoverDelayMs) && options.hoverDelayMs >= 0
      ? options.hoverDelayMs
      : HOVER_DELAY_MS;
    const closeDelayMs = Number.isFinite(options.closeDelayMs) && options.closeDelayMs >= 0
      ? options.closeDelayMs
      : CLOSE_DELAY_MS;

    const cache = new Map();
    let popEl = null;
    let arrowEl = null;
    let pinned = false;
    let hoverTimer = null;
    let closeTimer = null;
    let currentAnchor = null;
    let currentIp = '';

    function ensureElements() {
      if (popEl && arrowEl) {
        return;
      }
      popEl = document.createElement('div');
      popEl.id = 'lum-geo-pop';
      popEl.style.display = 'none';
      arrowEl = document.createElement('div');
      arrowEl.id = 'lum-geo-arrow';
      arrowEl.style.display = 'none';
      document.body.appendChild(popEl);
      document.body.appendChild(arrowEl);

      document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') {
          hide(true);
        }
      });
      document.addEventListener('click', function (ev) {
        if (!pinned) {
          return;
        }
        if (popEl && !popEl.contains(ev.target) && currentAnchor && !currentAnchor.contains(ev.target)) {
          hide(true);
        }
      });
      window.addEventListener('scroll', function () {
        if (pinned) {
          positionTo(currentAnchor);
        } else {
          hide(false);
        }
      }, true);
      window.addEventListener('resize', function () {
        if (pinned) {
          positionTo(currentAnchor);
        } else {
          hide(false);
        }
      });
    }

    function renderContent(ip, payload) {
      const geo = payload && payload.geo ? payload.geo : {};
      if (geo.status && geo.status !== 'success') {
        popEl.innerHTML =
          '<div class="cg-head"><span class="cg-ip">' + escapeHtml(ip) + '</span><span class="cg-bad">lookup failed</span></div>' +
          '<div class="cg-grid"><div class="cg-key">Message</div><div class="cg-val cg-bad">' + escapeHtml(geo.message || 'Unknown error') + '</div></div>';
        return;
      }

      const loc = [geo.city, geo.regionName, geo.countryCode ? (geo.country + ' (' + geo.countryCode + ')') : geo.country, geo.zip]
        .filter(Boolean)
        .join(' · ');
      const asn = String(geo.asname || geo.as || '');

      popEl.innerHTML =
        '<div class="cg-head">' +
          '<span class="cg-ip">' + escapeHtml(ip) + '</span>' +
          ((payload && payload.cached) ? '<span class="chip">cached</span>' : '') +
        '</div>' +
        '<div class="cg-grid">' +
          '<div class="cg-key">Location</div><div class="cg-val">' + escapeHtml(loc || '—') + '</div>' +
          '<div class="cg-key">ISP</div><div class="cg-val">' + escapeHtml(geo.isp || '—') + '</div>' +
          '<div class="cg-key">Org</div><div class="cg-val">' + escapeHtml(geo.org || '—') + '</div>' +
          '<div class="cg-key">ASN</div><div class="cg-val">' + escapeHtml(asn || '—') + '</div>' +
          '<div class="cg-key">Timezone</div><div class="cg-val">' + escapeHtml(geo.timezone || '—') + '</div>' +
          '<div class="cg-key">Reverse</div><div class="cg-val">' + escapeHtml(geo.reverse || '—') + '</div>' +
          '<div class="cg-key">Coords</div><div class="cg-val">' + ((geo.lat != null && geo.lon != null) ? escapeHtml(geo.lat + ', ' + geo.lon) : '—') + '</div>' +
        '</div>' +
        '<div class="cg-flags">' +
          (geo.proxy ? '<span class="chip negative">proxy</span>' : '') +
          (geo.hosting ? '<span class="chip warn">hosting/DC</span>' : '') +
          (geo.mobile ? '<span class="chip warn">mobile</span>' : '') +
          (geo.continent ? '<span class="chip">' + escapeHtml(geo.continentCode || '') + ' ' + escapeHtml(geo.continent) + '</span>' : '') +
          (geo.country ? '<span class="chip">' + escapeHtml(geo.country) + '</span>' : '') +
        '</div>' +
        '<div class="cg-foot">' +
          '<button class="btn-mini" data-act="copy">Copy IP</button>' +
          '<button class="btn-mini" data-act="close">Close</button>' +
        '</div>';

      const copyBtn = popEl.querySelector('[data-act="copy"]');
      if (copyBtn) {
        copyBtn.addEventListener('click', function () {
          if (!window.navigator.clipboard || typeof window.navigator.clipboard.writeText !== 'function') {
            return;
          }
          window.navigator.clipboard.writeText(ip).then(function () {
            copyBtn.textContent = 'Copied';
            setTimeout(function () {
              copyBtn.textContent = 'Copy IP';
            }, 1200);
          }).catch(function () {});
        });
      }
      const closeBtn = popEl.querySelector('[data-act="close"]');
      if (closeBtn) {
        closeBtn.addEventListener('click', function () {
          hide(true);
        });
      }
    }

    function positionTo(anchor) {
      if (!anchor || !popEl) {
        return;
      }
      const rect = anchor.getBoundingClientRect();
      const viewW = window.innerWidth;
      const viewH = window.innerHeight;
      const pad = 10;
      let left = rect.right + 10;
      let top = rect.top;
      const preferredWidth = Math.min(popEl.offsetWidth || 420, 520);

      if (left + preferredWidth + 16 > viewW) {
        left = Math.max(pad, rect.left - (preferredWidth + 18));
        if (left < pad) {
          left = Math.max(pad, viewW - preferredWidth - pad);
        }
      }
      if (top + (popEl.offsetHeight || 240) + 16 > viewH) {
        top = Math.max(pad, viewH - (popEl.offsetHeight || 240) - pad);
      }

      popEl.style.left = Math.round(left) + 'px';
      popEl.style.top = Math.round(top) + 'px';

      const arrowSize = 8;
      arrowEl.style.top = Math.round(rect.top + Math.min(rect.height / 2, Math.max(arrowSize + 2, (popEl.offsetHeight || 0) / 3))) + 'px';
      arrowEl.style.left = Math.round(Math.min(rect.right + 2, left - arrowSize)) + 'px';
    }

    function hide(force) {
      window.clearTimeout(closeTimer);
      if (force) {
        pinned = false;
      }
      if (pinned) {
        return;
      }
      if (popEl) {
        popEl.style.display = 'none';
      }
      if (arrowEl) {
        arrowEl.style.display = 'none';
      }
      currentAnchor = null;
      currentIp = '';
    }

    function lookup(ip) {
      const hit = cache.get(ip);
      const now = Date.now();
      if (hit && hit.data && (now - hit.t < frontTtlMs)) {
        return Promise.resolve(hit.data);
      }
      if (hit && hit.pending) {
        return hit.pending;
      }

      const pending = fetch(apiBase + '?geo=' + encodeURIComponent(ip), {
        credentials: 'include',
        headers: { 'Cache-Control': 'no-store' },
      })
        .then(function (res) {
          return res.json().catch(function () {
            return { ok: false, error: 'Invalid JSON' };
          }).then(function (json) {
            if (!res.ok || json.ok === false) {
              throw new Error(json.error || ('HTTP ' + res.status));
            }
            const payload = { cached: !!json.cached, geo: json.geo || {} };
            cache.set(ip, { t: now, data: payload });
            return payload;
          });
        })
        .finally(function () {
          const marker = cache.get(ip);
          if (marker && marker.pending === pending) {
            cache.delete(ip);
          }
        });

      cache.set(ip, { pending: pending });
      return pending;
    }

    function show(anchor, ip, payloadPromise) {
      window.clearTimeout(closeTimer);
      injectStyleOnce();
      ensureElements();

      currentAnchor = anchor;
      currentIp = ip;

      popEl.style.display = 'block';
      arrowEl.style.display = 'block';
      positionTo(anchor);

      payloadPromise.then(function (payload) {
        if (anchor !== currentAnchor || ip !== currentIp) {
          return;
        }
        renderContent(ip, payload);
        positionTo(anchor);
      }).catch(function (err) {
        if (anchor !== currentAnchor || ip !== currentIp) {
          return;
        }
        popEl.innerHTML =
          '<div class="cg-head"><span class="cg-ip">' + escapeHtml(ip) + '</span><span class="cg-bad">lookup failed</span></div>' +
          '<div class="cg-grid"><div class="cg-key">Error</div><div class="cg-val cg-bad">' + escapeHtml(err && err.message ? err.message : 'Request error') + '</div></div>';
      });
    }

    function attach(el, ipValue) {
      if (!el) {
        return;
      }
      const ip = normalizeIpForLookup(ipValue);
      if (!ip) {
        return;
      }
      if (el.dataset && el.dataset.lumGeoBound === ip) {
        return;
      }
      if (el.dataset) {
        el.dataset.lumGeoBound = ip;
      }

      el.classList.add('lum-ip-geo');
      el.addEventListener('mouseenter', function () {
        if (pinned) {
          return;
        }
        window.clearTimeout(hoverTimer);
        hoverTimer = setTimeout(function () {
          show(el, ip, lookup(ip));
        }, hoverDelayMs);
      });
      el.addEventListener('mouseleave', function () {
        if (pinned) {
          return;
        }
        window.clearTimeout(hoverTimer);
        closeTimer = setTimeout(function () {
          hide(false);
        }, closeDelayMs);
      });
      el.addEventListener('click', function (ev) {
        ev.preventDefault();
        if (pinned && currentAnchor === el) {
          hide(true);
          return;
        }
        pinned = true;
        show(el, ip, lookup(ip));
      });
    }

    return {
      attach: attach,
      hide: hide,
      lookup: lookup,
    };
  }

  window.LUMGeo = {
    createPopover: createPopover,
    normalizeIpForLookup: normalizeIpForLookup,
  };
})();
