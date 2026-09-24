<?php
declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');
require_once 'web_functions.inc.php';
require_once 'ldap_functions.inc.php';
require_once 'module_functions.inc.php';
@session_start();
set_page_access('admin');

$CSRF = csrf_get_token();
$API  = $THIS_MODULE_PATH . '/crowdsec_api.php';

function h(?string $s): string
{
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

render_header("$ORGANISATION_NAME account manager");
render_submenu();
?>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">
      <div class="panel-headline panel-headline--stacked">
        <h3 class="card-title">CrowdSec Bans</h3>
        <div class="panel-badges">
          <span class="badge-soft" id="ban_count">-- decisions</span>
        </div>
      </div>
      <button id="btn_refresh" class="btn btn-soft btn-pill btn-sm">Refresh</button>
    </div>

    <div class="card-body">
      <div id="loading_state">
        <div class="alert alert-info" role="alert" style="margin:0;">
          Loading decisions from CrowdSec...
        </div>
      </div>

      <div id="error_state" class="hidden">
        <div class="alert alert-warning" role="alert" style="margin:0;">
          <span id="error_msg">Failed to load decisions.</span>
        </div>
      </div>

      <div id="empty_state" class="hidden">
        <div class="alert alert-success" role="alert" style="margin:0;">
          No active bans.
        </div>
      </div>

      <div id="table_wrap" class="hidden">
        <p class="help-min" id="cs_updated" style="margin:0 0 8px 0;"></p>
        <div class="table-responsive">
          <table class="table table-dark table-striped table-modern" id="bans_table">
            <thead>
              <tr>
                <th>IP / Range</th>
                <th>Reason</th>
                <th>Origin</th>
                <th>Scope</th>
                <th>Duration</th>
                <th>Alert #</th>
                <th style="width:200px">Actions</th>
              </tr>
            </thead>
            <tbody id="bans_body"></tbody>
          </table>
        </div>
      </div>

      <div id="fp_wrap" class="hidden" style="margin-top:16px;">
        <h4 style="margin:0 0 10px 0;">Potential False Positives</h4>
        <div class="table-responsive">
          <table class="table table-dark table-striped table-modern" id="fp_table">
            <thead>
              <tr>
                <th>IP / User(s)</th>
                <th>Reason</th>
                <th>Origin</th>
                <th>Scope</th>
                <th>Duration</th>
                <th>Alert #</th>
              </tr>
            </thead>
            <tbody id="fp_body"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="container wrap-narrow" style="margin-top:24px;">
  <div class="card panel-modern">
    <div class="panel-heading" style="display:flex;align-items:center;justify-content:space-between;">
      <div class="panel-headline panel-headline--stacked">
        <h3 class="card-title">Edge Bans</h3>
        <div class="panel-badges">
          <span class="badge-soft" id="edge_count">-- IPs</span>
        </div>
      </div>
      <button id="btn_edge_refresh" class="btn btn-soft btn-pill btn-sm">Refresh</button>
    </div>

    <div class="card-body">
      <div id="edge_loading">
        <div class="alert alert-info" role="alert" style="margin:0;">
          Loading edge bans...
        </div>
      </div>

      <div id="edge_error" class="hidden">
        <div class="alert alert-warning" role="alert" style="margin:0;">
          <span id="edge_error_msg">Failed to load edge bans.</span>
        </div>
      </div>

      <div id="edge_empty" class="hidden">
        <div class="alert alert-success" role="alert" style="margin:0;">
          No edge bans.
        </div>
      </div>

      <div id="edge_table_wrap" class="hidden">
        <p class="help-min" id="edge_updated" style="margin:0 0 8px 0;"></p>
        <div class="table-responsive">
          <table class="table table-dark table-striped table-modern" id="edge_table">
            <thead>
              <tr>
                <th>IP / Range</th>
                <th style="width:200px">Actions</th>
              </tr>
            </thead>
            <tbody id="edge_body"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<script src="<?php echo $SERVER_PATH; ?>js/lum_geo_ui.min.js"></script>
<script>
(function(){
  var API  = <?php echo json_encode($API); ?>;
  var CSRF = <?php echo json_encode($CSRF); ?>;
  var GEO_API = '/lease_ip/api.php';
  var GeoUI = (window.LUMGeo && typeof window.LUMGeo.createPopover === 'function')
    ? window.LUMGeo.createPopover({ apiBase: GEO_API })
    : null;

  var $loading  = document.getElementById('loading_state');
  var $error    = document.getElementById('error_state');
  var $errorMsg = document.getElementById('error_msg');
  var $empty    = document.getElementById('empty_state');
  var $tableW   = document.getElementById('table_wrap');
  var $tbody    = document.getElementById('bans_body');
  var $fpWrap   = document.getElementById('fp_wrap');
  var $fpBody   = document.getElementById('fp_body');
  var $count    = document.getElementById('ban_count');

  var $csUpdated = document.getElementById('cs_updated');

  function show(el){ el.classList.remove('hidden'); }
  function hide(el){ el.classList.add('hidden'); }

  function formatTimestamp(d){
    if(!(d instanceof Date)) d = new Date();
    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    var h = d.getHours(), m = d.getMinutes(), ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear() + ' ' +
      h + ':' + (m < 10 ? '0' : '') + m + ' ' + ampm;
  }

  function showToast(msg, isError){
    var t = document.createElement('div');
    t.className = 'alert ' + (isError ? 'alert-warning' : 'alert-success');
    t.style.cssText = 'position:fixed;top:80px;right:20px;z-index:9999;min-width:280px;max-width:480px;box-shadow:0 4px 20px rgba(0,0,0,.5);';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function(){ t.remove(); }, 4000);
  }

  function extractGeoIp(value){
    if (window.LUMGeo && typeof window.LUMGeo.normalizeIpForLookup === 'function') {
      return window.LUMGeo.normalizeIpForLookup(value);
    }
    return '';
  }

  function normalizeIpFallback(value){
    var raw = value == null ? '' : String(value).trim();
    if(!raw) return '';

    if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)){
      var parts = raw.split('.');
      var ok = parts.every(function(part){
        var n = Number(part);
        return Number.isInteger(n) && n >= 0 && n <= 255;
      });
      return ok ? raw : '';
    }

    if(raw.indexOf(':') !== -1 && /^[0-9a-f:.]+$/i.test(raw)){
      return raw;
    }

    return '';
  }

  function normalizeMatchIp(value){
    var raw = value == null ? '' : String(value).trim();
    if(!raw) return '';
    var prefixed = raw.match(/^(?:ip|range|cidr|asn|country):(.+)$/i);
    if(prefixed){
      raw = String(prefixed[1] || '').trim();
    }
    var ip = extractGeoIp(raw);
    if(!ip) ip = normalizeIpFallback(raw);
    if(ip) return ip;
    if(raw.indexOf('/') !== -1){
      var base = raw.split('/', 2)[0];
      ip = extractGeoIp(base);
      if(!ip) ip = normalizeIpFallback(base);
      if(ip) return ip;
    }
    return '';
  }

  /* ---------- Poll helper ------------------------------------------------- */
  function pollResult(actionId, cb){
    var tries = 0;
    var poll = function(){
      tries++;
      fetch(API + '?action=result&id=' + encodeURIComponent(actionId) + '&t=' + Date.now(), {
        credentials:'include',
        cache: 'no-store'
      })
        .then(function(r){
          if(r.status === 404){
            if(tries < 40) setTimeout(poll, 750);
            else cb({ok:false, details:'Timed out waiting for result'});
            return null;
          }
          return r.json();
        })
        .then(function(j){
          if(j) cb(j);
        })
        .catch(function(e){
          if(tries < 40) setTimeout(poll, 750);
          else cb({ok:false, details:'Network error: ' + e.message});
        });
    };
    poll();
  }

  /* ---------- Load decisions ---------------------------------------------- */
  function loadDecisions(){
    hide($error); hide($empty); hide($tableW);
    if($fpWrap){
      hide($fpWrap);
    }
    show($loading);
    $count.textContent = '-- decisions';
    if($tbody){
      $tbody.innerHTML = '';
    }
    if($fpBody){
      $fpBody.innerHTML = '';
    }

    var body = new URLSearchParams();
    body.append('op', 'decisions.list');

    fetch(API + '?t=' + Date.now(), {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials:'include',
      cache: 'no-store',
      body: body
    })
      .then(function(r){ return r.json(); })
      .then(function(j){
        if(!j.ok){
          hide($loading);
          $errorMsg.textContent = j.error || 'Failed to queue list job';
          show($error);
          return;
        }
        pollResult(j.action_id, function(res){
          hide($loading);
          if(!res.ok){
            $errorMsg.textContent = res.details || res.stderr || 'Failed to list decisions';
            show($error);
            return;
          }
          renderDecisions(res.data || [], res.potential_false_positives || {});
        });
      })
      .catch(function(e){
        hide($loading);
        $errorMsg.textContent = 'Network error: ' + e.message;
        show($error);
      });
  }

  /* ---------- Render table ------------------------------------------------ */
  function esc(s){
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function pushUnique(arr, value){
    if(value == null) return;
    var v = String(value).trim();
    if(!v) return;
    if(arr.indexOf(v) === -1){
      arr.push(v);
    }
  }

  function parseNumericId(value){
    var v = value == null ? '' : String(value).trim();
    return /^\d+$/.test(v) ? v : '';
  }

  function parseNumericIdList(value){
    var out = [];
    if(value == null) return out;
    String(value).split(',').forEach(function(part){
      var id = parseNumericId(part);
      if(id){
        pushUnique(out, id);
      }
    });
    return out;
  }

  function inspectButtonLabel(targetCount){
    return targetCount > 1 ? ('More Info (' + targetCount + ')') : 'More Info';
  }

  function parseMetaEntries(metaEntries){
    var out = Object.create(null);
    if(!Array.isArray(metaEntries)) return out;
    metaEntries.forEach(function(entry){
      if(!entry || typeof entry !== 'object') return;
      var k = entry.key == null ? '' : String(entry.key).trim();
      if(!k) return;
      out[k] = entry.value == null ? '' : String(entry.value);
    });
    return out;
  }

  function parseJsonArrayString(value){
    var raw = value == null ? '' : String(value).trim();
    if(!raw) return [];
    try {
      var parsed = JSON.parse(raw);
      if(Array.isArray(parsed)){
        return parsed.map(function(v){ return String(v); }).filter(Boolean);
      }
    } catch(_e) {}
    return [raw];
  }

  function trimList(values, maxCount){
    if(!Array.isArray(values)) return [];
    var list = values.filter(function(v){ return v != null && String(v).trim() !== ''; }).map(function(v){ return String(v).trim(); });
    if(list.length <= maxCount) return list;
    var out = list.slice(0, maxCount);
    out.push('+' + (list.length - maxCount) + ' more');
    return out;
  }

  function getEventBreakdown(events){
    var methods = [];
    var statuses = [];
    var paths = [];
    var userAgents = [];
    var pathCounts = Object.create(null);
    var firstTs = '';
    var lastTs = '';

    if(!Array.isArray(events)){
      return {
        methods: methods,
        statuses: statuses,
        paths: paths,
        userAgentsCount: 0,
        topPaths: [],
        firstTs: firstTs,
        lastTs: lastTs
      };
    }

    events.forEach(function(event){
      var metaMap = parseMetaEntries(event && event.meta);
      var method = String(metaMap.http_verb || '').trim();
      var status = String(metaMap.http_status || '').trim();
      var path = String(metaMap.http_path || '').trim();
      var ua = String(metaMap.http_user_agent || '').trim();
      var ts = String(metaMap.timestamp || (event && event.timestamp) || '').trim();

      pushUnique(methods, method);
      pushUnique(statuses, status);
      pushUnique(paths, path);
      pushUnique(userAgents, ua);

      if(path){
        pathCounts[path] = (pathCounts[path] || 0) + 1;
      }
      if(ts){
        if(!firstTs || ts < firstTs) firstTs = ts;
        if(!lastTs || ts > lastTs) lastTs = ts;
      }
    });

    var topPaths = Object.keys(pathCounts)
      .sort(function(a, b){ return pathCounts[b] - pathCounts[a]; })
      .map(function(path){ return path + ' (' + pathCounts[path] + ')'; });

    return {
      methods: methods,
      statuses: statuses,
      paths: paths,
      userAgentsCount: userAgents.length,
      topPaths: topPaths,
      firstTs: firstTs,
      lastTs: lastTs
    };
  }

  function inspectSummaryRow(label, value){
    var text = '';
    if(Array.isArray(value)){
      text = value.join(', ');
    } else if(value != null){
      text = String(value).trim();
    }
    if(!text) return '';
    return (
      '<div style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap;margin:2px 0;">' +
        '<span style="opacity:.75;min-width:104px;">' + esc(label) + ':</span>' +
        '<span style="word-break:break-word;">' + esc(text) + '</span>' +
      '</div>'
    );
  }

  function buildInspectObjectHtml(header, payload){
    var decisions = Array.isArray(payload && payload.decisions) ? payload.decisions : [];
    var decision = decisions.length ? decisions[0] : null;
    var source = (payload && typeof payload.source === 'object' && payload.source) ? payload.source : {};
    var metaMap = parseMetaEntries(payload && payload.meta);
    var eventBreakdown = getEventBreakdown(payload && payload.events);

    var methods = parseJsonArrayString(metaMap.method);
    if(!methods.length) methods = eventBreakdown.methods;
    methods = trimList(methods, 6);

    var statuses = parseJsonArrayString(metaMap.status);
    if(!statuses.length) statuses = eventBreakdown.statuses;
    statuses = trimList(statuses, 6);

    var uris = parseJsonArrayString(metaMap.target_uri);
    if(!uris.length) uris = eventBreakdown.topPaths.length ? eventBreakdown.topPaths : eventBreakdown.paths;
    uris = trimList(uris, 8);

    var uaList = parseJsonArrayString(metaMap.user_agent);
    var uaCount = uaList.length || eventBreakdown.userAgentsCount;

    var sourceIp = source.ip || source.value || (decision && decision.value) || '';
    var sourceAsn = source.as_number && source.as_name
      ? (source.as_number + ' (' + source.as_name + ')')
      : (source.as_name || source.as_number || '');
    var timeWindow = '';
    if(payload && payload.start_at && payload.stop_at){
      timeWindow = payload.start_at + ' -> ' + payload.stop_at;
    } else {
      timeWindow = (payload && payload.start_at) || (payload && payload.stop_at) || '';
    }
    var eventWindow = '';
    if(eventBreakdown.firstTs && eventBreakdown.lastTs){
      eventWindow = eventBreakdown.firstTs + ' -> ' + eventBreakdown.lastTs;
    }

    var rows = '';
    rows += inspectSummaryRow('Scenario', payload && payload.scenario);
    rows += inspectSummaryRow('Source IP', sourceIp);
    rows += inspectSummaryRow('Decision', decision ? ([decision.type, decision.scope, decision.value].filter(Boolean).join(' ')) : '');
    rows += inspectSummaryRow('Duration', decision && decision.duration);
    rows += inspectSummaryRow('Events', payload && payload.events_count);
    rows += inspectSummaryRow('Methods', methods);
    rows += inspectSummaryRow('Status', statuses);
    rows += inspectSummaryRow('Targets', uris);
    rows += inspectSummaryRow('Geo/ASN', [source.cn || '', sourceAsn || '', source.range || ''].filter(Boolean).join(' | '));
    rows += inspectSummaryRow('Created', payload && payload.created_at);
    rows += inspectSummaryRow('Window', timeWindow);
    rows += inspectSummaryRow('Event Span', eventWindow);
    rows += inspectSummaryRow('User Agents', uaCount ? (uaCount + ' unique') : '');
    rows += inspectSummaryRow('Leak Speed', payload && payload.leakspeed);
    rows += inspectSummaryRow('Message', payload && payload.message);

    return (
      '<div style="margin:0 0 10px 0;padding:10px 12px;border:1px solid rgba(120,138,255,.25);border-radius:10px;background:rgba(16,20,44,.45);">' +
        '<div style="font-weight:700;letter-spacing:.02em;margin-bottom:8px;">' + esc(header) + '</div>' +
        rows +
        '<details style="margin-top:8px;">' +
          '<summary style="cursor:pointer;opacity:.85;">Raw JSON</summary>' +
          '<pre style="margin:8px 0 0;white-space:pre-wrap;word-break:break-all;color:var(--text-primary,#d7e7ff);font-size:12px;max-height:360px;overflow:auto;">' + esc(JSON.stringify(payload, null, 2)) + '</pre>' +
        '</details>' +
      '</div>'
    );
  }

  function buildInspectDetailHtml(targets, results){
    var blocks = [];
    var i;
    for(i = 0; i < targets.length; i++){
      var target = targets[i];
      var result = results[i] || {ok:false, details:'missing response'};
      var header = target.type === 'alert'
        ? ('Alert #' + target.id)
        : ('Decision #' + target.id);

      if(result && result.ok){
        var detail = result.data != null
          ? result.data
          : (result.details != null ? result.details : '(no data)');
        if(detail && typeof detail === 'object' && !Array.isArray(detail)){
          blocks.push(buildInspectObjectHtml(header, detail));
        } else {
          blocks.push(
            '<div style="margin:0 0 10px 0;padding:10px 12px;border:1px solid rgba(120,138,255,.25);border-radius:10px;background:rgba(16,20,44,.45);">' +
              '<div style="font-weight:700;letter-spacing:.02em;margin-bottom:8px;">' + esc(header) + '</div>' +
              '<pre style="margin:0;white-space:pre-wrap;word-break:break-all;color:var(--text-primary,#d7e7ff);font-size:12px;max-height:360px;overflow:auto;">' + esc(String(detail)) + '</pre>' +
            '</div>'
          );
        }
      } else {
        blocks.push(
          '<div style="margin:0 0 10px 0;padding:10px 12px;border:1px solid rgba(255,98,98,.35);border-radius:10px;background:rgba(58,16,16,.45);">' +
            '<div style="font-weight:700;letter-spacing:.02em;margin-bottom:6px;">' + esc(header) + '</div>' +
            '<div style="color:#ffc4c4;">' + esc(String((result && (result.details || result.stderr || result.error)) || 'unknown error')) + '</div>' +
          '</div>'
        );
      }
    }
    return blocks.join('');
  }

  function groupDecisionsByTarget(decisions){
    var groups = [];
    var index = Object.create(null);

    decisions.forEach(function(d){
      var source   = (d && typeof d.source === 'object' && d.source) ? d.source : {};
      var ip       = d.value || d.ip || source.value || source.ip || '?';
      var reason   = d.scenario || d.reason || '';
      var origin   = d.origin || '';
      var scope    = d.scope || source.scope || '';
      var duration = d.duration || '';
      var alertId  = parseNumericId(d.alert_id);
      var decId    = parseNumericId(d.id);
      var key      = String(ip);
      var group    = index[key];

      if(!group){
        group = {
          ip: String(ip),
          scopes: [],
          reasons: [],
          origins: [],
          durations: [],
          alertIds: [],
          decisionIds: [],
          inspectAlertIds: [],
          inspectDecisionIds: []
        };
        index[key] = group;
        groups.push(group);
      }

      pushUnique(group.scopes, scope);
      pushUnique(group.reasons, reason);
      pushUnique(group.origins, origin);
      pushUnique(group.durations, duration);
      pushUnique(group.alertIds, alertId);
      pushUnique(group.decisionIds, decId);
      if(alertId){
        pushUnique(group.inspectAlertIds, alertId);
      } else if(decId){
        pushUnique(group.inspectDecisionIds, decId);
      }
    });

    return groups;
  }

  function queueDecisionDelete(decId, cb){
    var fd = new FormData();
    fd.append('op', 'decision.delete');
    fd.append('decision_id', decId);

    fetch(API, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials: 'include',
      body: new URLSearchParams(fd)
    })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(!j.ok){
        cb({ok:false, details:j.error || 'failed to queue delete'});
        return;
      }
      pollResult(j.action_id, function(res){
        cb(res || {ok:false, details:'empty response'});
      });
    })
    .catch(function(er){
      cb({ok:false, details:'Network error: ' + er.message});
    });
  }

  function queueInspect(target, cb){
    var fd = new FormData();
    fd.append('op', 'alert.inspect');
    if(target && target.type === 'alert'){
      fd.append('alert_id', target.id);
    } else {
      fd.append('decision_id', target.id);
    }

    fetch(API, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials: 'include',
      body: new URLSearchParams(fd)
    })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(!j.ok){
        cb({ok:false, details:j.error || 'failed to queue inspect'});
        return;
      }
      pollResult(j.action_id, function(res){
        cb(res || {ok:false, details:'empty response'});
      });
    })
    .catch(function(er){
      cb({ok:false, details:'Network error: ' + er.message});
    });
  }

  function renderPotentialFalsePositives(grouped, matchMap){
    if(!$fpWrap || !$fpBody){
      return;
    }

    hide($fpWrap);
    $fpBody.innerHTML = '';

    if(!Array.isArray(grouped) || grouped.length === 0 || !matchMap || typeof matchMap !== 'object'){
      return;
    }

    grouped.forEach(function(group){
      var groupIp   = group && group.ip ? String(group.ip) : '';
      var matchIp   = normalizeMatchIp(groupIp);
      var usernames = matchIp && Array.isArray(matchMap[matchIp]) ? matchMap[matchIp].slice() : [];

      if(!matchIp || usernames.length === 0){
        return;
      }

      var reason   = group.reasons.length ? group.reasons.join(', ') : '';
      var origin   = group.origins.length ? group.origins.join(', ') : '';
      var scope    = group.scopes.length ? group.scopes.join(', ') : '';
      var duration = group.durations.length ? group.durations.join(', ') : '';
      var alertIds = group.alertIds.length ? group.alertIds.join(', ') : '';
      var geoIp    = extractGeoIp(matchIp);
      var ipLabel  = geoIp
        ? '<a href="#" class="lum-ban-ip" data-geo-ip="' + esc(geoIp) + '"><code>' + esc(matchIp) + '</code></a>'
        : '<code>' + esc(matchIp) + '</code>';

      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' +
          ipLabel +
          '<br><span class="help-min">' + esc(usernames.join(', ')) + '</span>' +
        '</td>' +
        '<td>' + esc(reason) + '</td>' +
        '<td>' + esc(origin) + '</td>' +
        '<td>' + esc(scope) + '</td>' +
        '<td>' + esc(duration) + '</td>' +
        '<td>' + (alertIds ? esc(alertIds) : '<span class="help-min">n/a</span>') + '</td>';
      $fpBody.appendChild(tr);

      var ipAnchor = tr.querySelector('.lum-ban-ip');
      if (GeoUI && ipAnchor && geoIp) {
        GeoUI.attach(ipAnchor, geoIp);
      }
    });

    if($fpBody.children.length > 0){
      show($fpWrap);
    }
  }

  function renderDecisions(decisions, potentialFalsePositives){
    if (GeoUI) {
      GeoUI.hide(true);
    }
    if(!Array.isArray(decisions) || decisions.length === 0){
      $csUpdated.textContent = 'Last updated: ' + formatTimestamp(new Date());
      show($empty);
      $count.textContent = '0 decisions';
      if($fpWrap){
        hide($fpWrap);
      }
      return;
    }
    $csUpdated.textContent = 'Last updated: ' + formatTimestamp(new Date());
    var grouped = groupDecisionsByTarget(decisions);
    var groupedCountText = grouped.length + ' IP/range' + (grouped.length !== 1 ? 's' : '');
    var decisionCountText = decisions.length + ' decision' + (decisions.length !== 1 ? 's' : '');
    $count.textContent = groupedCountText + ' (' + decisionCountText + ')';
    $tbody.innerHTML = '';

    grouped.forEach(function(group){
      var ip       = group.ip || '?';
      var reason   = group.reasons.length ? group.reasons.join(', ') : '';
      var origin   = group.origins.length ? group.origins.join(', ') : '';
      var scope    = group.scopes.length ? group.scopes.join(', ') : '';
      var duration = group.durations.length ? group.durations.join(', ') : '';
      var alertIds = group.alertIds.slice();
      var decIds   = group.decisionIds.slice();
      var inspectAlertIds = group.inspectAlertIds.slice();
      var inspectDecisionIds = group.inspectDecisionIds.slice();
      var hasAlert = alertIds.length > 0;
      var hasDecId = decIds.length > 0;
      var firstDecId = hasDecId ? decIds[0] : '';
      var inspectTargetCount = inspectAlertIds.length + inspectDecisionIds.length;
      var unbanLabel = decIds.length > 1 ? 'Unban All' : 'Unban';
      var unbanHtml = hasDecId
        ? '<button type="button" class="btn btn-xs btn-danger btn-pill btn-unban" data-ids="' + esc(decIds.join(',')) + '">' + unbanLabel + '</button> '
        : '<span class="help-min">No decision id</span> ';
      var inspectHtml = inspectTargetCount > 0
        ? '<button type="button" class="btn btn-xs btn-soft btn-pill btn-inspect" data-alerts="' + esc(inspectAlertIds.join(',')) + '" data-decisions="' + esc(inspectDecisionIds.join(',')) + '">' + esc(inspectButtonLabel(inspectTargetCount)) + '</button>'
        : '';
      var geoIp = extractGeoIp(ip);
      var ipHtml = geoIp
        ? '<a href="#" class="lum-ban-ip" data-geo-ip="' + esc(geoIp) + '"><code>' + esc(ip) + '</code></a>'
        : '<code>' + esc(ip) + '</code>';

      var tr = document.createElement('tr');
      tr.setAttribute('data-decision-id', firstDecId);

      tr.innerHTML =
        '<td>' + ipHtml + '</td>' +
        '<td>' + esc(reason) + '</td>' +
        '<td>' + esc(origin) + '</td>' +
        '<td>' + esc(scope) + '</td>' +
        '<td>' + esc(duration) + '</td>' +
        '<td>' + (hasAlert ? esc(alertIds.join(', ')) : '<span class="help-min">n/a</span>') + '</td>' +
        '<td>' +
          unbanHtml + inspectHtml +
        '</td>';
      $tbody.appendChild(tr);
      var ipAnchor = tr.querySelector('.lum-ban-ip');
      if (GeoUI && ipAnchor && geoIp) {
        GeoUI.attach(ipAnchor, geoIp);
      }
    });

    show($tableW);
    renderPotentialFalsePositives(grouped, potentialFalsePositives);
  }

  /* ---------- Unban ------------------------------------------------------- */
  document.addEventListener('click', function(e){
    var btn = e.target.closest('.btn-unban');
    if(!btn) return;
    var rawIds = btn.getAttribute('data-ids') || btn.getAttribute('data-id') || '';
    var decIds = parseNumericIdList(rawIds);
    if(decIds.length === 0) return;
    btn.disabled = true;

    var idx = 0;
    var okCount = 0;
    var failCount = 0;
    var firstError = '';

    function nextDelete(){
      if(idx >= decIds.length){
        if(failCount === 0){
          showToast(okCount === 1 ? 'Decision removed' : ('Removed ' + okCount + ' decisions'));
        } else {
          var msg = 'Removed ' + okCount + '/' + decIds.length + ' decisions';
          if(firstError){
            msg += '. ' + firstError;
          }
          showToast(msg, true);
        }
        loadDecisions();
        return;
      }

      btn.textContent = decIds.length === 1
        ? 'Removing...'
        : ('Removing... ' + (idx + 1) + '/' + decIds.length);

      queueDecisionDelete(decIds[idx], function(res){
        if(res && res.ok){
          okCount++;
        } else {
          failCount++;
          if(!firstError){
            firstError = (res && (res.details || res.error)) ? String(res.details || res.error) : 'unknown error';
          }
        }
        idx++;
        nextDelete();
      });
    }

    nextDelete();
  });

  /* ---------- Inspect (accordion) ----------------------------------------- */
  document.addEventListener('click', function(e){
    var btn = e.target.closest('.btn-inspect');
    if(!btn) return;
    var alertIds = parseNumericIdList(btn.getAttribute('data-alerts'));
    var decisionIds = parseNumericIdList(btn.getAttribute('data-decisions'));
    var fallbackAlertId = parseNumericId(btn.getAttribute('data-alert'));
    var fallbackDecisionId = parseNumericId(btn.getAttribute('data-decision'));
    if(alertIds.length === 0 && fallbackAlertId){
      pushUnique(alertIds, fallbackAlertId);
    }
    if(decisionIds.length === 0 && fallbackDecisionId){
      pushUnique(decisionIds, fallbackDecisionId);
    }

    var inspectTargets = [];
    alertIds.forEach(function(id){
      inspectTargets.push({type:'alert', id:id});
    });
    decisionIds.forEach(function(id){
      inspectTargets.push({type:'decision', id:id});
    });
    if(inspectTargets.length === 0) return;
    var inspectLabel = inspectButtonLabel(inspectTargets.length);

    var tr = btn.closest('tr');
    var existingDetail = tr.nextElementSibling;
    if(existingDetail && existingDetail.classList.contains('inspect-row')){
      existingDetail.remove();
      btn.textContent = inspectLabel;
      return;
    }

    btn.disabled = true;
    var idx = 0;
    var inspectResults = [];

    function finishInspect(){
      btn.disabled = false;
      btn.textContent = inspectLabel;
      var detailHtml = buildInspectDetailHtml(inspectTargets, inspectResults);

      var detailTr = document.createElement('tr');
      detailTr.className = 'inspect-row';
      var td = document.createElement('td');
      td.setAttribute('colspan', '7');
      td.style.cssText = 'padding:12px 16px;background:rgba(0,0,0,.3);';
      td.innerHTML = detailHtml;
      detailTr.appendChild(td);

      if(tr.nextSibling){
        tr.parentNode.insertBefore(detailTr, tr.nextSibling);
      } else {
        tr.parentNode.appendChild(detailTr);
      }
    }

    function nextInspect(){
      if(idx >= inspectTargets.length){
        finishInspect();
        return;
      }

      btn.textContent = inspectTargets.length === 1
        ? 'Loading...'
        : ('Loading... ' + (idx + 1) + '/' + inspectTargets.length);

      queueInspect(inspectTargets[idx], function(res){
        inspectResults.push(res || {ok:false, details:'empty response'});
        idx++;
        nextInspect();
      });
    }

    nextInspect();
  });

  /* ---------- Edge Bans ---------------------------------------------------- */
  var $edgeLoading  = document.getElementById('edge_loading');
  var $edgeError    = document.getElementById('edge_error');
  var $edgeErrorMsg = document.getElementById('edge_error_msg');
  var $edgeEmpty    = document.getElementById('edge_empty');
  var $edgeTableW   = document.getElementById('edge_table_wrap');
  var $edgeBody     = document.getElementById('edge_body');
  var $edgeCount    = document.getElementById('edge_count');
  var $edgeUpdated  = document.getElementById('edge_updated');

  function loadEdgeBans(){
    hide($edgeError); hide($edgeEmpty); hide($edgeTableW);
    show($edgeLoading);
    $edgeCount.textContent = '-- IPs';
    if($edgeBody) $edgeBody.innerHTML = '';

    fetch(API + '?action=edgebans&t=' + Date.now(), {
      credentials:'include',
      cache: 'no-store'
    })
      .then(function(r){ return r.json(); })
      .then(function(j){
        hide($edgeLoading);
        if(!j.ok){
          $edgeErrorMsg.textContent = j.error || 'Failed to load edge bans';
          show($edgeError);
          return;
        }
        renderEdgeBans(j);
      })
      .catch(function(e){
        hide($edgeLoading);
        $edgeErrorMsg.textContent = 'Network error: ' + e.message;
        show($edgeError);
      });
  }

  function renderEdgeBans(data){
    var ips = Array.isArray(data.exclude_ips) ? data.exclude_ips : [];
    var count = ips.length;

    $edgeCount.textContent = count + ' IP' + (count !== 1 ? 's' : '');

    if(count === 0){
      show($edgeEmpty);
      return;
    }

    if(data.updated_utc){
      $edgeUpdated.textContent = 'Last updated: ' + formatTimestamp(new Date(data.updated_utc));
    }

    $edgeBody.innerHTML = '';
    ips.forEach(function(ip){
      var geoIp = extractGeoIp(ip);
      var ipHtml = geoIp
        ? '<a href="#" class="lum-ban-ip" data-geo-ip="' + esc(geoIp) + '"><code>' + esc(ip) + '</code></a>'
        : '<code>' + esc(ip) + '</code>';

      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + ipHtml + '</td>' +
        '<td>' +
          '<button type="button" class="btn btn-xs btn-danger btn-pill btn-edge-unban" data-ip="' + esc(ip) + '">Unban</button>' +
        '</td>';
      $edgeBody.appendChild(tr);

      var ipAnchor = tr.querySelector('.lum-ban-ip');
      if (GeoUI && ipAnchor && geoIp) {
        GeoUI.attach(ipAnchor, geoIp);
      }
    });

    show($edgeTableW);
  }

  document.addEventListener('click', function(e){
    var btn = e.target.closest('.btn-edge-unban');
    if(!btn) return;
    var ip = btn.getAttribute('data-ip') || '';
    if(!ip) return;
    btn.disabled = true;
    btn.textContent = 'Removing...';

    var body = new URLSearchParams();
    body.append('op', 'edgeban.remove');
    body.append('ip', ip);

    fetch(API, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials: 'include',
      body: body
    })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(j.ok){
        showToast('Queued removal for ' + ip);
        loadEdgeBans();
      } else {
        showToast(j.error || 'Failed to remove edge ban', true);
        btn.disabled = false;
        btn.textContent = 'Unban';
      }
    })
    .catch(function(er){
      showToast('Network error: ' + er.message, true);
      btn.disabled = false;
      btn.textContent = 'Unban';
    });
  });

  /* ---------- Refresh buttons --------------------------------------------- */
  document.getElementById('btn_refresh').addEventListener('click', function(){
    loadDecisions();
  });
  document.getElementById('btn_edge_refresh').addEventListener('click', function(){
    loadEdgeBans();
  });

  /* ---------- Auto-load on page open -------------------------------------- */
  loadDecisions();
  loadEdgeBans();

})();
</script>

<?php render_footer(); ?>
