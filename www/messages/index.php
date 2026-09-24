<?php
declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');

require_once 'web_functions.inc.php';
require_once 'messages_functions.inc.php';

@session_start();
set_page_access('auth');

$API = $THIS_MODULE_PATH . '/api.php';
$CSRF = csrf_get_token();
$config_error = messages_configuration_error();
$setup_help = messages_setup_instructions();

render_header("$ORGANISATION_NAME messages");
?>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading">
      <div class="panel-headline panel-headline--stacked">
        <h3 class="card-title">Messages</h3>
        <div class="panel-badges">
          <span class="badge-soft" id="msg_counts">Loading...</span>
        </div>
      </div>
    </div>

    <div class="card-body">
      <div id="messages_unavailable" class="<?php echo $config_error === '' ? 'hidden' : ''; ?>">
        <div class="alert alert-warning" role="alert" style="margin:0;">
          <strong>Messages are disabled.</strong>
          <div style="margin-top:8px;"><?php echo htmlspecialchars($config_error !== '' ? $config_error : 'Configuration is incomplete.', ENT_QUOTES, 'UTF-8'); ?></div>
          <div style="margin-top:10px;">
            <div class="help-min" style="margin-bottom:6px;">Setup:</div>
            <ul style="margin:0;padding-left:20px;">
              <?php foreach ($setup_help as $line): ?>
              <li><?php echo htmlspecialchars((string)$line, ENT_QUOTES, 'UTF-8'); ?></li>
              <?php endforeach; ?>
            </ul>
          </div>
        </div>
      </div>

      <div id="messages_app" class="<?php echo $config_error !== '' ? 'hidden' : ''; ?>">
        <div class="panel-toolbar">
          <div class="panel-toolbar-actions" style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" id="btn_inbox" class="btn btn-soft btn-pill btn-sm">Inbox</button>
            <button type="button" id="btn_outbox" class="btn btn-soft btn-pill btn-sm">Outbox</button>
            <button type="button" id="btn_compose" class="btn btn-primary btn-pill btn-sm">New Message</button>
            <button type="button" id="btn_refresh" class="btn btn-soft btn-pill btn-sm">Refresh</button>
          </div>
        </div>

        <div id="compose_wrap" class="hidden" style="margin:10px 0 14px;">
          <div class="card" style="margin:0;">
            <div class="card-body" style="padding:14px;">
              <form id="compose_form" autocomplete="off">
                <div class="form-group">
                  <label for="compose_to"><strong>To</strong></label>
                  <select id="compose_to" class="form-control" required>
                    <option value="">Select recipient...</option>
                  </select>
                </div>
                <div class="form-group">
                  <label for="compose_body"><strong>Message</strong></label>
                  <textarea id="compose_body" class="form-control" rows="6" maxlength="5000" required placeholder="Write your message..."></textarea>
                  <div id="compose_bb_toolbar" class="msg-compose-toolbar" role="toolbar" aria-label="BBCode helper">
                    <button type="button" class="btn btn-xs btn-soft btn-pill" data-bb-action="wrap" data-bb-open="[b]" data-bb-close="[/b]" title="Bold">Bold</button>
                    <button type="button" class="btn btn-xs btn-soft btn-pill" data-bb-action="wrap" data-bb-open="[u]" data-bb-close="[/u]" title="Underline">Underline</button>
                    <button type="button" class="btn btn-xs btn-soft btn-pill" data-bb-action="wrap" data-bb-open="[quote]" data-bb-close="[/quote]" title="Quote">Quote</button>
                    <button type="button" class="btn btn-xs btn-soft btn-pill" data-bb-action="wrap" data-bb-open="[code]" data-bb-close="[/code]" title="Code">Code</button>
                    <button type="button" class="btn btn-xs btn-soft btn-pill" data-bb-action="link" title="Insert Link">Link</button>
                  </div>
                  <div class="help-min" id="compose_limit_note" style="margin-top:6px;">Supports BBCode: [b], [u], [code], [quote], [url].</div>
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end;">
                  <button type="button" id="btn_compose_cancel" class="btn btn-default btn-pill btn-sm">Cancel</button>
                  <button type="submit" id="btn_send" class="btn btn-primary btn-pill btn-sm">Send</button>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div id="messages_loading">
          <div class="alert alert-info" role="status" style="margin:0;">Loading messages...</div>
        </div>
        <div id="messages_error" class="hidden">
          <div class="alert alert-warning" role="alert" style="margin:0;" id="messages_error_text">Unable to load messages.</div>
        </div>
        <div id="messages_empty" class="hidden">
          <div class="alert alert-success" role="status" style="margin:0;" id="messages_empty_text">No messages.</div>
        </div>
        <div id="messages_table_wrap" class="hidden">
          <div class="table-responsive">
            <table class="table table-dark table-striped table-modern">
              <thead>
                <tr>
                  <th id="col_party">From</th>
                  <th>Preview</th>
                  <th>Sent</th>
                  <th>Read</th>
                  <th style="width:220px;">Actions</th>
                </tr>
              </thead>
              <tbody id="messages_rows"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
.msg-tab-active {
  box-shadow: 0 0 0 1px var(--border-hover), 0 0 16px var(--shadow-glow);
}
.msg-row-unread td {
  font-weight: 600;
}
.msg-row-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.msg-detail-row > td {
  padding: 12px 16px !important;
  background: rgba(0,0,0,.28);
}
.msg-detail-card {
  margin: 0;
  border: 1px solid var(--border-primary);
  border-radius: 14px;
  background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%), var(--bg-tertiary);
  box-shadow: inset 0 1px 0 var(--gradient-header);
  padding: 14px;
}
.msg-detail-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 8px;
}
.msg-detail-title {
  margin: 0;
  font-size: 17px;
  color: var(--accent);
}
.msg-detail-meta {
  margin-bottom: 10px;
}
.msg-detail-body {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: 10px;
  padding: 12px;
  color: var(--text-primary);
}
.msg-detail-body a {
  color: var(--accent);
  text-decoration: underline;
  word-break: break-all;
}
.msg-detail-body .msg-quote {
  margin: 8px 0;
  padding: 8px 10px;
  border-left: 3px solid var(--accent);
  background: rgba(0,0,0,.25);
  border-radius: 8px;
}
.msg-detail-body .msg-code-block {
  margin: 8px 0;
  padding: 10px;
  background: rgba(0,0,0,.35);
  border: 1px solid var(--border-primary);
  border-radius: 8px;
  white-space: pre-wrap;
}
.msg-detail-body .msg-code-block code {
  color: var(--text-primary);
}
.msg-compose-toolbar {
  margin-top: 8px;
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
</style>

<script>
(function(){
  var API = <?php echo json_encode($API); ?>;
  var CSRF = <?php echo json_encode($CSRF); ?>;
  var STATE = {
    box: 'inbox',
    isAdmin: false,
    currentUid: '',
    maxBodyLength: 5000,
    counts: {inbox: 0, outbox: 0, unread: 0},
    prefillCompose: false,
    prefillToUid: '',
    prefillApplied: false
  };

  var $counts = document.getElementById('msg_counts');
  var $unavailable = document.getElementById('messages_unavailable');
  var $app = document.getElementById('messages_app');
  var $loading = document.getElementById('messages_loading');
  var $error = document.getElementById('messages_error');
  var $errorText = document.getElementById('messages_error_text');
  var $empty = document.getElementById('messages_empty');
  var $emptyText = document.getElementById('messages_empty_text');
  var $tableWrap = document.getElementById('messages_table_wrap');
  var $rows = document.getElementById('messages_rows');
  var $colParty = document.getElementById('col_party');
  var $btnInbox = document.getElementById('btn_inbox');
  var $btnOutbox = document.getElementById('btn_outbox');
  var $btnRefresh = document.getElementById('btn_refresh');
  var $btnCompose = document.getElementById('btn_compose');
  var $composeWrap = document.getElementById('compose_wrap');
  var $composeForm = document.getElementById('compose_form');
  var $composeTo = document.getElementById('compose_to');
  var $composeBody = document.getElementById('compose_body');
  var $composeBbToolbar = document.getElementById('compose_bb_toolbar');
  var $composeLimit = document.getElementById('compose_limit_note');
  var $btnComposeCancel = document.getElementById('btn_compose_cancel');
  var $btnSend = document.getElementById('btn_send');

  (function parsePrefill(){
    try {
      var params = new URLSearchParams(window.location.search || '');
      var toUid = (params.get('to_uid') || '').trim();
      if(toUid){
        STATE.prefillToUid = toUid;
        STATE.prefillCompose = true;
      } else if(params.get('compose') === '1'){
        STATE.prefillCompose = true;
      }
    } catch (e) {
      // Ignore malformed query strings.
    }
  })();

  function show(el){ if(el) el.classList.remove('hidden'); }
  function hide(el){ if(el) el.classList.add('hidden'); }

  function showToast(msg, isError){
    var t = document.createElement('div');
    t.className = 'alert ' + (isError ? 'alert-warning' : 'alert-success');
    t.style.cssText = 'position:fixed;top:80px;right:20px;z-index:9999;min-width:280px;max-width:520px;box-shadow:0 4px 20px rgba(0,0,0,.5);';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function(){ t.remove(); }, 4200);
  }

  function fmtTime(iso){
    if(!iso) return 'n/a';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  function escapeHtml(value){
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  var _entityDecoder = null;
  function decodeHtmlEntities(value){
    if(_entityDecoder === null){
      _entityDecoder = document.createElement('textarea');
    }
    _entityDecoder.innerHTML = String(value || '');
    return _entityDecoder.value;
  }

  function sanitizeBbcodeUrl(raw){
    var value = decodeHtmlEntities(String(raw || '')).trim();
    if(!value){
      return '';
    }
    if(/^www\./i.test(value)){
      value = 'https://' + value;
    } else if(!/^(https?:\/\/|mailto:)/i.test(value)) {
      return '';
    }

    var parsed;
    try {
      parsed = new URL(value, window.location.origin);
    } catch (e) {
      return '';
    }

    var protocol = String(parsed.protocol || '').toLowerCase();
    if(protocol !== 'http:' && protocol !== 'https:' && protocol !== 'mailto:'){
      return '';
    }
    return parsed.href;
  }

  function replaceSimpleBbcodeTag(html, tagName, openTag, closeTag){
    var pattern = new RegExp('\\[' + tagName + '\\]([\\s\\S]*?)\\[\\/' + tagName + '\\]', 'gi');
    var out = String(html || '');
    var prev = '';
    while(out !== prev){
      prev = out;
      out = out.replace(pattern, openTag + '$1' + closeTag);
    }
    return out;
  }

  function renderMessageBody(body){
    var raw = String(body || '').replace(/\r\n?/g, '\n');
    if(!raw){
      return '';
    }

    var html = escapeHtml(raw);
    var tokens = [];
    function tokenized(markup){
      var token = '\u0001bbcode-' + tokens.length + '\u0001';
      tokens.push(markup);
      return token;
    }

    html = html.replace(/\[code\]([\s\S]*?)\[\/code\]/gi, function(_, codeBody){
      return tokenized('<pre class="msg-code-block"><code>' + codeBody + '</code></pre>');
    });

    html = html.replace(/\[url=([^\]\r\n]+)\]([\s\S]*?)\[\/url\]/gi, function(_, target, label){
      var safeUrl = sanitizeBbcodeUrl(target);
      if(!safeUrl){
        return label;
      }
      var linkLabel = String(label || '').trim() === '' ? escapeHtml(safeUrl) : label;
      return '<a href="' + escapeHtml(safeUrl) + '" target="_blank" rel="noopener noreferrer">' + linkLabel + '</a>';
    });

    html = html.replace(/\[url\]([\s\S]*?)\[\/url\]/gi, function(_, target){
      var safeUrl = sanitizeBbcodeUrl(target);
      if(!safeUrl){
        return target;
      }
      return '<a href="' + escapeHtml(safeUrl) + '" target="_blank" rel="noopener noreferrer">' + target + '</a>';
    });

    html = replaceSimpleBbcodeTag(html, 'b', '<strong>', '</strong>');
    html = replaceSimpleBbcodeTag(html, 'u', '<u>', '</u>');
    html = replaceSimpleBbcodeTag(html, 'quote', '<blockquote class="msg-quote">', '</blockquote>');

    html = html.replace(/\u0001bbcode-(\d+)\u0001/g, function(_, idx){
      var i = Number(idx);
      return Number.isFinite(i) && tokens[i] ? tokens[i] : '';
    });

    return html;
  }

  function applyBbWrap(openTag, closeTag, fallbackText){
    var area = $composeBody;
    if(!area) return;
    area.focus();

    var value = String(area.value || '');
    var start = Number(area.selectionStart);
    var end = Number(area.selectionEnd);
    if(!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || end < start){
      start = value.length;
      end = value.length;
    }

    var selected = value.slice(start, end);
    if(!selected && fallbackText){
      selected = String(fallbackText);
    }

    var wrapped = String(openTag || '') + selected + String(closeTag || '');
    area.value = value.slice(0, start) + wrapped + value.slice(end);

    var caretStart = start + String(openTag || '').length;
    var caretEnd = caretStart + selected.length;
    try {
      area.setSelectionRange(caretStart, caretEnd);
    } catch (e) {
      // Ignore browsers without selection APIs.
    }
  }

  function applyBbLink(){
    var area = $composeBody;
    if(!area) return;
    area.focus();

    var value = String(area.value || '');
    var start = Number(area.selectionStart);
    var end = Number(area.selectionEnd);
    if(!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || end < start){
      start = value.length;
      end = value.length;
    }

    var selected = value.slice(start, end);
    var selectedTrimmed = selected.trim();
    var selectedAsUrl = sanitizeBbcodeUrl(selectedTrimmed);
    if(selectedAsUrl){
      applyBbWrap('[url]', '[/url]');
      return;
    }

    var rawUrl = window.prompt('Enter link URL (https://, http://, mailto:, or www.)', 'https://');
    if(rawUrl === null){
      return;
    }
    var safeUrl = sanitizeBbcodeUrl(rawUrl);
    if(!safeUrl){
      showToast('Unsupported link format. Use http(s), mailto, or www.', true);
      return;
    }

    if(selected){
      applyBbWrap('[url=' + safeUrl + ']', '[/url]');
      return;
    }
    applyBbWrap('[url]', '[/url]', safeUrl);
  }

  function setCounts(counts){
    counts = counts || {};
    var inbox = Number(counts.inbox || 0);
    var outbox = Number(counts.outbox || 0);
    var unread = Number(counts.unread || 0);
    STATE.counts = {
      inbox: inbox,
      outbox: outbox,
      unread: unread
    };
    $counts.textContent = 'Inbox ' + inbox + ' (' + unread + ' unread) / Outbox ' + outbox;
    $btnInbox.textContent = 'Inbox (' + unread + ')';
    $btnOutbox.textContent = 'Outbox (' + outbox + ')';
  }

  function setBox(box){
    STATE.box = (box === 'outbox') ? 'outbox' : 'inbox';
    $btnInbox.classList.toggle('msg-tab-active', STATE.box === 'inbox');
    $btnOutbox.classList.toggle('msg-tab-active', STATE.box === 'outbox');
    $colParty.textContent = STATE.box === 'inbox' ? 'From' : 'To';
    loadList();
  }

  function setComposeVisible(showCompose){
    if(showCompose){
      show($composeWrap);
      $btnCompose.textContent = 'Close Composer';
      return;
    }
    hide($composeWrap);
    $btnCompose.textContent = 'New Message';
  }

  function fillRecipients(users){
    var current = $composeTo.value;
    $composeTo.innerHTML = '';
    var placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Select recipient...';
    $composeTo.appendChild(placeholder);

    (users || []).forEach(function(user){
      if(!user || !user.uid || user.uid === STATE.currentUid) return;
      var opt = document.createElement('option');
      opt.value = user.uid;
      opt.textContent = user.display && user.display !== user.uid
        ? (user.display + ' (' + user.uid + ')')
        : user.uid;
      $composeTo.appendChild(opt);
    });
    if(current) {
      $composeTo.value = current;
    }
  }

  function applyPrefill(){
    if(STATE.prefillApplied) return;
    STATE.prefillApplied = true;

    if(STATE.prefillToUid){
      var target = STATE.prefillToUid.toLowerCase();
      var matchedValue = '';
      for(var i = 0; i < $composeTo.options.length; i++){
        var optValue = ($composeTo.options[i].value || '').trim();
        if(!optValue) continue;
        if(optValue === STATE.prefillToUid || optValue.toLowerCase() === target){
          matchedValue = optValue;
          break;
        }
      }
      if(matchedValue){
        $composeTo.value = matchedValue;
        STATE.prefillCompose = true;
      }
    }

    if(STATE.prefillCompose){
      setComposeVisible(true);
      $composeBody.focus();
      if(window.history && typeof window.history.replaceState === 'function'){
        window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
      }
    }
  }

  function resetListState(){
    hide($error);
    hide($empty);
    hide($tableWrap);
    show($loading);
  }

  function fetchJson(url, opts){
    return fetch(url, opts).then(function(r){ return r.json(); });
  }

  function loadBootstrap(){
    fetchJson(API + '?action=bootstrap&t=' + Date.now(), {
      credentials: 'include',
      cache: 'no-store'
    })
    .then(function(j){
      if(!j.ok){
        throw new Error(j.error || 'Failed to load messages bootstrap');
      }
      if(!j.enabled){
        show($unavailable);
        hide($app);
        hide($loading);
        $counts.textContent = 'Messages disabled';
        return;
      }
      STATE.currentUid = j.current_uid || '';
      STATE.isAdmin = !!j.is_admin;
      STATE.maxBodyLength = Number(j.max_body_length || 5000);
      $composeBody.setAttribute('maxlength', String(STATE.maxBodyLength));
      $composeLimit.textContent = 'Supports BBCode: [b], [u], [code], [quote], [url]. Max ' + STATE.maxBodyLength + ' characters.';
      fillRecipients(j.users || []);
      applyPrefill();
      setCounts(j.counts || {});
      setBox('inbox');
    })
    .catch(function(err){
      hide($loading);
      show($error);
      $errorText.textContent = 'Bootstrap error: ' + err.message;
    });
  }

  function renderRows(rows){
    $rows.innerHTML = '';
    rows.forEach(function(row){
      var tr = document.createElement('tr');
      tr.setAttribute('data-message-id', String(row.id || ''));
      tr.setAttribute('data-is-unread', row.is_unread ? '1' : '0');
      if(STATE.box === 'inbox' && row.is_unread){
        tr.classList.add('msg-row-unread');
      }

      var party = STATE.box === 'inbox'
        ? (row.from_display || row.from_uid || '?')
        : (row.to_display || row.to_uid || '?');

      var readText = 'n/a';
      if(row.read_visible){
        readText = row.is_unread ? 'Unread' : ('Read ' + fmtTime(row.read_at));
      }

      var tdParty = document.createElement('td');
      tdParty.textContent = party;
      tr.appendChild(tdParty);

      var tdPreview = document.createElement('td');
      tdPreview.textContent = row.preview || '';
      tr.appendChild(tdPreview);

      var tdSent = document.createElement('td');
      tdSent.textContent = fmtTime(row.created_at);
      tr.appendChild(tdSent);

      var tdRead = document.createElement('td');
      tdRead.textContent = readText;
      tr.appendChild(tdRead);

      var tdActions = document.createElement('td');
      tdActions.className = 'msg-row-actions';
      var openBtn = document.createElement('button');
      openBtn.type = 'button';
      openBtn.className = 'btn btn-xs btn-soft btn-pill';
      openBtn.textContent = 'Open';
      openBtn.setAttribute('aria-expanded', 'false');
      openBtn.addEventListener('click', function(){ toggleMessageDetail(row.id, tr, openBtn); });
      tdActions.appendChild(openBtn);

      if(row.can_delete){
        var delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn btn-xs btn-danger btn-pill';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', function(){ deleteMessage(row.id); });
        tdActions.appendChild(delBtn);
      }

      tr.appendChild(tdActions);
      $rows.appendChild(tr);
    });
  }

  function findRecipientOptionValue(uid){
    var target = String(uid || '').trim().toLowerCase();
    if(!target) return '';
    for(var i = 0; i < $composeTo.options.length; i++){
      var value = String($composeTo.options[i].value || '').trim();
      if(!value) continue;
      if(value.toLowerCase() === target){
        return value;
      }
    }
    return '';
  }

  function openComposeReply(toUid){
    var uid = String(toUid || '').trim();
    if(!uid){
      showToast('Reply target is not available.', true);
      return;
    }
    var matchedValue = findRecipientOptionValue(uid);
    if(!matchedValue){
      showToast('Reply target is not available in recipients.', true);
      return;
    }
    setComposeVisible(true);
    $composeTo.value = matchedValue;
    $composeBody.focus();
  }

  function rowReadText(message){
    if(!message || !message.read_visible){
      return 'n/a';
    }
    return message.is_unread ? 'Unread' : ('Read ' + fmtTime(message.read_at));
  }

  function detailMetaText(message){
    var partyFrom = (message.from_display || message.from_uid || '?');
    var partyTo = (message.to_display || message.to_uid || '?');
    return 'From: ' + partyFrom + ' | To: ' + partyTo + ' | Sent: ' + fmtTime(message.created_at) + ' | Read: ' + rowReadText(message);
  }

  function messageReplyTargetUid(message){
    if(!message) return '';
    var uid = STATE.box === 'inbox'
      ? String(message.from_uid || '')
      : String(message.to_uid || '');
    uid = uid.trim();
    if(!uid) return '';
    if(STATE.currentUid && uid.toLowerCase() === String(STATE.currentUid).toLowerCase()){
      return '';
    }
    return uid;
  }

  function buildDetailRow(message){
    var tr = document.createElement('tr');
    tr.className = 'msg-detail-row';
    tr.setAttribute('data-parent-id', String(message.id || ''));

    var td = document.createElement('td');
    td.setAttribute('colspan', '5');

    var card = document.createElement('div');
    card.className = 'msg-detail-card';

    var head = document.createElement('div');
    head.className = 'msg-detail-head';

    var title = document.createElement('h4');
    title.className = 'msg-detail-title';
    title.textContent = 'Message';
    head.appendChild(title);

    var replyTarget = messageReplyTargetUid(message);
    if(replyTarget){
      var replyBtn = document.createElement('button');
      replyBtn.type = 'button';
      replyBtn.className = 'btn btn-xs btn-soft btn-pill';
      replyBtn.textContent = 'Reply';
      replyBtn.addEventListener('click', function(){
        openComposeReply(replyTarget);
      });
      head.appendChild(replyBtn);
    }

    var meta = document.createElement('div');
    meta.className = 'help-min msg-detail-meta';
    meta.textContent = detailMetaText(message);

    var pre = document.createElement('div');
    pre.className = 'msg-detail-body';
    pre.innerHTML = renderMessageBody(String(message.body || ''));

    card.appendChild(head);
    card.appendChild(meta);
    card.appendChild(pre);
    td.appendChild(card);
    tr.appendChild(td);
    return tr;
  }

  function findDetailRow(parentId){
    var id = String(parentId || '');
    if(!id) return null;
    return $rows.querySelector('tr.msg-detail-row[data-parent-id="' + id + '"]');
  }

  function markRowRead(tr, message){
    if(!tr || !message || STATE.box !== 'inbox') return;
    if(tr.getAttribute('data-is-unread') !== '1') return;
    tr.setAttribute('data-is-unread', '0');
    tr.classList.remove('msg-row-unread');
    if(tr.children && tr.children[3]){
      tr.children[3].textContent = rowReadText(message);
    }
    if(STATE.counts.unread > 0){
      STATE.counts.unread -= 1;
      setCounts(STATE.counts);
    }
  }

  function fetchMessageDetail(id){
    var body = new URLSearchParams();
    body.append('op', 'view');
    body.append('box', STATE.box);
    body.append('id', id);
    return fetchJson(API, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials: 'include',
      body: body
    });
  }

  function toggleMessageDetail(id, tr, btn){
    if(!id || !tr || !btn) return;
    var existing = findDetailRow(id);
    if(existing){
      existing.remove();
      btn.textContent = 'Open';
      btn.setAttribute('aria-expanded', 'false');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Loading...';
    fetchMessageDetail(id)
      .then(function(j){
        btn.disabled = false;
        if(!j.ok){
          btn.textContent = 'Open';
          btn.setAttribute('aria-expanded', 'false');
          showToast(j.error || 'Unable to open message', true);
          return;
        }
        var message = j.message || {};
        markRowRead(tr, message);
        if(!tr.parentNode){
          return;
        }
        var detailRow = buildDetailRow(message);
        if(tr.nextSibling){
          tr.parentNode.insertBefore(detailRow, tr.nextSibling);
        } else {
          tr.parentNode.appendChild(detailRow);
        }
        btn.textContent = 'Close';
        btn.setAttribute('aria-expanded', 'true');
      })
      .catch(function(err){
        btn.disabled = false;
        btn.textContent = 'Open';
        btn.setAttribute('aria-expanded', 'false');
        showToast('Network error: ' + err.message, true);
      });
  }

  function loadList(){
    resetListState();
    fetchJson(API + '?action=list&box=' + encodeURIComponent(STATE.box) + '&t=' + Date.now(), {
      credentials: 'include',
      cache: 'no-store'
    })
    .then(function(j){
      hide($loading);
      if(!j.ok){
        show($error);
        $errorText.textContent = j.error || 'Failed to load messages';
        return;
      }
      setCounts(j.counts || {});
      var rows = Array.isArray(j.messages) ? j.messages : [];
      if(rows.length === 0){
        show($empty);
        $emptyText.textContent = STATE.box === 'inbox'
          ? 'No messages in your inbox.'
          : 'No messages in your outbox.';
        return;
      }
      renderRows(rows);
      show($tableWrap);
    })
    .catch(function(err){
      hide($loading);
      show($error);
      $errorText.textContent = 'Network error: ' + err.message;
    });
  }

  function deleteMessage(id){
    if(!id) return;
    var confirmText = STATE.box === 'outbox'
      ? 'Delete this message from your outbox?'
      : 'Delete this message from your inbox?';
    if(!window.confirm(confirmText)) return;

    var body = new URLSearchParams();
    body.append('op', 'delete');
    body.append('box', STATE.box);
    body.append('id', id);
    fetchJson(API, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials: 'include',
      body: body
    })
    .then(function(j){
      if(!j.ok){
        showToast(j.error || 'Unable to delete message', true);
        return;
      }
      setCounts(j.counts || {});
      loadList();
      showToast('Message deleted');
    })
    .catch(function(err){
      showToast('Network error: ' + err.message, true);
    });
  }

  function sendMessage(){
    var toUid = ($composeTo.value || '').trim();
    var bodyText = ($composeBody.value || '').trim();
    if(!toUid || !bodyText){
      showToast('Recipient and message are required.', true);
      return;
    }
    if(bodyText.length > STATE.maxBodyLength){
      showToast('Message is too long.', true);
      return;
    }

    $btnSend.disabled = true;
    $btnSend.textContent = 'Sending...';
    var payload = new URLSearchParams();
    payload.append('op', 'send');
    payload.append('to_uid', toUid);
    payload.append('body', bodyText);

    fetchJson(API, {
      method: 'POST',
      headers: {'X-CSRF-Token': CSRF},
      credentials: 'include',
      body: payload
    })
    .then(function(j){
      $btnSend.disabled = false;
      $btnSend.textContent = 'Send';
      if(!j.ok){
        showToast(j.error || 'Unable to send message', true);
        return;
      }
      setCounts(j.counts || {});
      var mail = j.mail || {};
      if(mail.attempted && !mail.sent){
        showToast('Message sent, but email notification failed: ' + (mail.error || 'unknown error'), true);
      } else if(!mail.attempted && mail.error){
        showToast('Message sent. Email not attempted: ' + mail.error, false);
      } else {
        showToast('Message sent');
      }

      $composeBody.value = '';
      setComposeVisible(false);
      setBox('outbox');
    })
    .catch(function(err){
      $btnSend.disabled = false;
      $btnSend.textContent = 'Send';
      showToast('Network error: ' + err.message, true);
    });
  }

  $btnInbox.addEventListener('click', function(){ setBox('inbox'); });
  $btnOutbox.addEventListener('click', function(){ setBox('outbox'); });
  $btnRefresh.addEventListener('click', function(){ loadList(); });

  $btnCompose.addEventListener('click', function(){
    setComposeVisible($composeWrap.classList.contains('hidden'));
  });
  $btnComposeCancel.addEventListener('click', function(){
    setComposeVisible(false);
  });
  $composeForm.addEventListener('submit', function(e){
    e.preventDefault();
    sendMessage();
  });
  if($composeBbToolbar){
    $composeBbToolbar.addEventListener('mousedown', function(e){
      var target = e.target;
      if(target && target.getAttribute && target.getAttribute('data-bb-action')){
        e.preventDefault();
      }
    });
    $composeBbToolbar.addEventListener('click', function(e){
      var target = e.target;
      if(!target || !target.getAttribute){
        return;
      }
      var action = target.getAttribute('data-bb-action');
      if(!action){
        return;
      }
      if(action === 'link'){
        applyBbLink();
        return;
      }
      if(action === 'wrap'){
        applyBbWrap(target.getAttribute('data-bb-open') || '', target.getAttribute('data-bb-close') || '');
      }
    });
  }

  loadBootstrap();
})();
</script>

<?php render_footer(); ?>
