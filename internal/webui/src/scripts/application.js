  function markPendingApply(on, status) {
    pendingApply = on === true;
    const dot = document.getElementById('nav-config-pending');
    if (dot) dot.classList.toggle('hidden', on === false);
    const banner = document.getElementById('apps-pending-banner');
    if (banner) {
      banner.classList.toggle('hidden', on === false);
      banner.dataset.state = on === true ? 'pending' : 'unknown';
    }
    let message;
    if (on === true) {
      message = status ? 'Saved generation ' + status.saved_generation + ' is pending. The applied configuration is generation ' + status.applied_generation + '.' : 'Saved changes are waiting to be applied.';
    } else if (on === false) {
      message = status ? 'The applied configuration matches saved generation ' + status.saved_generation + '.' : 'Saved configuration applied.';
    } else {
      message = 'The applied generation is unknown. ' + (status ? 'The saved configuration is generation ' + status.saved_generation + '.' : 'Edge status is unavailable.');
    }
    for (const id of ['apps-edge-state', 'config-edge-state']) {
      const el = document.getElementById(id);
      if (el) el.textContent = message;
    }
  }

  function renderPersistentEdgeStatus(status) {
    const pending = status && status.pending;
    const applied = status && status.applied_generation;
    const relationshipIsValid = pending === null ? applied === null :
      pending === false ? Number.isSafeInteger(applied) && applied === status.saved_generation :
      pending === true ? Number.isSafeInteger(applied) && applied !== status.saved_generation : false;
    if (!status || typeof status !== 'object' || !Number.isSafeInteger(status.saved_generation) ||
        !Object.prototype.hasOwnProperty.call(status, 'pending') || !relationshipIsValid) {
      edgeStatusCache = null;
      markPendingApply(null, null);
      return false;
    }
    edgeStatusCache = status;
    markPendingApply(status.pending === true ? true : status.pending === false ? false : null, status);
    return true;
  }

  async function refreshEdgeStatus() {
    let response;
    try {
      response = await fetch('/api/v1/edge/status', { headers: hdr(), cache: 'no-store' });
    } catch (_) {
      renderPersistentEdgeStatus(null);
      return null;
    }
    if (!response.ok) {
      renderPersistentEdgeStatus(null);
      return null;
    }
    const status = await response.json().catch(() => null);
    return renderPersistentEdgeStatus(status) ? status : null;
  }

  async function reportApplicationSaved(response, subject) {
    const applied = response.headers.get('X-Easy-Waf-Applied') === 'true';
    markPendingApply(!applied);
    toast(subject + (applied ? ' applied.' : ' saved. Select Apply HAProxy in Edge changes to activate.'), 'ok');
    await refreshEdgeStatus();
  }

  function copyBtn(value) {
    return '<button type="button" class="secondary copy-btn" data-copy="' + esc(value) + '" title="Copy to clipboard">⧉</button>';
  }

  document.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest && e.target.closest('.copy-btn');
    if (!btn) return;
    const v = btn.getAttribute('data-copy');
    if (!v) return;
    navigator.clipboard.writeText(v).then(
      () => toast('Copied', 'ok', 2000),
      () => toast('Copy failed', 'err')
    );
  });

  function setAppFormCollapsed(collapsed) {
    const panel = document.getElementById('app-form-panel');
    if (panel) panel.classList.toggle('hidden', collapsed);
  }

  function setAppFormTitle(name) {
    const title = document.getElementById('app-form-title');
    if (!title) return;
    title.textContent = name ? ('Edit: ' + name) : 'Add or update application';
  }

  const MIB = 1048576;

  function fillBodyPolicy(sec) {
    const max = sec.max_body_bytes_override;
    document.getElementById('body-max-mib').value = max == null ? '' : String(max / MIB);
    const block = sec.block_multipart_override;
    document.getElementById('body-multipart').value = block == null ? '' : (block ? 'block' : 'allow');
    document.getElementById('body-mp-paths').value = (sec.multipart_allowed_paths || []).join('\n');
  }

  // Returns sec with the form's body settings; empty fields fall back to the profile.
  function withBodyPolicy(sec) {
    const out = { ...sec };
    delete out.max_body_bytes_override;
    delete out.block_multipart_override;
    delete out.multipart_allowed_paths;
    const mib = document.getElementById('body-max-mib').value.trim();
    if (mib !== '') out.max_body_bytes_override = Math.round(parseFloat(mib) * MIB);
    const multipart = document.getElementById('body-multipart').value;
    if (multipart) out.block_multipart_override = multipart === 'block';
    const paths = document.getElementById('body-mp-paths').value.split('\n').map((p) => p.trim()).filter(Boolean);
    if (paths.length) out.multipart_allowed_paths = paths;
    return out;
  }

  function formatBackendServers(list) {
    return (Array.isArray(list) ? list : []).map((s) => s.host + ':' + s.port + (s.backup ? ' backup' : '')).join('\n');
  }

  // "host:port [backup]" per line; the last colon splits, so IPv6 needs [brackets].
  function parseBackendServers(text) {
    const out = [];
    const lines = String(text || '').split('\n').map((l) => l.trim()).filter(Boolean);
    for (const line of lines) {
      const m = /^(\S+):(\d{1,5})(\s+backup)?$/i.exec(line);
      if (!m) throw new Error('Backend server "' + line + '": use host:port, optionally followed by backup');
      out.push({ host: m[1], port: parseInt(m[2], 10), backup: !!m[3] });
    }
    return out;
  }

  async function loadPanelUsers() {
    const box = document.getElementById('pu-table');
    if (!box) return;
    const r = await fetch('/api/v1/panel-users', { headers: hdr() });
    if (!r.ok) { box.textContent = await apiMessage(r); return; }
    const raw = await r.json();
    const list = Array.isArray(raw) ? raw : [];
    box.innerHTML = '<table><thead><tr><th>User</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>' +
      list.map((u) => '<tr><td>' + esc(u.username) + '</td><td><select name="panel_user_role" class="pu-role" aria-label="Role for ' + esc(u.username) + '" data-user="' + esc(u.username) + '">' +
        '<option value="admin"' + (u.role === 'admin' ? ' selected' : '') + '>admin</option>' +
        '<option value="viewer"' + (u.role === 'viewer' ? ' selected' : '') + '>viewer</option></select></td><td>' +
        (u.must_change_password ? 'must change password' : 'active') + (u.totp_enabled ? ', 2FA on' : '') + '</td><td>' +
        (u.totp_enabled ? '<button type="button" class="secondary pu-2fa" data-user="' + esc(u.username) + '">Reset 2FA</button> ' : '') +
        '<button type="button" class="secondary pu-reset" data-user="' + esc(u.username) + '">Reset password</button> ' +
        '<button type="button" class="secondary pu-del" data-user="' + esc(u.username) + '">Delete</button></td></tr>').join('') +
      '</tbody></table>';
    box.querySelectorAll('.pu-role').forEach((sel) => {
      sel.onchange = async () => {
        const r = await fetch('/api/v1/panel-users/' + encodeURIComponent(sel.dataset.user), { method: 'PATCH', headers: hdr(), body: JSON.stringify({ role: sel.value }) });
        if (!r.ok) toast(await apiMessage(r), 'err'); else toast('Role updated.', 'ok');
        loadPanelUsers();
      };
    });
    box.querySelectorAll('.pu-reset').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, async () => {
        const username = btn.dataset.user;
        if (!(await confirmDialog(
          'Reset the password of ' + username + '?\n\nTheir current password stops working and all sessions end. A new temporary password is shown once; reset it again if it is lost.',
          { title: 'Reset panel password', danger: true, okLabel: 'Reset password' }
        ))) return;
        const r = await fetch('/api/v1/panel-users/' + encodeURIComponent(username) + '/reset-password', { method: 'POST', headers: hdr() });
        if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
        const j = await r.json();
        if (!j || typeof j.temporary_password !== 'string') { toast('The server returned an invalid temporary password response.', 'err'); return; }
        await oneTimeCredentialDialog(j.username, j.temporary_password, btn);
        j.temporary_password = '';
        await loadPanelUsers();
        const replacement = Array.from(box.querySelectorAll('.pu-reset')).find((candidate) => candidate.dataset.user === username);
        if (replacement) replacement.focus();
      });
    });
    box.querySelectorAll('.pu-2fa').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, async () => {
        if (!(await confirmDialog(
          'Turn off two-factor sign-in for ' + btn.dataset.user + '?\n\nTheir next sign-in will require only the password. They can set up two-factor sign-in again after signing in.',
          { title: 'Reset two-factor sign-in', danger: true, okLabel: 'Reset 2FA' }
        ))) return;
        const r = await fetch('/api/v1/panel-users/' + encodeURIComponent(btn.dataset.user) + '/totp', { method: 'DELETE', headers: hdr() });
        if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
        await loadPanelUsers();
        document.getElementById('btn-pu-create').focus();
      });
    });
    box.querySelectorAll('.pu-del').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, async () => {
        if (!(await confirmDialog(
          'Delete panel user ' + btn.dataset.user + '?\n\nTheir sessions end and they can no longer sign in. Recreate the account to restore access.',
          { title: 'Delete panel user', danger: true, okLabel: 'Delete user' }
        ))) return;
        const r = await fetch('/api/v1/panel-users/' + encodeURIComponent(btn.dataset.user), { method: 'DELETE', headers: hdr() });
        if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
        await loadPanelUsers();
        document.getElementById('btn-pu-create').focus();
      });
    });
  }

  let totpGeneration = 0;
  function clearTOTPSecrets() {
    totpGeneration++;
    document.getElementById('totp-secret').textContent = '';
    document.getElementById('totp-uri').removeAttribute('href');
    document.getElementById('totp-code').value = '';
    document.getElementById('totp-setup-box').classList.add('hidden');
    const recovery = document.getElementById('totp-recovery');
    recovery.textContent = '';
    recovery.classList.add('hidden');
    document.getElementById('btn-totp-dismiss').classList.add('hidden');
  }

  function renderTOTPStatus(on) {
    const st = document.getElementById('totp-status');
    if (!st) return;
    st.textContent = on ? 'On: sign-in asks for a code from your authenticator app.' : 'Off: sign-in needs only the password.';
    document.getElementById('btn-totp-setup').classList.toggle('hidden', on);
    document.getElementById('btn-totp-disable').classList.toggle('hidden', !on);
    document.getElementById('totp-setup-box').classList.add('hidden');
  }

  function fillAppMaintenance(enabled, bypassCIDRs) {
    const maintenance = document.getElementById('app-maint');
    maintenance.defaultChecked = enabled;
    maintenance.checked = enabled;
    const bypass = document.getElementById('app-maint-bypass');
    bypass.defaultValue = bypassCIDRs.join(', ');
    bypass.value = bypass.defaultValue;
  }

  function clearAppFormFields() {
    const edit = document.getElementById('app-edit-id');
    edit.value = '';
    delete edit.dataset.updatedAt;
    document.getElementById('apps-edit-hint').classList.add('hidden');
    document.getElementById('name').value = '';
    document.getElementById('host').value = '';
    document.getElementById('backend').value = '';
    document.getElementById('port').value = '';
    document.getElementById('backend-servers').value = '';
    document.getElementById('backend-balance').value = '';
    const healthPath = document.getElementById('app-health-path');
    healthPath.value = '';
    healthPath.defaultValue = '';
    fillAppMaintenance(false, []);
    document.getElementById('app-fwd-auth').value = '';
    document.getElementById('app-fwd-auth-bypass').value = '';
    document.getElementById('behttps').checked = false;
    document.getElementById('ws').checked = false;
    document.getElementById('profile').value = 'balanced';
    document.getElementById('app-security-mode').value = 'balanced';
    renderProfileHelp();
    document.getElementById('app-cert').value = '';
    delete document.getElementById('app-cert').dataset.requestedValue;
    document.getElementById('app-cert-domain').value = '';
    delete document.getElementById('app-cert-domain').dataset.edited;
    document.getElementById('app-cert-mode').value = 'http-01';
    document.getElementById('app-cert-dns-provider').value = '';
    document.getElementById('app-cert-dns-env').value = '';
    document.getElementById('app-cert-fullchain').value = '';
    document.getElementById('app-cert-key').value = '';
    document.getElementById('app-cert-create-status').textContent = '';
    document.getElementById('app-cert-create-panel').classList.add('hidden');
    document.getElementById('btn-app-cert-create-toggle').setAttribute('aria-expanded', 'false');
    document.getElementById('app-advanced').open = false;
    fillBodyPolicy({});
    fillPathPolicy(null);
    fillPublicationRules([]);
    const nlm = document.getElementById('listen-mode');
    if (nlm) nlm.value = 'https_only';
    syncListenModeUI();
    syncPublicationCertificateCreateFields();
    syncPublicationCertificateUI();
    syncSecurityModeHelp();
    clearPublicationErrors();
    updatePublicationReview();
    setAppFormTitle('');
    initRestrictedPathRows();
  }

  function panelFromHash() {
    const raw = (location.hash || '#dashboard').split('?')[0].toLowerCase();
    return HASH_TO_PANEL[raw] || 'dashboard';
  }

  function setActiveNav(panel) {
    document.querySelectorAll('.nav-link').forEach((a) => {
      const active = a.getAttribute('data-tab') === panel;
      a.classList.toggle('active', active);
      if (active) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }

  function showTabPanel(panel) {
    document.querySelectorAll('.tab-panel').forEach((el) => {
      el.classList.toggle('active', el.id === 'tab-' + panel);
    });
    setActiveNav(panel);
  }

  function openMobileNav() {
    document.body.classList.add('nav-open');
    const toggle = document.getElementById('nav-toggle');
    toggle.setAttribute('aria-expanded', 'true');
    toggle.setAttribute('aria-label', 'Close navigation');
    document.getElementById('main-content').inert = true;
    document.getElementById('nav-overlay').setAttribute('aria-hidden', 'false');
    const current = document.querySelector('.nav-link[aria-current="page"]');
    (current && current.getClientRects().length ? current : document.querySelector('.nav-link')).focus();
  }

  function closeMobileNav(restoreFocus) {
    document.body.classList.remove('nav-open');
    const toggle = document.getElementById('nav-toggle');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open navigation');
    document.getElementById('main-content').inert = false;
    document.getElementById('nav-overlay').setAttribute('aria-hidden', 'true');
    if (restoreFocus) toggle.focus();
  }

  window.matchMedia('(max-width: 768px)').addEventListener('change', event => {
    const sidebar = document.getElementById('app-sidebar');
    if (event.matches) closeMobileNav(sidebar.contains(document.activeElement));
    else closeMobileNav(false);
  });

  function showTabFromHash() {
    if (document.getElementById('view-app').classList.contains('hidden')) return;
    const raw = (location.hash || '#dashboard').split('?')[0].toLowerCase();
    if (!HASH_TO_PANEL[raw]) {
      location.hash = '#dashboard';
      return;
    }
    const panel = HASH_TO_PANEL[raw];
    if (panel !== 'dashboard') stopDashStatsTimer();
    if (panel !== 'logs') stopAuditRefreshTimer();
    showTabPanel(panel);
    switch (panel) {
      case 'dashboard':
        loadDashboard();
        break;
      case 'apps':
        loadApps();
        void refreshEdgeStatus();
        loadProfileSelect();
        loadSecurityModesForApps();
        void loadCertOptionsForApps().then(() => syncListenModeUI());
        syncListenModeUI();
        break;
      case 'certs':
        void (async () => {
          await loadSettingsPanel();
          loadCertDashboard();
        })();
        break;
      case 'security':
        void (async () => {
          await loadSettingsPanel();
          loadProfilesDoc();
          loadBlockedUATable();
          await refreshGeoIPProvidersNote();
        })();
        break;
      case 'crowdsec':
        void (async () => {
          await loadSettingsPanel();
          await loadCrowdsecDecisionsTable();
        })();
        break;
      case 'fail2ban':
        void loadFail2banOverview();
        break;
      case 'system':
        loadSystemTab();
        break;
      case 'mcp':
        void loadMCPStatus();
        void loadMCPConnections();
        break;
      case 'network':
        loadNetworkTab();
        break;
      case 'users':
        if (!document.body.classList.contains('role-viewer')) loadPanelUsers();
        loadUsersTab();
        break;
      case 'config':
        loadRevisions();
        void refreshEdgeStatus();
        break;
      case 'settings':
        void loadSettingsTab();
        break;
      case 'logs':
        document.getElementById('policy-matches-host').value = policyMatchesHost();
        if (policyMatchesHost()) document.getElementById('policy-matches-title').focus();
        loadBlocked();
        loadPolicyMatches();
        loadAuditPage(true);
        syncAuditAutoRefresh();
        break;
      case 'about':
        void loadAbout();
        break;
      default:
        break;
    }
  }

  document.getElementById('nav-toggle').onclick = () => {
    if (document.body.classList.contains('nav-open')) closeMobileNav(true);
    else openMobileNav();
  };
  document.getElementById('nav-overlay').onclick = () => closeMobileNav(true);
  document.getElementById('sidebar-nav').onclick = (e) => {
    if (e.target.closest('a.nav-link')) {
      closeMobileNav(false);
      document.getElementById('main-content').focus();
    }
  };
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.body.classList.contains('nav-open')) {
      e.preventDefault();
      closeMobileNav(true);
    }
  });

  window.addEventListener('hashchange', () => {
    showTabFromHash();
  });

  function renderApplicationVersion(value) {
    const version = typeof value === 'string' ? value.trim() : '';
    document.getElementById('header-version').textContent = version ? 'v' + version : 'Version unavailable';
    document.getElementById('dash-version').textContent = version || 'Unknown';
  }

  async function loadApplicationVersion() {
    try {
      const response = await fetch('/api/v1/status', { headers: hdr(), cache: 'no-store' });
      const status = response.ok ? await response.json() : {};
      renderApplicationVersion(status.version);
      setHostTimezone(status.timezone);
    } catch (_) {
      renderApplicationVersion('');
    }
  }

  let hostTimeFormatter = null;
  setHostTimezone('UTC');

  function hostTimezoneFormatter(timeZone) {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'shortOffset'
    });
  }

  function setHostTimezone(timezone) {
    try {
      hostTimeFormatter = hostTimezoneFormatter(timezone || 'UTC');
      return true;
    } catch (_) {
      hostTimeFormatter = null;
      return false;
    }
  }

  function formatHostTime(value) {
    if (!value) return '—';
    const time = new Date(value);
    if (!Number.isFinite(time.getTime())) return String(value);
    if (!hostTimeFormatter) return time.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
    const parts = Object.fromEntries(hostTimeFormatter.formatToParts(time).map(({type, value}) => [type, value]));
    const zone = parts.timeZoneName.replace('−', '-');
    const offset = /^GMT(?:[+-]0(?::00)?)?$/.test(zone) ? 'UTC' : zone;
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} ${offset}`;
  }

  let aboutGeneration = 0;

  async function loadAbout() {
    const gen = ++aboutGeneration;
    const status = document.getElementById('about-status');
    const components = document.getElementById('about-components');
    status.textContent = 'Loading product information…';
    try {
      const response = await fetch('/api/v1/about', { headers: hdr() });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (gen !== aboutGeneration) return;
      document.getElementById('about-version').textContent = data.version || 'Unavailable';
      document.getElementById('about-runtime').textContent = [data.go_version, data.platform].filter(Boolean).join(' · ') || 'Unavailable';
      document.getElementById('about-revision-label').classList.toggle('hidden', !data.revision);
      document.getElementById('about-revision-row').classList.toggle('hidden', !data.revision);
      document.getElementById('about-revision').textContent = data.revision
        ? data.revision + (data.modified ? ' (modified source)' : '') : '';
      document.getElementById('about-source-time-label').classList.toggle('hidden', !data.source_time);
      document.getElementById('about-source-time-row').classList.toggle('hidden', !data.source_time);
      const sourceTime = document.getElementById('about-source-time');
      sourceTime.dateTime = data.source_time || '';
      sourceTime.textContent = formatHostTime(sourceTime.dateTime);
      components.replaceChildren();
      for (const component of data.components || []) {
        const row = document.createElement('tr');
        for (const value of [component.name, component.version || 'Unavailable', component.source]) {
          const cell = document.createElement('td');
          cell.textContent = value;
          row.appendChild(cell);
        }
        components.appendChild(row);
      }
      document.getElementById('about-license').textContent = data.license_text || 'License text unavailable.';
      document.getElementById('about-notice').textContent = data.notice || 'Notice text unavailable.';
      status.textContent = '';
    } catch (_) {
      if (gen === aboutGeneration) status.textContent = 'Could not load product information.';
    }
  }

  const VIEWER_SAFE_ACTIONS = new Set([
    'btn-dashboard-refresh', 'btn-apps-refresh', 'btn-certs', 'btn-cs-dec', 'btn-cs-ping',
    'btn-f2b-refresh', 'btn-geoip-lookup', 'btn-ipbl-load', 'btn-ipwl-load',
    'btn-revisions-refresh', 'btn-settings-load', 'btn-certs-settings-load', 'btn-security-settings-load', 'btn-cs-settings-load', 'btn-ua-load', 'btn-blocked-refresh',
    'btn-audit-refresh', 'btn-audit-more', 'btn-policy-matches-refresh'
  ]);

  function applyRoleCapabilities(role) {
    currentRole = role === 'viewer' ? 'viewer' : 'admin';
    const viewer = currentRole === 'viewer';
    document.body.classList.toggle('role-viewer', viewer);
    if (viewer && typeof clearHostJournalSnapshot === 'function') {
      clearHostJournalSnapshot('Administrator access is required for service journals.');
    }
    const banner = document.getElementById('viewer-banner');
    if (banner) banner.classList.toggle('hidden', !viewer);
    document.querySelectorAll('main button[id]').forEach((button) => {
      if (VIEWER_SAFE_ACTIONS.has(button.id)) button.setAttribute('data-viewer-action', 'true');
      else button.removeAttribute('data-viewer-action');
    });
  }

  async function refreshSession() {
    const t = getTok();
    if (!t) {
      // Without a status answer, fall back to the sign-in form.
      const st = await fetch('/api/v1/auth/status').then((r) => r.json()).catch(() => ({}));
      show('view-enroll', !!st.enrollment_required);
      show('view-login', !st.enrollment_required);
      show('view-pass', false);
      show('view-app', false);
      return;
    }
    show('view-enroll', false);
    let r;
    try {
      r = await fetch('/api/v1/auth/me', { headers: hdr() });
    } catch (_) {
      show('view-app', false);
      show('view-login', true);
      document.getElementById('login-err').textContent = 'The API is unavailable. Check the appliance and try again.';
      return;
    }
    if (r.status === 401) return;
    const me = await r.json().catch(() => ({}));
    if (!r.ok) { show('view-login', true); return; }
    sessionExpired = false;
    const hu = document.getElementById('header-user');
    if (hu) {
      hu.textContent = '';
      hu.classList.add('hidden');
    }
    if (me.must_change_password) {
      show('view-login', false); show('view-pass', true); show('view-app', false);
    } else {
      show('view-login', false); show('view-pass', false); show('view-app', true);
      if (hu && me.username) {
        hu.textContent = String(me.username) + (me.role === 'viewer' ? ' (read-only)' : '');
        hu.classList.remove('hidden');
      }
      applyRoleCapabilities(me.role);
      renderTOTPStatus(!!me.totp_enabled);
      const status = loadApplicationVersion();
      await loadSettingsPanel();
      await status;
      loadProfileSelect();
      initRestrictedPathRows();
      if (!location.hash || !HASH_TO_PANEL[location.hash.toLowerCase().split('?')[0]]) {
        location.hash = '#dashboard';
      }
      showTabFromHash();
    }
  }

  function initRestrictedPathRows() {
    const box = document.getElementById('restricted-rows');
    if (!box) return;
    box.innerHTML = '';
    addRestrictedPathRow('', '');
  }

  function clearRestrictedPathRows() {
    const box = document.getElementById('restricted-rows');
    if (!box) return;
    box.innerHTML = '';
  }

  function bindAuthForm(name, submit) {
    const form = document.getElementById(name + '-form');
    const button = document.getElementById('btn-' + name);
    form.onsubmit = async (event) => {
      event.preventDefault();
      if (button.disabled) return;
      try {
        await withBusy(button, submit);
      } catch (_) {
        document.getElementById(name + '-err').textContent = 'Could not confirm the result. Check the connection before trying again.';
      }
    };
  }

  bindAuthForm('login', async () => {
    document.getElementById('login-err').textContent = '';
    const body = {
      username: document.getElementById('login-user').value.trim(),
      password: document.getElementById('login-pass').value,
      totp_code: document.getElementById('login-totp').value.trim()
    };
    const r = await fetch('/api/v1/auth/login', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    if (r.status === 429) {
      const retryAfter = r.headers.get('Retry-After') || '?';
      document.getElementById('login-err').textContent =
        'Too many login attempts. Try again in ' + retryAfter + ' seconds.';
      return;
    }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      if (j.error === 'totp_required') {
        document.getElementById('login-totp-row').classList.remove('hidden');
        document.getElementById('login-totp').focus();
        document.getElementById('login-err').textContent = 'Enter the 6-digit code from your authenticator app, or a recovery code.';
        return;
      }
      document.getElementById('login-err').textContent = j.error || r.statusText;
      return;
    }
    document.getElementById('login-totp').value = '';
    document.getElementById('login-totp-row').classList.add('hidden');
    document.getElementById('login-pass').value = '';
    setTok(j.token);
    if (j.must_change_password) {
      show('view-login', false); show('view-pass', true); show('view-app', false);
    } else {
      if (!location.hash.startsWith('#mcp?')) location.hash = '#dashboard';
      await refreshSession();
    }
  });

  bindAuthForm('enroll', async () => {
    const err = document.getElementById('enroll-err');
    err.textContent = '';
    const password = document.getElementById('enroll-pass').value;
    if (password !== document.getElementById('enroll-pass2').value) {
      err.textContent = 'Passwords do not match.';
      document.getElementById('enroll-pass2').focus();
      return;
    }
    const body = {
      secret: document.getElementById('enroll-secret').value.trim(),
      username: document.getElementById('enroll-user').value.trim(),
      password
    };
    const r = await fetch('/api/v1/auth/enroll', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    if (r.status === 429) {
      err.textContent = 'Too many attempts. Try again in ' + (r.headers.get('Retry-After') || '?') + ' seconds.';
      return;
    }
    if (!r.ok) {
      err.textContent = await apiMessage(r);
      return;
    }
    const j = await r.json();
    setTok(j.token);
    document.getElementById('enroll-form').reset();
    await refreshSession();
  });

  bindAuthForm('pass', async () => {
    document.getElementById('pass-err').textContent = '';
    const cur = document.getElementById('old-pass').value;
    const nw = document.getElementById('new-pass').value;
    const nw2 = document.getElementById('new-pass2').value;
    if (nw.length < 8) {
      document.getElementById('pass-err').textContent = 'New password must be at least 8 characters.';
      return;
    }
    if (nw !== nw2) {
      document.getElementById('pass-err').textContent = 'New password and confirmation do not match.';
      document.getElementById('new-pass2').focus();
      return;
    }
    const body = { current_password: cur, new_password: nw };
    const r = await fetch('/api/v1/auth/change-password', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { document.getElementById('pass-err').textContent = j.error || await r.text(); return; }
    setTok(j.token);
    document.getElementById('old-pass').value = '';
    document.getElementById('new-pass').value = '';
    document.getElementById('new-pass2').value = '';
    if (!location.hash.startsWith('#mcp?')) location.hash = '#dashboard';
    await refreshSession();
  });

  document.getElementById('btn-logout').onclick = async () => {
    // Ask the server to revoke the session (bumps users.session_version) before
    // dropping the local copy: clearing sessionStorage alone leaves the JWT
    // valid for its full lifetime anywhere it was captured.
    try {
      await fetch('/api/v1/auth/logout', { method: 'POST', headers: hdr(), body: '{}' });
    } catch (e) {
      /* offline or already revoked — still clear the local token below */
    }
    setTok('');
    currentRole = '';
    sessionExpired = false;
    document.body.classList.remove('role-viewer');
    clearHostJournalSnapshot('Sign in as an administrator to load a journal snapshot.');
    closeMobileNav(false);
    refreshSession();
  };

  document.getElementById('btn-audit-refresh').onclick = () => { loadAuditPage(true); };
  document.getElementById('btn-blocked-refresh').onclick = () => { loadBlocked(); };
  document.getElementById('blocked-period').onchange = () => { loadBlocked(); };
  document.getElementById('policy-matches-filter').onsubmit = (event) => {
    event.preventDefault();
    const host = document.getElementById('policy-matches-host').value.trim();
    const hash = host ? '#logs?host=' + encodeURIComponent(host) : '#logs';
    if (location.hash === hash) loadPolicyMatches();
    else location.hash = hash;
  };
  document.getElementById('policy-matches-period').onchange = () => document.getElementById('policy-matches-filter').requestSubmit();
  document.getElementById('policy-matches-all').onclick = () => { document.getElementById('policy-matches-host').value = ''; };
  document.getElementById('blocked-ips').onclick = (e) => {
    const b = e.target.closest('button[data-block-ip]');
    if (b) blockIPFromLog(b.getAttribute('data-block-ip'), b);
  };
  document.getElementById('btn-audit-more').onclick = () => { loadAuditPage(false); };
  document.getElementById('audit-filter-action').onchange = () => { loadAuditPage(true); syncAuditAutoRefresh(); };
  document.getElementById('btn-host-journal-load').onclick = () => { loadHostJournal(); };
  ['host-journal-unit', 'host-journal-since', 'host-journal-priority', 'host-journal-lines'].forEach((id) => {
    document.getElementById(id).onchange = markHostJournalFiltersChanged;
  });

  const btnDiag = document.getElementById('btn-diagnostics-download');
  if (btnDiag) {
    btnDiag.onclick = async () => {
      const ok = await confirmDialog(
        'This collects system info and logs from the API host (secrets in easy-waf.env are masked).\n\nShare with support if needed.\n\nContinue?',
        { okLabel: 'Download' }
      );
      if (!ok) return;
      await withBusy(btnDiag, async () => {
        const msg = document.getElementById('dash-diag-msg');
        if (msg) {
          msg.textContent = '';
          msg.className = 'warn';
        }
        try {
          const r = await fetch('/api/v1/diagnostics/bundle', { method: 'POST', headers: hdr(), body: '{}' });
          if (r.status === 401) {
            setTok('');
            refreshSession();
            return;
          }
          if (!r.ok) {
            toast(await apiMessage(r), 'err');
            return;
          }
          const blob = await r.blob();
          const cd = r.headers.get('Content-Disposition') || '';
          const m = cd.match(/filename="([^"]+)"/);
          const name = m ? m[1] : 'easy-waf-diag-api.tar.gz';
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = name;
          a.rel = 'noopener';
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          toast('Download started.', 'ok');
          if (msg) {
            msg.textContent = 'Download started.';
            msg.className = 'ok';
          }
        } catch (e) {
          const errMsg = e && e.message ? e.message : String(e);
          toast(errMsg, 'err');
          if (msg) msg.textContent = errMsg;
        }
      });
    };
  }

  const btnNewApp = document.getElementById('btn-new-app');
  if (btnNewApp) {
    btnNewApp.onclick = () => {
      clearAppFormFields();
      setAppFormCollapsed(false);
      document.getElementById('name').focus();
    };
  }
  document.getElementById('audit-auto-refresh').onchange = () => { syncAuditAutoRefresh(); };

  const publicationRulesBox = document.getElementById('publication-rules');
  const publicationRuleAdd = document.getElementById('btn-publication-rule-add');
  publicationRuleAdd.onclick = () => addPublicationRule({}).querySelector('.pub-id').focus();

  function syncPublicationOrder() {
    const rows = [...publicationRulesBox.children];
    rows.forEach((row, i) => {
      row.querySelector('legend').textContent = 'Rule ' + (i + 1);
      row.querySelector('.pub-up').disabled = i === 0;
      row.querySelector('.pub-down').disabled = i === rows.length - 1;
    });
    publicationRuleAdd.disabled = rows.length >= 16;
  }

  function fillPublicationRules(rules) {
    publicationRulesBox.replaceChildren();
    rules.forEach(addPublicationRule);
    syncPublicationOrder();
  }

  function addPublicationRule(rule) {
    const match = rule.match || {};
    const row = document.createElement('fieldset');
    row.className = 'panel';
    row.innerHTML = `
      <legend></legend>
      <div class="row" style="flex-wrap:wrap;gap:0.5rem;align-items:flex-start">
        <label>Rule ID<br /><input type="text" class="pub-id" maxlength="32" value="${esc(rule.id || '')}" placeholder="watch-api" /></label>
        <label>Action<br /><select class="pub-action"><option value="count">Count</option><option value="block">Block</option><option value="pass">Pass</option></select></label>
        <label>Path prefix<br /><input type="text" class="pub-path" value="${esc(match.path_prefix || '')}" placeholder="/api" /></label>
        <label>Methods<br /><input type="text" class="pub-methods" value="${esc((match.methods || []).join(', '))}" placeholder="GET, POST" /></label>
        <label>Source IPs or CIDRs<br /><input type="text" class="pub-sources" value="${esc((match.source_cidrs || []).join(', '))}" placeholder="192.0.2.0/24, 2001:db8::/32" /></label>
        <label>Header<br /><input type="text" class="pub-header" value="${esc(match.header || '')}" placeholder="User-Agent" /></label>
        <label>Header value prefix<br /><input type="text" class="pub-prefix" value="${esc(match.header_prefix || '')}" placeholder="Optional" /></label>
      </div>
      <div class="row" style="margin-top:0.5rem">
        <button type="button" class="secondary pub-up">Move up</button>
        <button type="button" class="secondary pub-down">Move down</button>
        <button type="button" class="secondary pub-remove">Remove rule</button>
      </div>`;
    row.querySelector('.pub-action').value = rule.action || 'count';
    row.querySelector('.pub-up').onclick = () => {
      row.previousElementSibling.before(row);
      syncPublicationOrder();
      row.querySelector('.pub-up:not(:disabled), .pub-down:not(:disabled)').focus();
    };
    row.querySelector('.pub-down').onclick = () => {
      row.nextElementSibling.after(row);
      syncPublicationOrder();
      (row.querySelector('.pub-down:not(:disabled)') || row.querySelector('.pub-up')).focus();
    };
    row.querySelector('.pub-remove').onclick = () => {
      const next = row.nextElementSibling || row.previousElementSibling;
      row.remove();
      syncPublicationOrder();
      (next ? next.querySelector('.pub-remove') : publicationRuleAdd).focus();
    };
    publicationRulesBox.appendChild(row);
    syncPublicationOrder();
    return row;
  }

  function collectPublicationRules() {
    const list = (value) => value.split(/[\s,]+/).filter(Boolean);
    return [...publicationRulesBox.children].map((row) => {
      const value = (field) => row.querySelector('.pub-' + field).value;
      return {
        id: value('id').trim(),
        action: value('action'),
        match: {
          path_prefix: value('path').trim(),
          methods: list(value('methods').toUpperCase()),
          source_cidrs: list(value('sources')),
          header: value('header').trim(),
          header_prefix: value('prefix')
        }
      };
    });
  }

  function fillPathPolicy(policy) {
    const mode = document.getElementById('path-mode');
    const allow = document.getElementById('path-allow');
    const client = document.getElementById('path-client-timeout');
    const server = document.getElementById('path-server-timeout');
    const box = document.getElementById('path-rules');
    if (!mode || !box) return;
    box.innerHTML = '';
    if (!policy) {
      mode.value = '';
      allow.value = '';
      client.value = '0';
      server.value = '0';
      return;
    }
    mode.value = policy.mode || '';
    allow.value = (policy.allow || []).join('\n');
    client.value = String(policy.client_timeout_sec || 0);
    server.value = String(policy.server_timeout_sec || 0);
    (policy.rules || []).forEach((rule) => addPathRuleRow(rule));
  }

  function addPathRuleRow(rule) {
    const box = document.getElementById('path-rules');
    if (!box) return;
    const row = rule || {};
    const wrap = document.createElement('div');
    wrap.className = 'path-rule panel';
    wrap.style.marginTop = '0.5rem';
    const tokenNote = row.edge_token_configured ? 'A token is already stored. Leave the field empty to keep it.' : 'Optional. Stored outside the database and removed before the backend.';
    wrap.innerHTML = `
      <div class="row" style="flex-wrap:wrap;align-items:flex-start;gap:0.5rem">
        <label>Path<br /><input name="path_policy_prefix" class="pr-path" type="text" value="${esc(row.path_prefix || '')}" placeholder="/api/mcp" /></label>
        <label>Require header<br /><input name="path_policy_require_header" class="pr-header" type="text" value="${esc(row.require_header || '')}" placeholder="Authorization" /></label>
        <label>Value prefix<br /><input name="path_policy_value_prefix" class="pr-prefix" type="text" value="${esc(row.require_value_prefix || '')}" placeholder="Bearer " /></label>
        <label>Client timeout<br /><input name="path_policy_client_timeout" class="pr-client" type="number" min="0" max="86400" value="${esc(String(row.client_timeout_sec || 0))}" /></label>
        <label>Server timeout<br /><input name="path_policy_server_timeout" class="pr-server" type="number" min="0" max="86400" value="${esc(String(row.server_timeout_sec || 0))}" /></label>
        <label>Requests / 10s<br /><input name="path_policy_rate" class="pr-rate" type="number" min="0" value="${esc(String(row.rate_per_10s || 0))}" /></label>
        <label>Edge token header<br /><input name="path_policy_edge_token_header" class="pr-edge-header" type="text" value="${esc(row.edge_token_header || '')}" placeholder="X-Edge-Token" /></label>
        <label>Edge token<br /><input name="path_policy_edge_token" class="pr-edge-token" type="password" autocomplete="new-password" value="" /></label>
        <label><input name="path_policy_clear_edge_token" class="pr-edge-clear" type="checkbox" /> Clear stored token</label>
        <button type="button" class="secondary btn-pr-remove">Remove</button>
      </div>
      <p class="dash-note">${esc(tokenNote)}</p>`;
    wrap.querySelector('.btn-pr-remove').onclick = () => wrap.remove();
    box.appendChild(wrap);
  }

  function collectPathPolicy() {
    const mode = document.getElementById('path-mode').value;
    const allow = document.getElementById('path-allow').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const client = parseInt(document.getElementById('path-client-timeout').value, 10) || 0;
    const server = parseInt(document.getElementById('path-server-timeout').value, 10) || 0;
    const rules = [];
    document.querySelectorAll('#path-rules .path-rule').forEach((row) => {
      const rule = {
        path_prefix: row.querySelector('.pr-path').value.trim(),
        require_header: row.querySelector('.pr-header').value.trim(),
        require_value_prefix: row.querySelector('.pr-prefix').value,
        client_timeout_sec: parseInt(row.querySelector('.pr-client').value, 10) || 0,
        server_timeout_sec: parseInt(row.querySelector('.pr-server').value, 10) || 0,
        rate_per_10s: parseInt(row.querySelector('.pr-rate').value, 10) || 0,
        edge_token_header: row.querySelector('.pr-edge-header').value.trim()
      };
      const token = row.querySelector('.pr-edge-token').value;
      if (token) rule.edge_token = token;
      if (row.querySelector('.pr-edge-clear').checked) rule.clear_edge_token = true;
      if (rule.path_prefix) rules.push(rule);
    });
    if (!mode && !allow.length && !client && !server && !rules.length) return undefined;
    const policy = {};
    if (mode) policy.mode = mode;
    if (allow.length) policy.allow = allow;
    if (client) policy.client_timeout_sec = client;
    if (server) policy.server_timeout_sec = server;
    if (rules.length) policy.rules = rules;
    return policy;
  }

  const btnPathRule = document.getElementById('btn-path-rule-add');
  if (btnPathRule) btnPathRule.onclick = () => addPathRuleRow(null);

  function addRestrictedPathRow(prefix, cidrsText) {
    const wrap = document.createElement('div');
    wrap.className = 'rp-row panel';
    wrap.style.marginTop = '0.5rem';
    wrap.style.maxWidth = '100%';
    wrap.innerHTML = `
      <div class="row" style="align-items:flex-start">
        <label>Path prefix<br /><input name="restricted_path_prefix" class="rp-prefix" type="text" placeholder="/api" value="${esc(prefix || '')}" style="min-width:8rem" /></label>
        <label style="flex:1">Allowed CIDRs (one per line)<br /><textarea name="restricted_path_allowed_cidrs" class="rp-cidrs" rows="4" style="width:100%;min-width:14rem;font-family:monospace;font-size:12px" placeholder="192.168.0.0/16">${esc(cidrsText || '')}</textarea></label>
        <button type="button" class="secondary btn-rp-remove">Remove</button>
      </div>`;
    wrap.querySelector('.btn-rp-remove').onclick = () => wrap.remove();
    document.getElementById('restricted-rows').appendChild(wrap);
  }

  function collectRestrictedPaths() {
    const out = [];
    document.querySelectorAll('#restricted-rows .rp-row').forEach((row) => {
      const prefix = row.querySelector('.rp-prefix').value.trim();
      const raw = row.querySelector('.rp-cidrs').value;
      const cidrs = raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (prefix && cidrs.length) out.push({ path_prefix: prefix, allowed_cidrs: cidrs });
    });
    return out;
  }

  document.getElementById('btn-rp-add').onclick = () => addRestrictedPathRow('', '');

  let appProfilesCatalog = {};
  let profileSelectRequest = 0;

  function renderProfileHelp() {
    const name = document.getElementById('profile').value;
    const p = appProfilesCatalog[name];
    const help = document.getElementById('profile-help');
    if (!help) return;
    if (!p) { help.textContent = 'Profile details unavailable. Refresh the page to retry.'; return; }
    const lines = [p.description || p.Description || name];
    if (Number.isFinite(p.server_timeout_ms) && Number.isFinite(p.connect_timeout_ms)) {
      lines.push('Server timeout: ' + p.server_timeout_ms / 1000 + ' s. Connect timeout: ' + p.connect_timeout_ms / 1000 + ' s.');
    }
    if (Number.isFinite(p.rate_limit_burst)) {
      lines.push('Profile rate threshold: ' + p.rate_limit_burst + ' requests / 10 s per client IP when rate limiting is enabled. Overrides still apply.');
    }
    if (Array.isArray(p.block_paths)) lines.push('Probe paths blocked when Path ACL is enabled: ' + (p.block_paths.join(', ') || 'none') + '.');
    if (Array.isArray(p.extra_blocked_methods)) lines.push('Methods blocked when method filtering is enabled: ' + (p.extra_blocked_methods.join(', ') || 'none') + '.');
    if (Number.isFinite(p.max_body_bytes)) {
      lines.push('Default body limit: ' + (p.max_body_bytes ? p.max_body_bytes / 1048576 + ' MiB' : 'none') + '. Multipart: ' + (p.block_multipart ? 'blocked outside allowed paths' : 'allowed') + '.');
    }
    if (name === 'home-assistant') lines.push('One publication can serve the Home Assistant web UI, Companion and API. Enable WebSocket; configure trusted proxies in Home Assistant.');
    if (name === 'openclaw') lines.push('The default Gateway port is 18789. In OpenClaw, trust only the proxy address and allow the exact HTTPS origin. Keep device pairing enabled.');
    if (p.path_policy && Array.isArray(p.path_policy.allow)) {
      lines.push('Default allowed paths for a new, unset path policy: ' + p.path_policy.allow.join(', ') + '. Other paths return 404; this is not a full Home Assistant publication. Existing path rules stay in effect.');
    }
    help.textContent = lines.join('\n');
  }

  async function loadProfileSelect() {
    const sel = document.getElementById('profile');
    sel.onchange = renderProfileHelp;
    const request = ++profileSelectRequest;
    try {
      const r = await fetch('/api/v1/profiles', { headers: hdr() });
      if (request !== profileSelectRequest) return;
      if (r.status === 403) { refreshSession(); return; }
      if (!r.ok) throw new Error('profile catalogue unavailable');
      const j = await r.json();
      if (request !== profileSelectRequest) return;
      if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('invalid profile catalogue');
      appProfilesCatalog = j;
      const keys = Object.keys(j).sort();
      const prev = sel.value;
      const escLocal = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
      sel.innerHTML = keys.map((k) => {
        const d = (j[k] && (j[k].Description || j[k].description)) || '';
        return `<option value="${escLocal(k)}" title="${escLocal(d)}">${escLocal(k)}</option>`;
      }).join('');
      if (keys.includes(prev)) sel.value = prev;
      renderProfileHelp();
    } catch (_) {
      if (request !== profileSelectRequest) return;
      const help = document.getElementById('profile-help');
      if (help) help.textContent = 'Profile details unavailable. Refresh the page to retry.';
    }
  }

  async function loadProfilesDoc() {
    const el = document.getElementById('profiles-doc');
    if (!el) return;
    el.textContent = 'Loading…';
    const r = await fetch('/api/v1/profiles', { headers: hdr() });
    if (!r.ok) { el.textContent = await r.text(); return; }
    const j = await r.json();
    const keys = Object.keys(j).sort();
    const escLocal = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const rows = keys.map((k) => {
      const p = j[k] || {};
      const d = escLocal((p.Description || p.description || '').trim() || '—');
      return `<tr><td><code>${escLocal(k)}</code></td><td>${d}</td></tr>`;
    }).join('');
    el.innerHTML = `<table><thead><tr><th>Profile</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  let appCertificatesCache = [];

  function certificatePublicationState(certificate) {
    if (!certificate) return 'unknown';
    const status = String(certificate.acme_status || '').toLowerCase();
    if (status === 'pending' || status === 'issuing') return 'pending';
    if (status === 'failed') return 'failed';
    const hasKey = !!String(certificate.pem_key_path || '').trim();
    const hasCertificate = !!String(certificate.fullchain_path || certificate.pem_crt_path || '').trim();
    return status === 'ready' && hasKey && hasCertificate ? 'ready' : 'unavailable';
  }

  function selectedPublicationCertificate() {
    const id = (document.getElementById('app-cert') || {}).value || '';
    return appCertificatesCache.find((certificate) => certificate.id === id) || null;
  }

  function syncPublicationCertificateUI() {
    const status = document.getElementById('app-cert-status');
    const listenMode = (document.getElementById('listen-mode') || {}).value || 'https_only';
    if (!status) return;
    if (listenMode === 'http_only') {
      status.dataset.state = 'ready';
      status.textContent = 'A certificate is not required for intentional HTTP-only publication.';
      return;
    }
    const certificate = selectedPublicationCertificate();
    const state = certificatePublicationState(certificate);
    status.dataset.state = state;
    if (!certificate) {
      status.textContent = 'Choose a ready certificate, or create one below. The application is not saved without it.';
    } else if (state === 'ready') {
      status.textContent = 'Ready certificate: ' + (certificate.primary_domain || certificate.id) + '. Readiness is based on stored PEM metadata; Apply performs the authoritative file and HAProxy validation.';
    } else if (state === 'pending') {
      status.textContent = 'Issuance pending for ' + (certificate.primary_domain || certificate.id) + '. Application is not saved until the certificate is ready. Refresh after the ACME worker completes.';
    } else if (state === 'failed') {
      status.textContent = 'Issuance failed for ' + (certificate.primary_domain || certificate.id) + ': ' + (certificate.last_error || 'check Certificates and the ACME worker journal') + '.';
    } else {
      status.textContent = 'Certificate material is unavailable for ' + (certificate.primary_domain || certificate.id) + '. Application is not saved until full chain and key metadata are ready.';
    }
  }

  function validatePublicationBasics(draft, certificate) {
    const errors = {};
    if (!String(draft.name || '').trim()) errors.name = 'Enter an application name.';
    const host = String(draft.public_host || '').trim();
    if (!host || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) || !host.includes('.')) errors.host = 'Enter a lowercase DNS hostname such as ha.example.com.';
    const backend = String(draft.backend_host || '').trim();
    if (!backend || !/^[A-Za-z0-9._:[\]-]+$/.test(backend)) errors.backend = 'Enter a backend hostname or IP address.';
    const port = Number(draft.backend_port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.port = 'Enter a port from 1 to 65535.';
    if (draft.listen_mode !== 'http_only') {
      if (!draft.certificate_id) errors.certificate = 'Choose a ready certificate for HTTPS.';
      else {
        const state = certificatePublicationState(certificate);
        if (state !== 'ready') errors.certificate = state === 'pending'
          ? 'Certificate issuance is pending. Refresh after the ACME worker completes.'
          : state === 'failed'
            ? 'Certificate issuance failed. Resolve it on Certificates before saving.'
            : 'Certificate full chain and key are not ready for publication.';
      }
    }
    return errors;
  }

  function clearPublicationErrors() {
    for (const key of ['name', 'host', 'backend', 'port', 'certificate']) {
      const message = document.getElementById(key + '-error');
      const field = document.getElementById('field-' + key);
      const control = document.getElementById(key === 'certificate' ? 'app-cert' : key);
      if (message) message.textContent = '';
      if (field) field.classList.remove('has-error');
      if (control) control.removeAttribute('aria-invalid');
    }
    const summary = document.getElementById('apps-form-error');
    if (summary) {
      summary.textContent = '';
      summary.classList.add('hidden');
    }
  }

  function showPublicationErrors(errors, message) {
    clearPublicationErrors();
    const keys = Object.keys(errors || {});
    for (const key of keys) {
      const target = document.getElementById(key + '-error');
      const field = document.getElementById('field-' + key);
      const control = document.getElementById(key === 'certificate' ? 'app-cert' : key);
      if (target) target.textContent = errors[key];
      if (field) field.classList.add('has-error');
      if (control) control.setAttribute('aria-invalid', 'true');
    }
    const summary = document.getElementById('apps-form-error');
    if (summary) {
      summary.textContent = message || (keys.length ? 'Review the highlighted fields. Nothing has been submitted.' : 'The application was not saved.');
      summary.classList.remove('hidden');
      summary.focus();
    }
  }

  function syncPublicationCertificateCreateFields() {
    const mode = (document.getElementById('app-cert-mode') || {}).value || 'http-01';
    const dns = document.getElementById('app-cert-dns-fields');
    const manual = document.getElementById('app-cert-manual-fields');
    const staging = document.getElementById('app-cert-staging');
    const create = document.getElementById('btn-app-cert-create');
    if (dns) dns.classList.toggle('hidden', mode !== 'dns-01');
    if (manual) manual.classList.toggle('hidden', mode !== 'manual');
    if (staging) staging.disabled = mode === 'manual';
    if (create) create.textContent = mode === 'manual' ? 'Create manual certificate metadata' : 'Create certificate & request issuance';
  }

  async function createPublicationCertificate() {
    const output = document.getElementById('app-cert-create-status');
    const domain = (document.getElementById('app-cert-domain') || {}).value.trim().toLowerCase();
    const mode = (document.getElementById('app-cert-mode') || {}).value || 'http-01';
    const fullchain = (document.getElementById('app-cert-fullchain') || {}).value.trim();
    const key = (document.getElementById('app-cert-key') || {}).value.trim();
    if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain) || !domain.includes('.')) {
      if (output) {
        output.dataset.state = 'failed';
        output.textContent = 'Enter a lowercase DNS hostname before creating the certificate.';
      }
      return null;
    }
    if (mode === 'manual' && (!fullchain || !key)) {
      if (output) {
        output.dataset.state = 'failed';
        output.textContent = 'Manual certificates require both full chain and private key paths.';
      }
      return null;
    }
    const body = { primary_domain: domain, mode, staging: !!(document.getElementById('app-cert-staging') || {}).checked };
    if (mode === 'dns-01') {
      body.dns_provider = (document.getElementById('app-cert-dns-provider') || {}).value;
      body.dns_credentials_env_file = (document.getElementById('app-cert-dns-env') || {}).value.trim();
    }
    if (mode === 'manual') {
      body.fullchain_path = fullchain;
      body.pem_key_path = key;
    }
    if (output) {
      output.dataset.state = 'pending';
      output.textContent = 'Creating certificate metadata…';
    }
    let createdResponse;
    try {
      createdResponse = await fetch('/api/v1/certificates', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    } catch (_) {
      if (output) {
        output.dataset.state = 'failed';
        output.textContent = 'Certificate was not created because the API is unavailable. Your input is still available.';
      }
      return null;
    }
    if (!createdResponse.ok) {
      if (output) {
        output.dataset.state = 'failed';
        output.textContent = 'Certificate was not created: ' + await apiMessage(createdResponse);
      }
      return null;
    }
    let certificate = await createdResponse.json();
    if (mode === 'http-01' || mode === 'dns-01') {
      const issueBody = mode === 'dns-01' ? { mode, dns_provider: body.dns_provider, dns_credentials_env_file: body.dns_credentials_env_file } : { mode };
      let issueResponse;
      try {
        issueResponse = await fetch('/api/v1/certificates/' + encodeURIComponent(certificate.id) + '/request-issue', { method: 'POST', headers: hdr(), body: JSON.stringify(issueBody) });
      } catch (_) {
        if (output) {
          output.dataset.state = 'failed';
          output.textContent = 'Certificate metadata was created, but the issuance request could not reach the API. Retry from Certificates.';
        }
        await loadCertOptionsForApps();
        return certificate;
      }
      if (!issueResponse.ok) {
        if (output) {
          output.dataset.state = 'failed';
          output.textContent = 'Certificate metadata was created, but issuance was not requested: ' + await apiMessage(issueResponse) + '. Retry from Certificates.';
        }
        await loadCertOptionsForApps();
        return certificate;
      }
      certificate = await issueResponse.json();
    }
    await loadCertOptionsForApps();
    const select = document.getElementById('app-cert');
    if (select) select.value = certificate.id;
    syncPublicationCertificateUI();
    if (output) {
      const state = certificatePublicationState(certificate);
      output.dataset.state = state;
      output.textContent = mode === 'manual'
        ? 'Certificate metadata created. Apply will verify the configured files.'
        : 'Issuance requested. Status is ' + state + '; refresh certificates after the ACME worker completes.';
    }
    return certificate;
  }

  async function loadCertOptionsForApps() {
    const sel = document.getElementById('app-cert');
    if (!sel) return;
    let r;
    try {
      r = await fetch('/api/v1/certificates', { headers: hdr() });
    } catch (_) {
      r = null;
    }
    if (!r || !r.ok) {
      appCertificatesCache = [];
      const status = document.getElementById('app-cert-status');
      if (status) {
        status.dataset.state = 'unavailable';
        status.textContent = 'Certificate inventory is unavailable. Refresh before saving an HTTPS publication.';
      }
      return;
    }
    const list = await r.json().catch(() => []);
    appCertificatesCache = Array.isArray(list) ? list : [];
    const cur = sel.value || sel.dataset.requestedValue || '';
    sel.innerHTML = '<option value="">— none —</option>' +
      appCertificatesCache.map((c) => {
        const state = certificatePublicationState(c);
        return '<option value="' + esc(c.id) + '">' + esc(c.primary_domain || c.id) + ' — ' + esc(state) + '</option>';
      }).join('');
    if (cur && [...sel.options].some((o) => o.value === cur)) sel.value = cur;
    delete sel.dataset.requestedValue;
    syncPublicationCertificateUI();
  }

  const PUBLICATION_SECURITY_PRESETS = {
    full: {rate_limit_enabled:true, path_acl_enabled:true, method_filter_enabled:true, basic_waf_enabled:true, bot_protection_enabled:true, ip_blacklist_enabled:true, ip_allowlist_enabled:true, geoip_enabled:true, crowdsec_enabled:true},
    balanced: {rate_limit_enabled:true, path_acl_enabled:true, method_filter_enabled:true, basic_waf_enabled:true, bot_protection_enabled:true, ip_blacklist_enabled:true, ip_allowlist_enabled:true, geoip_enabled:false, crowdsec_enabled:true},
    'trusted-lan': {rate_limit_enabled:true, path_acl_enabled:false, method_filter_enabled:true, basic_waf_enabled:false, bot_protection_enabled:false, ip_blacklist_enabled:true, ip_allowlist_enabled:true, geoip_enabled:false, crowdsec_enabled:true},
    'reverse-proxy-only': {rate_limit_enabled:false, path_acl_enabled:false, method_filter_enabled:false, basic_waf_enabled:false, bot_protection_enabled:false, ip_blacklist_enabled:false, ip_allowlist_enabled:false, geoip_enabled:false, crowdsec_enabled:false}
  };
  let appSecurityModesCatalog = [];

  function securityForPublication(mode, existing) {
    if (mode === 'custom' && existing) return { ...existing };
    const preset = PUBLICATION_SECURITY_PRESETS[mode] || PUBLICATION_SECURITY_PRESETS.balanced;
    return { ...preset, mode: PUBLICATION_SECURITY_PRESETS[mode] ? mode : 'balanced' };
  }

  function syncSecurityModeHelp() {
    const select = document.getElementById('app-security-mode');
    const help = document.getElementById('app-security-mode-help');
    if (!select || !help) return;
    const meta = appSecurityModesCatalog.find((item) => item.id === select.value);
    const fallbacks = {
      full: 'All protection layers, including GeoIP. Review the country policy before saving.',
      balanced: 'Default home posture: all layers except GeoIP.',
      'trusted-lan': 'Reduced heuristics for trusted LAN services; internet exposure needs careful review.',
      'reverse-proxy-only': 'Routing and TLS only. WAF-style protection layers are disabled.',
      custom: 'Keeps the existing custom layer configuration.'
    };
    help.textContent = (meta && meta.description) || fallbacks[select.value] || fallbacks.balanced;
    updatePublicationReview();
  }

  async function loadSecurityModesForApps() {
    const select = document.getElementById('app-security-mode');
    if (!select) return;
    const previous = select.value || 'balanced';
    const response = await fetch('/api/v1/security/modes', { headers: hdr() }).catch(() => null);
    if (response && response.ok) {
      const data = await response.json().catch(() => []);
      if (Array.isArray(data)) appSecurityModesCatalog = data;
    }
    const items = appSecurityModesCatalog.filter((item) => item && item.id && item.id !== 'custom');
    if (items.length) {
      select.innerHTML = items.map((item) => '<option value="' + esc(item.id) + '">' + esc(item.label || item.id) + '</option>').join('') +
        '<option value="custom">Custom (existing configuration)</option>';
    }
    select.value = [...select.options].some((option) => option.value === previous) ? previous : 'balanced';
    syncSecurityModeHelp();
  }

  function readPublicationBasics() {
    const listenMode = (document.getElementById('listen-mode') || {}).value || 'https_only';
    return {
      name: document.getElementById('name').value.trim(),
      public_host: document.getElementById('host').value.trim(),
      backend_host: document.getElementById('backend').value.trim(),
      backend_port: Number(document.getElementById('port').value),
      listen_mode: listenMode,
      certificate_id: listenMode === 'http_only' ? '' : document.getElementById('app-cert').value.trim()
    };
  }

  function updatePublicationReview() {
    const box = document.getElementById('app-publication-review');
    if (!box) return;
    const draft = readPublicationBasics();
    const mode = (document.getElementById('app-security-mode') || {}).value || 'balanced';
    const certificate = selectedPublicationCertificate();
    const backendHost = draft.backend_host.includes(':') && !draft.backend_host.startsWith('[')
      ? '[' + draft.backend_host + ']'
      : draft.backend_host;
    const backendTarget = backendHost ? backendHost + ':' + (draft.backend_port || '—') : 'Not entered';
    const tlsText = draft.listen_mode === 'http_only'
      ? 'HTTP only · no certificate'
      : draft.listen_mode + ' · ' + (certificate ? (certificate.primary_domain || certificate.id) + ' (' + certificatePublicationState(certificate) + ')' : 'certificate not selected');
    box.innerHTML =
      '<div><dt>Public route</dt><dd>' + esc(draft.public_host || 'Hostname not entered') + '</dd></div>' +
      '<div><dt>Backend</dt><dd><code>' + esc(backendTarget) + '</code></dd></div>' +
      '<div><dt>TLS</dt><dd>' + esc(tlsText) + '</dd></div>' +
      '<div><dt>Protection</dt><dd>' + esc(mode) + ' · saved intent</dd></div>' +
      '<div><dt>Apply behavior</dt><dd>Save auto-applies unless disabled by the operator.</dd></div>';
  }

  function reviewPublicationDraft() {
    const draft = readPublicationBasics();
    const errors = validatePublicationBasics(draft, selectedPublicationCertificate());
    updatePublicationReview();
    if (Object.keys(errors).length) {
      showPublicationErrors(errors);
      return false;
    }
    clearPublicationErrors();
    return true;
  }

  function appModeCardClass(mode) {
    if (mode === 'reverse-proxy-only') return 'app-card mode-rpo';
    if (mode === 'custom') return 'app-card mode-custom';
    return 'app-card';
  }

  function listenModeBadge(mode) {
    const m = String(mode || 'https_only').toLowerCase();
    switch (m) {
    case 'http_only':
      return '<span class="app-badge app-badge-warn" title="No TLS">HTTP</span>';
    case 'http_and_https':
      return '<span class="app-badge" title="Both protocols">HTTP+S</span>';
    default:
      return '<span class="app-badge app-badge-ok" title="TLS + redirect">HTTPS</span>';
    }
  }

  function syncListenModeUI() {
    const sel = document.getElementById('listen-mode');
    const hint = document.getElementById('listen-mode-hint');
    const warn = document.getElementById('listen-mode-warn');
    if (!sel || !hint || !warn) return;
    const mode = sel.value;
    if (mode === 'http_only') {
      hint.textContent = 'Certificate not needed for HTTP-only apps. Plain HTTP on port 80 only.';
      warn.classList.remove('hidden');
    } else if (mode === 'http_and_https') {
      hint.textContent = 'App accessible on both HTTP (:80) and HTTPS (:443). No automatic redirect. Certificate required.';
      warn.classList.add('hidden');
    } else {
      hint.textContent = (mode === 'redirect_to_https')
        ? 'Same as HTTPS only: certificate required; HTTP requests for this host redirect to HTTPS.'
        : 'Recommended for public services. Certificate required; HTTP requests redirect to HTTPS automatically.';
      warn.classList.add('hidden');
    }
    syncPublicationCertificateUI();
    updatePublicationReview();
  }

  const BADGE_TITLES = {
    '⚡Rate': 'Rate limiting (stick-table)',
    '🛡WAF': 'Basic WAF: SQLi / XSS / path traversal',
    '🤖CS': 'CrowdSec SPOE decisions',
    '🔒IPBL': 'IP blacklist (local + external feeds)',
    '✅Allow': 'IP allowlist bypass',
    '🌍Geo': 'GeoIP country filter',
    '🤖Bot': 'Bot protection (empty / known-bad User-Agent)'
  };

  function appSecurityBadges(sec) {
    if (!sec) return '<span class="app-badge">—</span>';
    const out = [];
    if (sec.rate_limit_enabled) out.push('⚡Rate');
    if (sec.basic_waf_enabled) out.push('🛡WAF');
    if (sec.crowdsec_enabled) out.push('🤖CS');
    if (sec.ip_blacklist_enabled) out.push('🔒IPBL');
    if (cachedSettings && cachedSettings.ipwl_enabled && sec.ip_allowlist_enabled) out.push('✅Allow');
    if (sec.geoip_enabled) out.push('🌍Geo');
    if (sec.bot_protection_enabled) out.push('🤖Bot');
    return out.length
      ? out.map((x) => '<span class="app-badge" title="' + esc(BADGE_TITLES[x] || x) + '">' + x + '</span>').join('')
      : '<span class="app-badge">(layers off)</span>';
  }

  function versionedPublicationURL(app, suffix = '') {
    if (!app || !app.updated_at) {
      toast('Refresh the publication list before changing this publication.', 'err');
      return '';
    }
    return '/api/v1/applications/' + encodeURIComponent(app.id) + suffix +
      '?expected_updated_at=' + encodeURIComponent(app.updated_at);
  }

  async function reportPublicationConflict(response) {
    if (response.status !== 409) return false;
    toast('The publication changed or was deleted. Review the current list before trying again.', 'err');
    await loadApps();
    return true;
  }

  async function deleteApplication(id, btn) {
    const app = appsListCache.find((item) => item.id === id);
    const url = versionedPublicationURL(app);
    if (!url) return;
    if (!(await confirmDialog('Delete publication "' + (app.name || app.public_host) + '" (' + app.public_host + ')?\n\nThe backend service and certificates are kept. This removes the publication from Easy Home WAF.', { danger: true, okLabel: 'Delete publication' }))) return;
    await withBusy(btn, async () => {
      const response = await fetch(url, { method: 'DELETE', headers: hdr() });
      if (await reportPublicationConflict(response)) return;
      if (!response.ok) { toast(await apiMessage(response), 'err'); return; }
      const applied = response.headers.get('X-Easy-Waf-Applied') === 'true';
      markPendingApply(!applied);
      toast(applied ? 'Application deleted and removal applied.' : 'Application deleted. Select Apply HAProxy in Edge changes to activate removal.', 'ok');
      await refreshEdgeStatus();
      if (document.getElementById('app-edit-id').value === id) {
        clearAppFormFields();
        setAppFormCollapsed(true);
      }
      await loadApps();
    });
  }

  async function setAppMaintenance(id, enabled, btn) {
    const url = versionedPublicationURL(appsListCache.find((app) => app.id === id), '/maintenance');
    if (!url) return;
    if (enabled && !(await confirmDialog('Put this application into maintenance?\n\nVisitors get a 503 maintenance page until you end it; the bypass sources set in the form still reach the app.', { okLabel: 'Start maintenance' }))) return;
    await withBusy(btn, async () => {
      const r = await fetch(url, {
        method: 'POST', headers: hdr(), body: JSON.stringify({ enabled })
      });
      if (await reportPublicationConflict(r)) return;
      if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
      await reportApplicationSaved(r, enabled ? 'Maintenance enabled' : 'Maintenance disabled');
      await loadApps();
    });
  }

  async function postAppModeChange(id, mode, selEl) {
    const app = appsListCache.find((item) => item.id === id);
    const prev = app && app.security;
    const prevMode = (prev && prev.mode) || 'balanced';
    const url = versionedPublicationURL(app, '/security/mode');
    if (!url) { selEl.value = prevMode; return; }
    if (mode === 'reverse-proxy-only') {
      const ok = await confirmDialog(
        '⚠ Switch to Reverse Proxy Only?\n\nThis DISABLES all security protections for this application:\n  • Rate limiting\n  • Basic WAF (SQLi/XSS)\n  • CrowdSec\n  • IP blacklist\n  • Bot protection\n  • GeoIP filter\n\nUse ONLY for debugging. Not suitable for production.\n\nContinue?',
        { danger: true, okLabel: 'Enable debug mode' }
      );
      if (!ok) { selEl.value = prevMode; return; }
    }
    const r = await fetch(url, {
      method: 'POST', headers: hdr(), body: JSON.stringify({ mode })
    });
    if (!r.ok) {
      selEl.value = prevMode;
      if (!(await reportPublicationConflict(r))) toast(await apiMessage(r), 'err');
      return;
    }
    await reportApplicationSaved(r, 'Security mode');
    await loadApps();
  }

  function fillAppFormFromApp(id) {
    const a = appsListCache.find((x) => x.id === id);
    if (!a) return;
    setAppFormCollapsed(false);
    setAppFormTitle(a.name || '');
    const edit = document.getElementById('app-edit-id');
    edit.value = a.id;
    edit.dataset.updatedAt = a.updated_at || '';
    document.getElementById('apps-edit-hint').classList.remove('hidden');
    document.getElementById('name').value = a.name || '';
    document.getElementById('host').value = a.public_host || '';
    document.getElementById('backend').value = a.backend_host || '';
    document.getElementById('port').value = String(a.backend_port != null ? a.backend_port : 80);
    document.getElementById('backend-servers').value = formatBackendServers(a.backend_servers);
    document.getElementById('backend-balance').value = a.backend_balance || '';
    const healthPath = document.getElementById('app-health-path');
    healthPath.defaultValue = a.health_path || '';
    healthPath.value = healthPath.defaultValue;
    fillAppMaintenance(!!a.maintenance, a.maintenance_bypass_cidrs || []);
    document.getElementById('app-fwd-auth').value = a.forward_auth_url || '';
    document.getElementById('app-fwd-auth-bypass').value = (a.forward_auth_bypass_cidrs || []).join(', ');
    document.getElementById('behttps').checked = !!a.backend_https;
    document.getElementById('ws').checked = !!a.websocket;
    document.getElementById('profile').value = a.profile || 'balanced';
    const securityMode = (a.security && a.security.mode) || 'balanced';
    document.getElementById('app-security-mode').value =
      ['full', 'balanced', 'trusted-lan', 'reverse-proxy-only', 'custom'].includes(securityMode) ? securityMode : 'custom';
    renderProfileHelp();
    const lmSel = document.getElementById('listen-mode');
    if (lmSel) {
      const lm = (a.listen_mode || 'https_only').toLowerCase();
      const allowed = new Set(['https_only', 'http_only', 'http_and_https', 'redirect_to_https']);
      lmSel.value = allowed.has(lm) ? lm : 'https_only';
    }
    document.getElementById('app-cert').dataset.requestedValue = a.certificate_id || '';
    document.getElementById('app-cert').value = a.certificate_id || '';
    syncListenModeUI();
    syncSecurityModeHelp();
    clearPublicationErrors();
    fillBodyPolicy(a.security || {});
    fillPathPolicy(a.path_policy || null);
    fillPublicationRules(a.policy_rules || []);
    clearRestrictedPathRows();
    (a.restricted_paths || []).forEach((rp) => addRestrictedPathRow(rp.path_prefix || '', (rp.allowed_cidrs || []).join('\n')));
    if (!(a.restricted_paths || []).length) addRestrictedPathRow('', '');
    document.getElementById('app-advanced').open = !!(
      (a.backend_servers || []).length || a.health_path || a.maintenance || a.forward_auth_url ||
      (a.restricted_paths || []).some((rp) => rp.path_prefix || (rp.allowed_cidrs || []).length) ||
      a.path_policy
    );
    updatePublicationReview();
    window.location.hash = '#apps';
    const panel = document.getElementById('app-form-panel');
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  document.getElementById('btn-cancel-edit').onclick = () => {
    clearAppFormFields();
    setAppFormCollapsed(true);
  };

  async function loadApps() {
    const msg = document.getElementById('apps-msg');
    const box = document.getElementById('apps');
    if (msg) msg.textContent = '';
    tableState(box, 'loading');
    const r = await fetch('/api/v1/applications', { headers: hdr() });
    const txt = await r.text();
    let j = [];
    try { j = JSON.parse(txt); } catch (_) { j = {}; }
    if (r.status === 403 && j.must_change_password) { refreshSession(); return; }
    if (!r.ok) {
      const errMsg = (j && typeof j === 'object' && (j.error || j.message)) || txt || r.statusText;
      tableState(box, 'error', { message: errMsg });
      return;
    }
    if (!cachedSettings) await loadSettingsPanel();
    appsListCache = Array.isArray(j) ? j : [];
    if (!appsListCache.length) {
      tableState(box, 'empty', { message: 'No applications yet. Use "New application" below.' });
      return;
    }
    box.innerHTML = appsListCache.map((a) => {
      const sec = a.security || {};
      const mode = sec.mode || 'balanced';
      const ws = a.websocket ? ' <span class="app-badge">WS</span>' : '';
      const lmb = ' ' + listenModeBadge(a.listen_mode);
      const rpoWarn = mode === 'reverse-proxy-only' ? '<div class="app-card-warn">⚠ DEBUG MODE — no WAF protections</div>' : '';
      const diagnosticsID = appDiagnosticsDOMID(a.id);
      return `<div class="${appModeCardClass(mode)}">
  <div class="app-card-head">
    <div>
      <p class="app-card-title">${esc(a.name)}</p>
      <p class="app-card-sub">${esc(a.public_host)} → <code>${esc(a.backend_host)}:${a.backend_port}</code>${(a.backend_servers || []).length ? ' <span class="app-badge">+' + a.backend_servers.length + ' server(s)</span>' : ''}${ws}${lmb}${a.maintenance ? ' <span class="app-badge" style="background:#9a6700;color:#fff">MAINTENANCE</span>' : ''}</p>
    </div>
    <div class="row" style="margin:0;gap:0.35rem">
      <button type="button" class="secondary btn-app-diagnostics" data-viewer-action="true" data-id="${esc(a.id)}" aria-expanded="false" aria-controls="${esc(diagnosticsID)}">Diagnose</button>
      <a href="#logs?host=${encodeURIComponent(a.public_host)}">Rule matches</a>
      <button type="button" class="secondary btn-app-maint" data-id="${esc(a.id)}" data-on="${a.maintenance ? '1' : ''}">${a.maintenance ? 'End maintenance' : 'Maintenance'}</button>
      <button type="button" class="secondary btn-app-edit" data-id="${esc(a.id)}">Edit</button>
      <button type="button" class="secondary btn-app-delete admin-only" data-id="${esc(a.id)}">Delete</button>
    </div>
  </div>
  <div class="row" style="margin:0;align-items:center;gap:0.5rem">
    <label style="font-size:0.82rem;color:var(--muted)">Security mode
      <select name="application_security_mode" class="app-mode-sel" data-id="${esc(a.id)}" style="font-size:0.85rem">
        <option value="full" ${mode === 'full' ? 'selected' : ''}>Full</option>
        <option value="balanced" ${mode === 'balanced' ? 'selected' : ''}>Balanced</option>
        <option value="trusted-lan" ${mode === 'trusted-lan' ? 'selected' : ''}>Trusted LAN</option>
        <option value="reverse-proxy-only" ${mode === 'reverse-proxy-only' ? 'selected' : ''}>Reverse proxy only</option>
        <option value="custom" ${mode === 'custom' ? 'selected' : ''}>Custom</option>
      </select>
    </label>
  </div>
  <div class="app-badges">${appSecurityBadges(sec)}</div>
  ${rpoWarn}
  <div class="app-diagnostics hidden" id="${esc(diagnosticsID)}" data-app-diagnostics="${esc(a.id)}" aria-live="polite"></div>
</div>`;
    }).join('');
    box.querySelectorAll('.btn-app-diagnostics').forEach((btn) => {
      btn.onclick = async () => toggleApplicationDiagnostics(btn);
    });
    box.querySelectorAll('.btn-app-edit').forEach((btn) => {
      btn.onclick = () => fillAppFormFromApp(btn.getAttribute('data-id'));
    });
    box.querySelectorAll('.btn-app-maint').forEach((btn) => {
      btn.onclick = () => setAppMaintenance(btn.getAttribute('data-id'), !btn.getAttribute('data-on'), btn);
    });
    box.querySelectorAll('.btn-app-delete').forEach((btn) => {
      btn.onclick = () => deleteApplication(btn.getAttribute('data-id'), btn);
    });
    box.querySelectorAll('.app-mode-sel').forEach((sel) => {
      sel.addEventListener('change', () => postAppModeChange(sel.getAttribute('data-id'), sel.value, sel));
    });
  }

  function appDiagnosticsDOMID(id) {
    return 'app-diagnostics-' + String(id || '').replace(/[^A-Za-z0-9_-]/g, '_');
  }

  function applicationDiagnosticPresentation(status) {
    switch (status) {
    case 'ok': return {label: 'OK', tone: 'success'};
    case 'failed': return {label: 'Failed', tone: 'danger'};
    case 'not_applicable': return {label: 'Not applicable', tone: 'neutral'};
    default: return {label: 'Unknown', tone: 'unknown'};
    }
  }

  function renderApplicationDiagnostics(payload) {
    const overall = applicationDiagnosticPresentation(payload && payload.status);
    const overallLabel = payload && payload.status === 'ok' ? 'Checks passed' :
      payload && payload.status === 'failed' ? 'Issue found' : 'Incomplete';
    const steps = payload && Array.isArray(payload.steps) ? payload.steps : [];
    const rows = steps.map((step) => {
      const state = applicationDiagnosticPresentation(step && step.status);
      const evidence = step && Array.isArray(step.evidence) ? step.evidence : [];
      const evidenceHTML = evidence.length ? '<ul class="app-diagnostic-evidence">' +
        evidence.map((fact) => '<li>' + esc(fact) + '</li>').join('') + '</ul>' : '';
      return '<li class="app-diagnostic-step" data-diagnostic-state="' + esc(step && step.status || 'unknown') + '">' +
        '<div class="app-diagnostic-step-head"><strong>' + esc(step && step.label || 'Check') + '</strong>' +
        statusBadge(state.label, state.tone) + '</div><p>' + esc(step && step.summary || 'No result was reported.') + '</p>' +
        evidenceHTML + '</li>';
    }).join('');
    const checked = payload && payload.checked_at ? formatHostTime(payload.checked_at) : 'Unknown';
    return '<div class="app-diagnostics-summary"><div><strong>Availability diagnosis</strong><p>' +
      esc(payload && payload.summary || 'Some checks could not be verified.') + '</p></div>' +
      statusBadge(overallLabel, overall.tone) + '</div>' +
      '<p class="dash-note">Server facts checked at ' + esc(checked) + '. DNS resolution does not prove that an address points to this appliance.</p>' +
      (rows ? '<ol class="app-diagnostics-list">' + rows + '</ol>' : stateView('error', 'No diagnostic steps were returned.'));
  }

  async function loadApplicationDiagnostics(id, panel) {
    panel.innerHTML = stateView('loading', 'Checking DNS, certificate material, applied edge state, and HAProxy runtime…');
    let response;
    try {
      response = await fetch('/api/v1/applications/' + encodeURIComponent(id) + '/diagnostics', {headers: hdr()});
    } catch (_) {
      panel.innerHTML = stateView('offline', 'Diagnostics are unavailable because the API could not be reached.');
      return;
    }
    const text = await response.text();
    let payload = null;
    try { payload = JSON.parse(text); } catch (_) { /* invalid response handled below */ }
    if (!response.ok) {
      panel.innerHTML = stateView('error', payload && (payload.error || payload.message) || text || ('HTTP ' + response.status));
      return;
    }
    if (!payload || !Array.isArray(payload.steps)) {
      panel.innerHTML = stateView('error', 'The diagnostics API returned an invalid response.');
      return;
    }
    panel.innerHTML = renderApplicationDiagnostics(payload);
  }

  async function toggleApplicationDiagnostics(button) {
    const panel = document.getElementById(button.getAttribute('aria-controls'));
    if (!panel) return;
    const opening = button.getAttribute('aria-expanded') !== 'true';
    if (opening && button.getAttribute('aria-busy') === 'true') return;
    button.setAttribute('aria-expanded', opening ? 'true' : 'false');
    button.textContent = opening ? 'Hide diagnostics' : 'Diagnose';
    panel.classList.toggle('hidden', !opening);
    if (!opening) return;
    button.setAttribute('aria-busy', 'true');
    try {
      await loadApplicationDiagnostics(button.getAttribute('data-id'), panel);
    } finally {
      button.removeAttribute('aria-busy');
    }
  }

  document.getElementById('btn-totp-setup').onclick = async () => {
    const generation = ++totpGeneration;
    const r = await fetch('/api/v1/auth/totp/setup', { method: 'POST', headers: hdr() });
    if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
    const j = await r.json();
    if (generation !== totpGeneration) return;
    clearTOTPSecrets();
    document.getElementById('totp-secret').textContent = j.secret;
    document.getElementById('totp-uri').href = j.otpauth_uri;
    document.getElementById('totp-setup-box').classList.remove('hidden');
  };
  document.getElementById('btn-totp-enable').onclick = async () => {
    const generation = totpGeneration;
    const code = document.getElementById('totp-code').value.trim();
    const r = await fetch('/api/v1/auth/totp/enable', { method: 'POST', headers: hdr(), body: JSON.stringify({ code }) });
    if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
    const j = await r.json();
    if (generation !== totpGeneration) return;
    clearTOTPSecrets();
    renderTOTPStatus(true);
    const pre = document.getElementById('totp-recovery');
    pre.textContent = 'Recovery codes: each works once instead of a code. Store them now; they are not shown again.\n\n' + j.recovery_codes.join('\n');
    pre.classList.remove('hidden');
    document.getElementById('btn-totp-dismiss').classList.remove('hidden');
  };
  document.getElementById('btn-totp-dismiss').onclick = () => {
    clearTOTPSecrets();
    document.getElementById('btn-totp-disable').focus();
  };
  document.getElementById('btn-totp-disable').onclick = async () => {
    const generation = totpGeneration;
    if (!(await confirmDialog('Turn off two-factor sign-in?', { danger: true, okLabel: 'Turn off' })) || generation !== totpGeneration) return;
    const r = await fetch('/api/v1/auth/totp/disable', { method: 'POST', headers: hdr() });
    if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
    if (generation !== totpGeneration) return;
    clearTOTPSecrets();
    renderTOTPStatus(false);
  };

  document.getElementById('btn-pu-create').onclick = () => {
    const button = document.getElementById('btn-pu-create');
    return withFocusableBusy(button, async () => {
      const username = document.getElementById('pu-new-name').value.trim();
      const role = document.getElementById('pu-new-role').value;
      const r = await fetch('/api/v1/panel-users', { method: 'POST', headers: hdr(), body: JSON.stringify({ username, role }) });
      if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
      const j = await r.json();
      if (!j || typeof j.temporary_password !== 'string') { toast('The server returned an invalid temporary password response.', 'err'); return; }
      document.getElementById('pu-new-name').value = '';
      await oneTimeCredentialDialog(j.username, j.temporary_password, button);
      j.temporary_password = '';
      await loadPanelUsers();
      button.focus();
    });
  };

  document.getElementById('btn-apps-refresh').onclick = async () => {
    await Promise.all([loadApps(), loadProfileSelect(), loadCertOptionsForApps(), refreshEdgeStatus()]);
  };

  document.getElementById('apply').onclick = async () => {
    const btn = document.getElementById('apply');
    await withBusy(btn, async () => {
      const r = await fetch('/api/v1/apply', { method: 'POST', headers: hdr(), body: JSON.stringify({ label: 'ui' }) });
      if (r.ok) {
        toast('HAProxy config applied', 'ok');
        await refreshEdgeStatus();
        if (panelFromHash() === 'config') loadRevisions();
      } else {
        toast(await apiMessage(r), 'err');
      }
    });
  };

  function shortSha(full) {
    if (!full || full.length < 12) return full || '';
    return full.slice(0, 12);
  }

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  }

  async function loadRevisions(preserveMessage = false) {
    const msg = document.getElementById('revisions-msg');
    const box = document.getElementById('revisions-table');
    if (!msg || !box) return;
    if (!preserveMessage) msg.textContent = '';
    tableState(box, 'loading');
    const r = await fetch('/api/v1/revisions?limit=50', { headers: hdr() });
    if (r.status === 403) { refreshSession(); return; }
    if (!r.ok) {
      tableState(box, 'error', { message: await apiMessage(r) });
      return;
    }
    const rows = await r.json();
    if (!Array.isArray(rows) || rows.length === 0) {
      tableState(box, 'empty', { message: 'No revisions yet. Run Apply after adding an application.' });
      return;
    }
    const head = '<thead><tr><th>SHA</th><th>Created</th><th>Status</th><th>Preview</th><th></th></tr></thead>';
    const body = rows.map((row) => {
      const st = row.is_current ? 'current' : 'previous';
      const rb = row.is_current ? '' : `<button type="button" class="secondary btn-rollback" data-id="${row.id}" data-sha="${esc(row.sha)}">Rollback</button>`;
      const prev = esc((row.config_snippet_preview || '').slice(0, 120));
      const dt = esc(formatHostTime(row.created_at));
      const shaFull = row.sha || '';
      return `<tr><td><code>${esc(shortSha(shaFull))}</code> ${copyBtn(shaFull)}</td><td>${dt}</td><td>${st}</td><td style="font-size:11px;max-width:14rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(row.config_snippet_preview || '')}">${prev}</td><td>${rb}</td></tr>`;
    }).join('');
    box.innerHTML = `<table>${head}<tbody>${body}</tbody></table>`;
    box.querySelectorAll('.btn-rollback').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        const sha = btn.getAttribute('data-sha');
        const okRb = await confirmDialog('Restore edge revision ' + shortSha(sha) + '?\n\nSaved applications and settings are unchanged. A later Apply or restart can replace this configuration. Review saved settings after rollback.', { danger: true, okLabel: 'Rollback' });
        if (!okRb) return;
        msg.textContent = '';
        const rr = await fetch(`/api/v1/revisions/${encodeURIComponent(id)}/rollback`, { method: 'POST', headers: hdr() });
        if (rr.ok) {
          toast('Previous edge configuration restored.', 'ok');
          markPendingApply(null);
          await refreshEdgeStatus();
          msg.textContent = 'Previous edge configuration restored. Saved applications and settings are unchanged. Their relationship to the restored edge is unknown until Apply or startup reconciliation.';
          msg.className = 'warn';
        } else {
          { const __m = await apiMessage(rr); toast(__m, 'err'); msg.textContent = __m; }
          msg.className = 'warn';
        }
        await loadRevisions(true);
      };
    });
  }

  document.getElementById('btn-revisions-refresh').onclick = () => loadRevisions();

  let cachedSettings = null;
  let appsListCache = [];

  function parseCountryListText(s) {
    return String(s || '').split(',').map((x) => x.trim().toUpperCase()).filter(Boolean);
  }

  function syncGeoIPMaxMindRow() {
    const row = document.getElementById('geoip-maxmind-row');
    const sel = document.getElementById('geoip-provider');
    if (!row || !sel) return;
    const isMaxMind = sel.value !== 'maxmind' ? false : true;
    row.classList.toggle('hidden', !isMaxMind);
    const up = document.getElementById('geoip-upload-row');
    if (up) up.classList.toggle('hidden', !isMaxMind);
  }

  async function refreshGeoIPProvidersNote() {
    const el = document.getElementById('geoip-providers-note');
    if (!el) return;
    el.textContent = '';
    try {
      const r = await fetch('/api/v1/geoip/providers', { headers: hdr() });
      if (!r.ok) return;
      const arr = await r.json();
      const mm = Array.isArray(arr) ? arr.find((x) => x && x.name === 'maxmind') : null;
      if (mm && mm.available) {
        el.textContent = 'Providers: ipinfo (API) · maxmind — MMDB on disk OK (' + (mm.mmdb_path || '') + ').';
      } else if (mm) {
        el.textContent = 'Providers: ipinfo (API) · maxmind — set a readable geoip_mmdb_path (current: ' + (mm.mmdb_path || '(empty)') + ').';
      } else {
        el.textContent = 'Providers: (unavailable)';
      }
    } catch (_) { /* ignore */ }
  }

  function loadGeoIPFromSettings() {
    if (!cachedSettings) return;
    document.getElementById('geoip-enabled').checked = !!cachedSettings.geoip_enabled;
    const pr = (cachedSettings.geoip_provider || 'ipinfo').toLowerCase();
    document.getElementById('geoip-provider').value = pr === 'maxmind' ? 'maxmind' : 'ipinfo';
    const pol = (cachedSettings.geoip_default_policy || 'allow').toLowerCase();
    document.getElementById('geoip-policy').value = pol === 'deny' ? 'deny' : 'allow';
    const list = cachedSettings.geoip_country_list;
    document.getElementById('geoip-countries').value = Array.isArray(list) ? list.join(', ') : '';
    const mp = document.getElementById('geoip-mmdb-path');
    if (mp) mp.value = cachedSettings.geoip_mmdb_path || '';
    syncGeoIPMaxMindRow();
    void refreshGeoIPProvidersNote();
  }

  function renderACMEConfigurationStatus(settings) {
    const status = document.getElementById('acme-configuration-status');
    if (!status) return;
    if (!settings) {
      status.textContent = 'Saved ACME configuration has not loaded. Automatic renewal readiness is unknown.';
      status.className = 'warn';
      return;
    }
    const warnings = [];
    if (!(settings.acme_email || '').trim()) {
      warnings.push('ACME issuance and renewal are paused: set and save a contact email.');
    }
    if (settings.acme_staging) {
      warnings.push('Staging is enabled: new and renewed ACME certificates will not be trusted by browsers.');
    }
    status.textContent = 'Saved ACME configuration: ' + (warnings.length ? warnings.join(' ') :
      'Production ACME configured. Individual certificates can still select staging.');
    status.className = warnings.length ? 'warn' : 'dash-note';
  }

  let zabbixFirewallRead = 0;

  async function loadZabbixFirewallStatus() {
    const status = document.getElementById('zabbix-firewall-status');
    const read = ++zabbixFirewallRead;
    if (currentRole !== 'admin') {
      status.textContent = 'Administrator access is required to read the managed Zabbix rule.';
      return;
    }
    let rule;
    try {
      const response = await fetch('/api/v1/host/firewall', { headers: hdr(), cache: 'no-store' });
      if (response.ok) rule = (await response.json()).zabbix_agent_rule;
    } catch (_) { /* report unavailable */ }
    if (read !== zabbixFirewallRead || currentRole !== 'admin') return;
    status.textContent = rule === true ? 'Managed Zabbix rule: present.'
      : rule === false ? 'Managed Zabbix rule: absent.' : 'Managed Zabbix rule: unavailable.';
  }

  function loadSettingsTab() {
    return Promise.all([loadSettingsPanel(), loadZabbixFirewallStatus()]);
  }

  let settingsRead = 0;
  let settingsDraftSession = -1;
  const editedSettingsFields = new Set();

  function clearSettingsDrafts() {
    editedSettingsFields.clear();
    cachedSettings = null;
    document.getElementById('cs-lapi-key').value = '';
    document.getElementById('notify-telegram-token').value = '';
  }

  function syncSettingsDraftSession() {
    if (settingsDraftSession !== sessionGeneration) {
      editedSettingsFields.clear();
      settingsDraftSession = sessionGeneration;
    }
  }

  document.addEventListener('input', ({target}) => {
    if (!target.matches(':is(#tab-certs, #tab-settings, #tab-security, #tab-crowdsec) :is(input:not([type=file]), select, textarea)')) return;
    syncSettingsDraftSession();
    editedSettingsFields.add(target);
  });

  async function loadSettingsPanel() {
    syncSettingsDraftSession();
    const read = ++settingsRead;
    const session = sessionGeneration;
    const current = () => read === settingsRead && session === sessionGeneration;
    const sm = document.getElementById('settings-msg');
    const cm = document.getElementById('certs-settings-msg');
    const csm = document.getElementById('cs-settings-msg');
    const security = document.getElementById('security-settings-status');
    security.textContent = 'Loading saved settings…';
    if (sm) {
      sm.textContent = '';
      sm.className = 'warn';
    }
    if (cm) {
      cm.textContent = '';
      cm.className = 'warn';
    }
    if (csm) {
      csm.textContent = '';
      csm.className = 'warn';
    }
    renderACMEConfigurationStatus(null);
    cachedSettings = null;
    try {
      const r = await fetch('/api/v1/settings', { headers: hdr() });
      if (!r.ok) throw new Error('Settings request failed');
      const saved = await r.json();
      if (!current()) return;
      if (typeof saved?.acme_staging !== 'boolean' ||
          (saved.acme_email !== undefined && typeof saved.acme_email !== 'string')) throw new Error('Invalid settings');
      cachedSettings = saved;
    } catch (_) {
      if (!current()) return;
      [sm, cm, csm, security].forEach((message) => {
        if (message) message.textContent = 'Could not load settings. Use the load button on this page to retry.';
      });
      return;
    }
    const drafts = Array.from(editedSettingsFields, field => {
      const property = field.type === 'checkbox' ? 'checked' : 'value';
      return {field, property, value: field[property]};
    });
    renderACMEConfigurationStatus(cachedSettings);
    document.getElementById('acme-email').value = cachedSettings.acme_email || '';
    document.getElementById('acme-staging').checked = !!cachedSettings.acme_staging;
    document.getElementById('waf-basic-enabled').checked = cachedSettings.waf_basic_rules_enabled !== false;
    loadIpwlToggleFromSettings();
    loadBotProtectionFromSettings();
    loadEdgeNetworkFromSettings();
    loadGeoIPFromSettings();
    loadIpblFetchCIDRsFromSettings();
    document.getElementById('cs-lapi-url').value = cachedSettings.crowdsec_lapi_url || '';
    document.getElementById('cs-lapi-key').value = '';
    document.getElementById('cs-lapi-key').placeholder = cachedSettings.crowdsec_lapi_key_set
      ? '•••• key stored — enter new key to replace'
      : 'Machine bouncer key (cscli bouncers add -o raw)';
    document.getElementById('cs-spoe-path').value = cachedSettings.spoe_config_path || '';
    document.getElementById('cs-engine-name').value = cachedSettings.crowdsec_engine_name || 'crowdsec';
    const promEl = document.getElementById('prometheus-enabled');
    if (promEl) promEl.checked = !!cachedSettings.prometheus_enabled;
    const zabbixEl = document.getElementById('firewall-zabbix-agent');
    if (zabbixEl) zabbixEl.checked = !!cachedSettings.firewall_zabbix_agent;
    const notifyEl = document.getElementById('notify-webhook-url');
    if (notifyEl) notifyEl.value = cachedSettings.notify_webhook_url || '';
    const tgChatEl = document.getElementById('notify-telegram-chat');
    if (tgChatEl) tgChatEl.value = cachedSettings.notify_telegram_chat_id || '';
    const tgTokEl = document.getElementById('notify-telegram-token');
    if (tgTokEl) {
      tgTokEl.value = '';
      tgTokEl.placeholder = cachedSettings.notify_telegram_bot_token_set
        ? '•••• token stored — enter a new one to replace'
        : '123456:ABC... from @BotFather';
    }
    const spikeEl = document.getElementById('notify-spike-threshold');
    if (spikeEl) spikeEl.value = String(cachedSettings.notify_blocked_spike_threshold || 0);
    editedSettingsFields.clear();
    for (const {field, property, value} of drafts) {
      if (field[property] === value) continue;
      field[property] = value;
      editedSettingsFields.add(field);
      if (field.id === 'geoip-provider') syncGeoIPMaxMindRow();
    }
    security.textContent = '';
    if (sm) {
      sm.textContent = 'Loaded from server.';
      sm.className = 'ok';
    }
  }

  function loadIpwlToggleFromSettings() {
    if (!cachedSettings) return;
    document.getElementById('ipwl-enabled').checked = !!cachedSettings.ipwl_enabled;
  }

  function loadEdgeNetworkFromSettings() {
    if (!cachedSettings) return;
    document.getElementById('edge-listen-ipv6').checked = !!cachedSettings.listen_ipv6;
    document.getElementById('edge-http3').checked = !!cachedSettings.http3;
    document.getElementById('edge-security-headers').checked = cachedSettings.security_headers_enabled !== false;
    document.getElementById('edge-hsts-subdomains').checked = !!cachedSettings.hsts_include_subdomains;
    document.getElementById('edge-trusted-proxies').value = (cachedSettings.trusted_proxy_cidrs || []).join('\n');
    document.getElementById('edge-tcp-services').value = (cachedSettings.tcp_services || []).map((t) =>
      [t.name, t.listen_port, t.backend_host + ':' + t.backend_port].concat((t.allow_cidrs || []).length ? ['allow=' + t.allow_cidrs.join(',')] : [], t.enabled ? [] : ['off']).join(' ')).join('\n');
    document.getElementById('edge-tls-passthrough').value = (cachedSettings.tls_passthrough || []).map((p) =>
      [p.server_name, p.backend_host + ':' + p.backend_port].concat((p.allow_cidrs || []).length ? ['allow=' + p.allow_cidrs.join(',')] : [],
        p.send_proxy ? ['proxy'] : [], p.enabled ? [] : ['off']).join(' ')).join('\n');
    document.getElementById('edge-real-ip-header').value = cachedSettings.real_ip_header || '';
    document.getElementById('edge-proxy-protocol').value = (cachedSettings.proxy_protocol_cidrs || []).join('\n');
  }

  function edgeLines(id) {
    return document.getElementById(id).value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  }

  function edgeRows(id) {
    return document.getElementById(id).value.split('\n').map((x) => x.trim()).filter(Boolean);
  }

  // https://www.cloudflare.com/ips/ — re-check when Cloudflare announces changes.
  const CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
    '2a06:98c0::/29', '2c0f:f248::/32',
  ];

  function edgeNetworkPatch() {
    return {
      listen_ipv6: document.getElementById('edge-listen-ipv6').checked,
      http3: document.getElementById('edge-http3').checked,
      security_headers_enabled: document.getElementById('edge-security-headers').checked,
      hsts_include_subdomains: document.getElementById('edge-hsts-subdomains').checked,
      trusted_proxy_cidrs: edgeLines('edge-trusted-proxies'),
      tcp_services: edgeRows('edge-tcp-services').map((line) => {
        const f = line.split(/\s+/);
        const hp = /^(\S+):(\d{1,5})$/.exec(f[2] || '');
        if (f.length < 3 || !hp) throw new Error('TCP service "' + line + '": use name listen_port host:port [allow=...] [off]');
        const allow = f.find((x) => x.startsWith('allow='));
        return { name: f[0], listen_port: parseInt(f[1], 10), backend_host: hp[1], backend_port: parseInt(hp[2], 10),
          allow_cidrs: allow ? allow.slice(6).split(',').filter(Boolean) : [], enabled: !f.includes('off') };
      }),
      tls_passthrough: edgeRows('edge-tls-passthrough').map((line) => {
        const f = line.split(/\s+/);
        const hp = /^(\S+):(\d{1,5})$/.exec(f[1] || '');
        if (f.length < 2 || !hp) throw new Error('TLS passthrough "' + line + '": use server_name host:port [allow=...] [proxy] [off]');
        const allow = f.find((x) => x.startsWith('allow='));
        return { server_name: f[0], backend_host: hp[1], backend_port: parseInt(hp[2], 10), send_proxy: f.includes('proxy'),
          allow_cidrs: allow ? allow.slice(6).split(',').filter(Boolean) : [], enabled: !f.includes('off') };
      }),
      real_ip_header: document.getElementById('edge-real-ip-header').value,
      proxy_protocol_cidrs: edgeLines('edge-proxy-protocol'),
    };
  }

  function loadBotProtectionFromSettings() {
    if (!cachedSettings) return;
    document.getElementById('ua-block-empty').checked = cachedSettings.block_empty_ua !== false;
    document.getElementById('ua-blocklist-enabled').checked = !!cachedSettings.blocked_user_agents_enabled;
  }

  function loadIpblFetchCIDRsFromSettings() {
    const ta = document.getElementById('ipbl-fetch-allowed-cidrs');
    if (!ta || !cachedSettings) return;
    const list = cachedSettings.ipbl_fetch_allowed_cidrs;
    ta.value = Array.isArray(list) ? list.join('\n') : '';
  }

  function parseIpblFetchCIDRsTextarea() {
    const ta = document.getElementById('ipbl-fetch-allowed-cidrs');
    if (!ta) return [];
    return ta.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  }

  function certStatusPillHTML(status, title) {
    const cls = status === 'valid' ? 'status-valid'
      : status === 'expiring' ? 'status-expiring'
        : (status === 'expired' || status === 'failed') ? 'status-expired' : 'status-pending';
    const t = title ? ' title="' + esc(title) + '"' : '';
    return '<span class="status-pill ' + cls + '"' + t + '>' + esc(status) + '</span>';
  }

  function certFailedTitle(c) {
    if (c.status !== 'failed') return '';
    let t = c.last_error || 'ACME issuance failed';
    if (c.next_attempt_at) t += ' — automatic retry at ' + formatHostTime(c.next_attempt_at);
    return t;
  }

  let certInventoryGeneration = 0;
  async function loadCertDashboard() {
    const generation = ++certInventoryGeneration;
    const msg = document.getElementById('cert-dash-msg');
    const tbody = document.getElementById('cert-table-body');
    if (!msg || !tbody) return;
    msg.textContent = '';
    const counters = {total: 'total', valid: 'valid', expiring: 'expiring_soon', expired: 'expired'};
    for (const id of Object.keys(counters)) document.getElementById('cert-sum-' + id).textContent = '—';
    tbody.innerHTML = '<tr><td colspan="6" class="dash-note">Loading…</td></tr>';
    let j;
    try {
      const r = await fetch('/api/v1/certificates/summary', { headers: hdr(), cache: 'no-store' });
      if (generation !== certInventoryGeneration) return;
      if (r.status === 401) {
        setTok('');
        refreshSession();
        return;
      }
      if (!r.ok) throw new Error(await apiMessage(r));
      j = await r.json();
      if (!Array.isArray(j?.certificates) || j.total !== j.certificates.length ||
          !Object.values(counters).every(key => Number.isSafeInteger(j[key]) && j[key] >= 0) ||
          !j.certificates.every(row => typeof row?.id === 'string' && row.id.length > 0)) {
        throw new Error('Invalid certificate summary.');
      }
    } catch (err) {
      if (generation !== certInventoryGeneration) return;
      tbody.innerHTML = '';
      msg.className = 'warn';
      msg.textContent = 'Certificate inventory unavailable. Use Refresh list to retry.' +
        (err instanceof SyntaxError ? '' : ' ' + err.message);
      return;
    }
    if (generation !== certInventoryGeneration) return;
    for (const [id, key] of Object.entries(counters)) {
      document.getElementById('cert-sum-' + id).textContent = String(j[key]);
    }
    const rows = j.certificates;
    tbody.innerHTML = '';
    if (rows.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="6"><span class="dash-note">No certificates yet.</span></td>';
      tbody.appendChild(tr);
      return;
    }
    rows.forEach((c) => {
      const actions = [];
      if (c.status === 'pending') {
        actions.push('<button type="button" data-cert-action="issue">Request issue</button>');
      }
      if (c.status === 'failed') {
        actions.push('<button type="button" data-cert-action="issue">Retry now</button>');
      }
      if (c.status === 'expiring' || c.status === 'expired') {
        actions.push('<button type="button" data-cert-action="renew">Renew now</button>');
      }
      actions.push('<button type="button" class="secondary" data-cert-action="delete">Delete</button>');
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td><code>' + esc(c.primary_domain || '') + '</code></td>' +
        '<td><code>' + esc(c.mode || '') + '</code></td>' +
        '<td>' + certStatusPillHTML(c.status || '', certFailedTitle(c)) + '</td>' +
        '<td><code>' + esc(formatHostTime(c.not_after)) + '</code></td>' +
        '<td>' + (c.days_remaining == null ? '—' : esc(String(c.days_remaining))) + '</td>' +
        '<td class="row" style="gap:0.35rem;flex-wrap:wrap">' + actions.join(' ') + '</td>';
      tbody.appendChild(tr);
      tr.querySelectorAll('[data-cert-action]').forEach(button => {
        button.onclick = () => runCertificateAction(button, c);
      });
    });
  }

  async function runCertificateAction(button, certificate) {
    if (button.disabled) return;
    const action = button.dataset.certAction;
    const removing = action === 'delete';
    const name = certificate.primary_domain || certificate.id;
    await withBusy(button, async () => {
      if (removing && !await confirmDialog('Delete the certificate for ' + name + '?', {danger: true, okLabel: 'Delete certificate'})) return;
      const path = '/api/v1/certificates/' + encodeURIComponent(certificate.id);
      let response;
      try {
        response = await fetch(removing ? path : path + '/request-issue', removing ?
          {method: 'DELETE', headers: hdr()} : {method: 'POST', headers: hdr(), body: '{}'});
      } catch (_) { /* The server may already have processed the request. */ }
      if (!response || response.status >= 500) {
        toast('Could not confirm the result for ' + name + '. Checking the certificate inventory again.', 'warn');
      } else if (!response.ok) {
        const message = await apiMessage(response);
        const status = document.getElementById('cert-dash-msg');
        status.className = 'warn';
        status.textContent = message;
        toast(message, 'err');
        return;
      } else {
        const outcome = removing ? 'Certificate deleted' : action === 'renew' ? 'Renewal queued' : 'Issuance queued';
        toast(outcome + ' for ' + name + '.', 'ok');
      }
      await loadCertDashboard();
    });
  }

  function decisionsCount(sample) {
    if (Array.isArray(sample)) return sample.length;
    if (Array.isArray(sample?.data)) return sample.data.length;
    if (sample === null || sample?.data === null) return 0;
    return null;
  }

  let dashStatsTimer = null;
  let dashboardController = null;

  function stopDashStatsTimer() {
    if (dashStatsTimer) {
      clearInterval(dashStatsTimer);
      dashStatsTimer = null;
    }
    dashboardController?.abort();
    dashboardController = null;
  }

  async function runDashboardLoad(load) {
    const controller = new AbortController();
    dashboardController = controller;
    try {
      await load(controller.signal);
    } finally {
      if (dashboardController === controller) dashboardController = null;
    }
  }

  function dashboardIsCurrent(signal) {
    return !signal.aborted && !sessionExpired && panelFromHash() === 'dashboard';
  }

  const AUDIT_PAGE = 50;
  let auditTimer = null;
  let auditShown = 0;
  let auditBeforeId = 0; // keyset cursor: next page holds rows with id < this
  // Bumped on every reset (filter change, auto-refresh): a "Load more" still
  // in flight from before it must not append its rows or move the cursor.
  let auditGen = 0;

  function stopAuditRefreshTimer() {
    if (auditTimer) {
      clearInterval(auditTimer);
      auditTimer = null;
    }
  }

  function syncAuditAutoRefresh() {
    stopAuditRefreshTimer();
    const cb = document.getElementById('audit-auto-refresh');
    if (cb && cb.checked && panelFromHash() === 'logs' && !document.getElementById('view-app').classList.contains('hidden')) {
      auditTimer = setInterval(() => { loadAuditPage(true); }, 15000);
    }
  }

  function formatAuditDetails(d) {
    if (d == null || d === '') return '—';
    const raw = typeof d === 'string' ? d : JSON.stringify(d);
    if (raw === 'null' || raw === '{}') return '—';
    if (typeof d === 'string') {
      try {
        return JSON.stringify(JSON.parse(d));
      } catch (_) {
        return d;
      }
    }
    return JSON.stringify(d);
  }

  const BLOCKED_RULES = {
    sensitive_path: '.git / .env', method: 'blocked method', path_allowlist: 'path not allowed',
    path_header: 'missing header / token', ip_blacklist: 'IP blacklist', geoip: 'GeoIP',
    empty_ua: 'empty User-Agent', bad_ua: 'blocked User-Agent', sqli: 'SQL injection', xss: 'XSS',
    traversal: 'path traversal', blocked_path: 'profile path block', restricted_path: 'restricted path',
    multipart: 'multipart', body_size: 'body too large', content_length: 'no Content-Length',
    crowdsec: 'CrowdSec', rate_limit: 'rate limit', unknown_host: 'unknown host',
    bad_request: 'malformed request', other: 'other',
  };
  let blockedGen = 0;
  let policyMatchesGen = 0;
  let hostJournalGen = 0;
  let hostJournalLoaded = false;

  function clearHostJournalSnapshot(message) {
    hostJournalGen++;
    hostJournalLoaded = false;
    const button = document.getElementById('btn-host-journal-load');
    const output = document.getElementById('host-journal-output');
    const status = document.getElementById('host-journal-status');
    if (button) button.removeAttribute('aria-busy');
    if (output) {
      output.removeAttribute('aria-busy');
      output.textContent = 'Not loaded.';
    }
    if (status) status.textContent = message || 'Choose filters and load a journal snapshot.';
  }

  function hostJournalRequest() {
    const unit = document.getElementById('host-journal-unit').value;
    const since = document.getElementById('host-journal-since').value;
    const priority = document.getElementById('host-journal-priority').value;
    const lines = document.getElementById('host-journal-lines').value;
    const params = new URLSearchParams({unit, since, lines});
    if (priority) params.set('priority', priority);
    return {unit, since, priority, lines, query: params.toString()};
  }

  function markHostJournalFiltersChanged() {
    hostJournalGen++;
    const button = document.getElementById('btn-host-journal-load');
    const output = document.getElementById('host-journal-output');
    const status = document.getElementById('host-journal-status');
    if (button) button.removeAttribute('aria-busy');
    if (output) output.removeAttribute('aria-busy');
    if (status && hostJournalLoaded) status.textContent = 'Filters changed. Load a new snapshot to refresh the output.';
  }

  function hostJournalLineCount(log) {
    if (!log) return 0;
    return String(log).replace(/\r\n/g, '\n').split('\n').filter((line) => line.length > 0).length;
  }

  async function loadHostJournal() {
    const button = document.getElementById('btn-host-journal-load');
    const output = document.getElementById('host-journal-output');
    const status = document.getElementById('host-journal-status');
    if (!button || !output || !status || button.getAttribute('aria-busy') === 'true' || panelFromHash() !== 'logs') return;
    const request = hostJournalRequest();
    const gen = ++hostJournalGen;
    button.setAttribute('aria-busy', 'true');
    output.setAttribute('aria-busy', 'true');
    status.textContent = 'Loading ' + request.unit + '…';
    let response, text;
    try {
      response = await fetch('/api/v1/host/journal?' + request.query, {headers: hdr()});
      text = await response.text();
    } catch (_) {
      if (gen !== hostJournalGen) return;
      output.textContent = 'Journal unavailable.';
      status.textContent = 'The journal could not be loaded because the API is unavailable.';
      button.removeAttribute('aria-busy');
      output.removeAttribute('aria-busy');
      return;
    }
    if (gen !== hostJournalGen) return;
    button.removeAttribute('aria-busy');
    output.removeAttribute('aria-busy');
    let payload = null;
    try { payload = JSON.parse(text); } catch (_) { /* invalid response handled below */ }
    if (!response.ok) {
      output.textContent = 'Journal unavailable.';
      status.textContent = payload && (payload.error || payload.message) || text || ('HTTP ' + response.status);
      return;
    }
    if (!payload || typeof payload.log !== 'string') {
      output.textContent = 'Journal unavailable.';
      status.textContent = 'The journal API returned an invalid response.';
      return;
    }
    hostJournalLoaded = true;
    const count = hostJournalLineCount(payload.log);
    if (count === 0) {
      output.textContent = 'No journal entries matched these filters.';
      status.textContent = 'Loaded ' + request.unit + ': no matching entries.';
      return;
    }
    output.textContent = payload.log;
    status.textContent = 'Loaded ' + count + ' line' + (count === 1 ? '' : 's') + ' from ' + request.unit + '. This is a read-only snapshot.';
  }

  function blockedRuleLabel(r) {
    if (r === 'policy_block') return 'Publication rule';
    return BLOCKED_RULES[r] || r;
  }

  async function blockIPFromLog(ip, button) {
    await withFocusableBusy(button, async () => {
      if (!(await confirmProtectiveRuleChange('blacklist-add', ip))) return;
      const r = await fetch('/api/v1/ipbl/local', {
        method: 'POST', headers: hdr(),
        body: JSON.stringify({ cidr: ip, note: 'from Blocked requests', enabled: true }),
      });
      if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
      markPendingApply(true);
      toast(ip + ' blacklisted. Apply HAProxy to enforce it.', 'ok');
    });
  }

  async function loadBlocked() {
    const errEl = document.getElementById('blocked-err');
    const tbody = document.getElementById('blocked-tbody');
    if (!tbody || panelFromHash() !== 'logs') return;
    const gen = ++blockedGen;
    const total = document.getElementById('blocked-total');
    const ruleRows = document.getElementById('blocked-rules');
    const ipRows = document.getElementById('blocked-ips');
    const hostRows = document.getElementById('blocked-hosts');
    errEl.textContent = '';
    total.textContent = '';
    ruleRows.replaceChildren();
    ipRows.replaceChildren();
    hostRows.replaceChildren();
    tbody.innerHTML = '<tr><td colspan="6" class="dash-note">Loading…</td></tr>';
    const period = document.getElementById('blocked-period').value;
    let data;
    try {
      const r = await fetch('/api/v1/security/blocked?period=' + encodeURIComponent(period), { headers: hdr() });
      if (gen !== blockedGen) return;
      if (r.status === 401) { setTok(''); refreshSession(); return; }
      if (!r.ok) {
        const message = await apiMessage(r);
        if (gen !== blockedGen) return;
        tbody.replaceChildren();
        errEl.textContent = message;
        return;
      }
      data = await r.json();
    } catch (e) {
      if (gen !== blockedGen) return;
      tbody.innerHTML = '';
      errEl.textContent = 'Request failed: ' + (e && e.message ? e.message : String(e));
      return;
    }
    if (gen !== blockedGen) return;
    const sum = data.summary || {};
    const events = Array.isArray(data.events) ? data.events : [];
    total.textContent = (sum.total || 0) + ' blocked' +
      (data.truncated ? ' (newest journal entries only)' : '') +
      (events.length < sum.total ? '. Showing the latest ' + events.length + '.' : '');
    const rows = (list, fmt) => (list || []).map(fmt).join('') || '<tr><td class="dash-note">—</td></tr>';
    ruleRows.innerHTML = rows(sum.by_rule, (c) =>
      '<tr><td>' + esc(blockedRuleLabel(c.key)) + '</td><td>' + c.count + '</td></tr>');
    ipRows.innerHTML = rows(sum.top_ips, (c) =>
      '<tr><td><code>' + esc(c.key) + '</code></td><td>' + esc(c.country || '') + '</td><td>' + c.count +
      '</td><td><button type="button" class="secondary" data-block-ip="' + esc(c.key) + '">Blacklist</button></td></tr>');
    hostRows.innerHTML = rows(sum.top_hosts, (c) =>
      '<tr><td>' + esc(c.key) + '</td><td>' + c.count + '</td></tr>');
    const empty = data.truncated ? 'No blocked requests in the available journal sample.' : 'Nothing blocked in this period.';
    tbody.innerHTML = events.map((ev) =>
      '<tr><td>' + esc(formatHostTime(ev.time)) + '</td><td><code>' + esc(ev.client_ip) + '</code></td><td>' +
      esc(ev.host || '—') + '</td><td><code>' + esc((ev.method || '') + ' ' + (ev.path || '')) + '</code></td><td>' +
      ev.status + '</td><td>' + esc(blockedRuleLabel(ev.rule)) + '</td></tr>').join('') ||
      '<tr><td colspan="6" class="dash-note">' + empty + '</td></tr>';
  }

  function policyMatchesHost() {
    return new URLSearchParams(location.hash.split('?')[1] || '').get('host') || '';
  }

  async function loadPolicyMatches() {
    if (panelFromHash() !== 'logs') return;
    const tbody = document.getElementById('policy-matches-tbody');
    const status = document.getElementById('policy-matches-status');
    const period = document.getElementById('policy-matches-period').value;
    const gen = ++policyMatchesGen;
    status.textContent = 'Loading…';
    tbody.replaceChildren();
    try {
      const query = new URLSearchParams({period});
      const host = policyMatchesHost();
      if (host) query.set('host', host);
      const response = await fetch('/api/v1/security/policy-matches?' + query, { headers: hdr() });
      if (gen !== policyMatchesGen) return;
      if (response.status === 401) { setTok(''); refreshSession(); return; }
      if (!response.ok) throw new Error(await apiMessage(response));
      const data = await response.json();
      if (gen !== policyMatchesGen) return;
      tbody.innerHTML = data.events.map((event) => {
        const matches = event.matches.map((match) => esc(match.id) + ' (' + esc(match.action) + ')').join(', ');
        return '<tr><td>' + esc(formatHostTime(event.time)) + '</td><td>' + esc(event.host) +
          '</td><td>' + matches + '</td><td>' + esc(String(event.status)) + '</td></tr>';
      }).join('');
      if (data.events.length === 0) {
        status.textContent = data.truncated ? 'No matches in the available journal sample.' : 'No matches in this period.';
      } else {
        status.textContent = 'Showing ' + data.events.length +
          (data.truncated ? ' most recent requests with matches.' : ' requests with matches.');
      }
    } catch (error) {
      if (gen === policyMatchesGen) status.textContent = error.message || 'Could not load publication rule matches.';
    }
  }

  async function loadAuditPage(reset) {
    const errEl = document.getElementById('audit-err');
    const tbody = document.getElementById('audit-tbody');
    const moreBtn = document.getElementById('btn-audit-more');
    const shownEl = document.getElementById('audit-shown');
    if (!tbody || !errEl) return;
    if (document.getElementById('view-app').classList.contains('hidden')) return;
    if (panelFromHash() !== 'logs') return;

    const sel = document.getElementById('audit-filter-action');
    const actionVal = sel && sel.value !== 'all' ? sel.value : '';

    if (reset) auditGen++;
    const gen = auditGen;
    if (reset) {
      auditShown = 0;
      auditBeforeId = 0;
      tbody.innerHTML = '<tr><td colspan="5" class="dash-note">Loading…</td></tr>';
    }

    errEl.textContent = '';
    // One page at a time: a double click would fetch the same cursor twice.
    if (moreBtn) moreBtn.disabled = true;
    const params = new URLSearchParams({ limit: String(AUDIT_PAGE) });
    if (!reset && auditBeforeId > 0) params.set('before_id', String(auditBeforeId));
    if (actionVal) params.set('action', actionVal);

    let r;
    try {
      r = await fetch('/api/v1/audit?' + params.toString(), { headers: hdr() });
    } catch (e) {
      // Network failure: report it and leave Load more usable for a retry.
      if (gen !== auditGen) return;
      if (reset) tbody.innerHTML = '';
      else if (moreBtn) moreBtn.disabled = auditBeforeId === 0;
      errEl.textContent = 'Request failed: ' + (e && e.message ? e.message : String(e));
      return;
    }
    if (gen !== auditGen) return; // superseded by a reset
    if (r.status === 401) {
      setTok('');
      refreshSession();
      return;
    }
    if (!r.ok) {
      const msg = await apiMessage(r);
      if (gen !== auditGen) return;
      if (reset) tbody.innerHTML = '';
      else if (moreBtn) moreBtn.disabled = auditBeforeId === 0; // allow a retry
      errEl.textContent = msg;
      return;
    }
    const data = await r.json().catch(() => null);
    if (gen !== auditGen) return;
    if (!data || typeof data !== 'object') {
      // Unreadable reply: keep the list and cursor, allow a retry.
      if (reset) tbody.innerHTML = '';
      else if (moreBtn) moreBtn.disabled = auditBeforeId === 0;
      errEl.textContent = 'Unexpected response from the server';
      return;
    }
    const entries = Array.isArray(data.entries) ? data.entries : [];
    const hasMore = data.has_more === true;

    if (reset && entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="dash-note">No audit entries yet.</td></tr>';
      auditShown = 0;
      if (shownEl) shownEl.textContent = 'Showing 0';
      if (moreBtn) moreBtn.disabled = true;
      return;
    }
    if (reset) tbody.innerHTML = '';

    for (const e of entries) {
      const tr = document.createElement('tr');
      const c0 = document.createElement('td');
      const c1 = document.createElement('td');
      const c2 = document.createElement('td');
      const c3 = document.createElement('td');
      const c4 = document.createElement('td');
      c0.innerHTML = '<code>' + esc(formatHostTime(e.timestamp)) + '</code>';
      c1.textContent = e.user_name || '';
      c2.innerHTML = '<code>' + esc(e.action || '') + '</code>';
      c3.textContent = e.source_ip || '';
      c4.style.maxWidth = '28rem';
      c4.style.wordBreak = 'break-word';
      c4.style.fontSize = '0.8rem';
      const pre = document.createElement('code');
      pre.textContent = formatAuditDetails(e.details);
      c4.appendChild(pre);
      tr.appendChild(c0);
      tr.appendChild(c1);
      tr.appendChild(c2);
      tr.appendChild(c3);
      tr.appendChild(c4);
      tbody.appendChild(tr);
    }

    auditShown += entries.length;
    auditBeforeId = hasMore && typeof data.next_before_id === 'number' ? data.next_before_id : 0;
    if (shownEl) shownEl.textContent = 'Showing ' + auditShown + (hasMore ? ' (more available)' : '');
    if (moreBtn) moreBtn.disabled = !hasMore;
  }

  async function dashboardRequest(path, signal, includeError = false) {
    if (signal.aborted) return { failure: 'canceled' };
    const controller = new AbortController();
    const cancel = () => controller.abort();
    signal.addEventListener('abort', cancel, { once: true });
    const timeout = setTimeout(cancel, 10000);
    let result = { failure: 'offline' };
    try {
      const response = await fetch(path, { headers: hdr(), signal: controller.signal });
      if (response.ok) {
        result = { failure: 'invalid response' };
        result = { data: await response.json() };
      } else {
        result = { failure: 'HTTP ' + response.status };
        if (includeError) result.failure = await apiMessage(response);
      }
    } catch (_) {
      // The last completed stage determines the failure when no abort occurred.
    } finally {
      clearTimeout(timeout);
      signal.removeEventListener('abort', cancel);
    }
    if (signal.aborted) return { failure: 'canceled' };
    if (controller.signal.aborted) return { failure: 'timed out' };
    return result;
  }

  function resetDashboardView() {
    document.getElementById('dash-apps-stat').textContent = 'Unknown';
    document.getElementById('dash-certs-stat').textContent = 'Unknown';
    document.getElementById('dash-certs-sub').textContent = 'API summary';
    document.getElementById('dash-cs-stat').textContent = 'Unknown';
    document.getElementById('dash-cs-sub').textContent = 'LAPI reachability probe';
    document.getElementById('dash-ipbl-stat').textContent = 'Unknown';
    document.getElementById('dash-req-rate').textContent = 'Unknown';
    document.getElementById('dash-active-sessions').textContent = 'Unknown';
    document.getElementById('dash-sec-line').textContent = 'Unknown';
    document.getElementById('dash-http-line').textContent = 'Unknown';
    document.getElementById('dash-edge-state').textContent = 'Unknown';
    document.getElementById('dash-edge-generation').textContent = 'Saved and applied generations are unknown.';
    document.getElementById('dash-edge-runtime').textContent = 'Managed runtime artifact is unknown.';
    document.getElementById('dash-revision-line').textContent = 'Unknown';
    document.getElementById('dash-last-apply').textContent = 'Unknown';
    document.getElementById('dash-backends').innerHTML = stateView('loading', 'Loading saved applications…');
    document.getElementById('dash-services').innerHTML = stateView('loading', 'Loading systemd state…');
    document.getElementById('dash-haproxy-table').innerHTML = stateView('loading', 'Loading HAProxy runtime…');
    document.getElementById('dash-haproxy-err').textContent = '';
    document.getElementById('dash-attention-list').innerHTML = stateView('loading', 'Checking current data…');
    document.getElementById('dash-status').dataset.state = 'loading';
    document.getElementById('dash-status').textContent = 'Loading dashboard…';
    for (const id of ['dash-cert-warn', 'dash-sec-warn', 'dash-http-warn']) {
      const el = document.getElementById(id);
      if (el) {
        el.classList.add('hidden');
        el.textContent = '';
      }
    }
  }

  function renderDashboardEdgeStatus(edge, attention) {
    const stateEl = document.getElementById('dash-edge-state');
    const generationEl = document.getElementById('dash-edge-generation');
    const runtimeEl = document.getElementById('dash-edge-runtime');
    const lastEl = document.getElementById('dash-last-apply');
    if (!renderPersistentEdgeStatus(edge)) {
      stateEl.innerHTML = statusBadge('Unknown', 'unknown');
      generationEl.textContent = 'Saved/applied state is unavailable.';
      runtimeEl.textContent = 'Managed runtime artifact is unknown.';
      lastEl.textContent = 'Last edge operation is unknown.';
      return;
    }

    const applied = Number.isSafeInteger(edge.applied_generation) ? edge.applied_generation : null;
    if (edge.pending === true) {
      stateEl.innerHTML = statusBadge('Saved changes pending', 'warning');
      generationEl.textContent = 'Saved generation ' + edge.saved_generation +
        (applied == null ? ' · applied generation unknown' : ' · applied generation ' + applied) + '.';
      attention.push(alertView('warning', 'Saved edge changes are pending',
        'Saved generation ' + edge.saved_generation +
        (applied == null ? ' has no exact applied acknowledgement.' : ' is newer than applied generation ' + applied + '.') +
        ' Use Edge changes → Apply HAProxy.'));
    } else if (edge.pending === false) {
      stateEl.innerHTML = statusBadge('Saved and applied match', 'success');
      generationEl.textContent = 'Saved and applied generation ' + edge.saved_generation + '. This is an exact apply acknowledgement, not a health check.';
    } else {
      stateEl.innerHTML = statusBadge('Apply relationship unknown', 'unknown');
      generationEl.textContent = 'Saved generation ' + edge.saved_generation + ' · applied generation unknown.';
      attention.push(alertView('unknown', 'Applied generation is unknown',
        'Apply HAProxy or wait for startup reconciliation before treating saved state as live.'));
    }

    const runtime = edge.runtime && typeof edge.runtime === 'object' ? edge.runtime : null;
    if (runtime && runtime.state === 'known' && runtime.revision_sha) {
      runtimeEl.textContent = 'Managed haproxy.cfg observed · SHA ' + shortSha(runtime.revision_sha) +
        (runtime.checked_at ? ' · checked ' + formatHostTime(runtime.checked_at) : '') + '. Process and backend health are separate.';
    } else {
      runtimeEl.textContent = 'Managed haproxy.cfg could not be identified' +
        (runtime && runtime.checked_at ? ' at ' + formatHostTime(runtime.checked_at) : '') + '. Process and backend health are separate.';
      attention.push(alertView('unknown', 'Managed edge artifact is unknown',
        'The API could not identify the current managed haproxy.cfg. Check the state path and API logs.'));
    }

    const last = edge.last_apply && typeof edge.last_apply === 'object' ? edge.last_apply : null;
    if (!last) {
      lastEl.textContent = 'No persistent edge operation has been recorded yet.';
      return;
    }
    lastEl.textContent = (last.at ? formatHostTime(last.at) : 'Time unavailable') + ' · ' +
      String(last.outcome || 'unknown') +
      (last.revision_sha ? ' · SHA ' + shortSha(last.revision_sha) : '') +
      (last.error_code ? ' · ' + String(last.error_code) : '');
    if (last.outcome === 'failed' || last.outcome === 'unknown') {
      attention.push(alertView(last.outcome === 'failed' ? 'danger' : 'unknown', 'Last edge operation was not confirmed',
        'Outcome ' + String(last.outcome) + (last.error_code ? ' · ' + String(last.error_code) : '') + '.'));
    }
  }

  async function loadDashTraffic(signal) {
    if (document.getElementById('view-app').classList.contains('hidden')) return { success: 0, failures: [] };
    if (!dashboardIsCurrent(signal)) return { success: 0, failures: [] };
    const errEl = document.getElementById('dash-haproxy-err');
    const table = document.getElementById('dash-haproxy-table');
    const rr = document.getElementById('dash-req-rate');
    const active = document.getElementById('dash-active-sessions');
    rr.textContent = 'Unknown';
    active.textContent = 'Unknown';
    if (errEl) errEl.textContent = '';
    if (table) table.innerHTML = stateView('loading', 'Loading HAProxy runtime…');

    const [summaryResult, runtimeResult] = await Promise.all([
      dashboardRequest('/api/v1/stats/summary', signal),
      dashboardRequest('/api/v1/stats/haproxy', signal)
    ]);
    if (!dashboardIsCurrent(signal)) return { success: 0, failures: [] };

    const failures = [];
    let success = 0;
    const summary = summaryResult.data;
    if (summary && !summary.error) {
      success++;
      rr.textContent = summary.req_rate != null && Number.isFinite(Number(summary.req_rate))
        ? Number(summary.req_rate).toFixed(1)
        : 'Unknown';
      active.textContent = summary.active_sessions != null ? String(summary.active_sessions) : 'Unknown';
    } else {
      failures.push('HAProxy summary (' + (summaryResult.failure || summary?.error || 'invalid response') + ')');
    }

    const runtime = runtimeResult.data;
    if (runtime && !runtime.error) {
      success++;
      const backends = Array.isArray(runtime.backends) ? runtime.backends : [];
      if (!backends.length) {
        table.innerHTML = stateView('empty', 'No HAProxy backend rows were returned.');
      } else {
        const rows = backends.map((backend) => {
          const servers = (Array.isArray(backend.servers) ? backend.servers : []).map((server) => {
            const serverStatus = String(server.status || 'unknown');
            const tone = serverStatus.toUpperCase().startsWith('UP') ? 'success' : (serverStatus ? 'warning' : 'unknown');
            return esc(server.name || 'server') + ': ' + statusBadge(serverStatus || 'Unknown', tone);
          }).join(' ') || 'Unknown';
          const backendStatus = String(backend.status || 'unknown');
          const backendTone = backendStatus.toUpperCase().startsWith('UP') ? 'success' : (backendStatus ? 'warning' : 'unknown');
          return '<tr><td><code>' + esc(backend.name || '') + '</code></td><td>' +
            statusBadge(backendStatus || 'Unknown', backendTone) + '</td><td>' +
            esc(backend.health || 'Unknown') + '</td><td>' +
            (backend.sessions_cur != null ? esc(String(backend.sessions_cur)) : 'Unknown') +
            '</td><td style="font-size:0.85rem">' + servers + '</td></tr>';
        }).join('');
        table.innerHTML = '<div class="table-scroll"><table><thead><tr><th>Backend</th><th>Runtime status</th><th>Health field</th><th>Sessions</th><th>Servers</th></tr></thead><tbody>' +
          rows + '</tbody></table></div>';
      }
    } else {
      failures.push('HAProxy runtime (' + (runtimeResult.failure || runtime?.error || 'invalid response') + ')');
      table.innerHTML = stateView('offline', 'HAProxy runtime is unavailable. Use Refresh after checking the stats socket and API logs.');
    }

    if (failures.length && errEl) errEl.textContent = failures.join(' · ');
    return { success, failures };
  }

  function loadDashboard() {
    stopDashStatsTimer();
    return runDashboardLoad(renderDashboard);
  }

  async function renderDashboard(signal) {
    resetDashboardView();

    const requests = [
      ['API status', '/api/v1/status'],
      ['Edge state', '/api/v1/edge/status'],
      ['Applications', '/api/v1/applications'],
      ['Certificate summary', '/api/v1/certificates/summary'],
      ['Revision history', '/api/v1/revisions?limit=30'],
      ['CrowdSec LAPI', '/api/v1/integrations/crowdsec'],
      ['CrowdSec decisions', '/api/v1/integrations/crowdsec/decisions', true],
      ['Local IP blacklist', '/api/v1/ipbl/local'],
      ['IP blacklist sources', '/api/v1/ipbl/sources'],
      ['systemd services', '/api/v1/system/services']
    ];
    const [results, trafficResult] = await Promise.all([
      Promise.all(requests.map(([, path, includeError]) => dashboardRequest(path, signal, includeError))),
      loadDashTraffic(signal)
    ]);
    if (!dashboardIsCurrent(signal)) return;

    const failedSources = [];
    let successCount = 0;
    results.forEach((result, index) => {
      if (result.failure) failedSources.push(requests[index][0] + ' (' + result.failure + ')');
      else successCount++;
    });

    const [
      {data: status}, {data: edge}, {data: appsData}, {data: certSummary}, {data: revisions}, {data: crowdsec},
      {data: decisions, failure: decisionsFailure}, {data: localEntries}, {data: sourceEntries}, {data: servicesData}
    ] = results;

    const attention = [];
    if (status) {
      renderApplicationVersion(status.version);
      document.getElementById('dash-state-dir').textContent = status.state_dir ? 'State directory reported' : '';
    } else {
      renderApplicationVersion('');
      document.getElementById('dash-state-dir').textContent = 'Status endpoint unavailable';
    }

    let apps = null;
    renderDashboardEdgeStatus(edge, attention);
    if (Array.isArray(appsData)) {
      apps = appsData;
      const enabled = apps.filter((app) => app.enabled).length;
      document.getElementById('dash-apps-stat').textContent = enabled + ' / ' + apps.length;

      let savedPreset = 0;
      let custom = 0;
      let reverseProxyOnly = 0;
      let httpOnly = 0;
      const reverseProxyNames = [];
      const httpOnlyNames = [];
      for (const app of apps) {
        const mode = (app.security && app.security.mode) || 'balanced';
        if (mode === 'reverse-proxy-only') {
          reverseProxyOnly++;
          reverseProxyNames.push(app.name || app.public_host || app.id || 'Unnamed application');
        } else if (mode === 'custom') {
          custom++;
        } else {
          savedPreset++;
        }
        if (String(app.listen_mode || 'https_only').toLowerCase() === 'http_only') {
          httpOnly++;
          httpOnlyNames.push(app.name || app.public_host || app.id || 'Unnamed application');
        }
      }
      document.getElementById('dash-sec-line').textContent = 'Saved preset modes: ' + savedPreset +
        ' · Custom: ' + custom + ' · Reverse proxy only: ' + reverseProxyOnly;
      document.getElementById('dash-http-line').textContent = 'Saved HTTP-only listen mode: ' + httpOnly;
      if (reverseProxyOnly > 0) {
        attention.push(alertView('warning', 'Saved mode requires review',
          reverseProxyOnly + ' application(s) use reverse-proxy-only in saved configuration: ' +
          reverseProxyNames.join(', ') + '. This does not report applied state.'));
      }
      if (httpOnly > 0) {
        attention.push(alertView('warning', 'Plain HTTP is configured',
          httpOnly + ' application(s) have HTTP-only saved configuration: ' + httpOnlyNames.join(', ') + '.'));
      }

      const rows = apps.map((app) => {
        const configured = app.enabled ? statusBadge('Enabled', 'info') : statusBadge('Disabled', 'neutral');
        const mode = (app.security && app.security.mode) || 'balanced';
        return '<tr><td>' + esc(app.name || '') + '</td><td>' + esc(app.public_host || '') +
          '</td><td><code>' + esc(app.backend_host || '') + ':' + esc(String(app.backend_port || '')) +
          '</code></td><td>' + statusBadge('Saved: ' + mode, 'neutral') + '</td><td>' + configured + '</td></tr>';
      }).join('');
      document.getElementById('dash-backends').innerHTML = apps.length
        ? '<div class="table-scroll"><table><thead><tr><th>Name</th><th>Public hostname</th><th>Saved backend</th><th>Saved policy</th><th>Configured state</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
        : stateView('empty', 'No applications are configured.');
    } else {
      document.getElementById('dash-backends').innerHTML = stateView('error', 'Saved applications are unavailable. Use Refresh to retry.');
    }

    if (certSummary && typeof certSummary.valid === 'number') {
      const expiring = Number(certSummary.expiring_soon || 0);
      const expired = Number(certSummary.expired || 0);
      const failed = Number(certSummary.failed || 0);
      document.getElementById('dash-certs-stat').textContent = certSummary.valid + ' / ' + expiring + ' / ' + expired;
      document.getElementById('dash-certs-sub').textContent = 'valid · expiring · expired · total ' + Number(certSummary.total || 0) +
        (failed > 0 ? ' · failed ' + failed : '');
      const certAttention = (Array.isArray(certSummary.certificates) ? certSummary.certificates : []).filter((cert) => cert.attention);
      if (certAttention.length) {
        attention.push(alertView('danger', 'Certificates need attention',
          certAttention.map((cert) => (cert.primary_domain || cert.id || 'Certificate') + ': ' + cert.attention).join(', ') + '.'));
      }
    } else {
      document.getElementById('dash-certs-sub').textContent = 'Summary unavailable';
    }

    if (crowdsec && typeof crowdsec.reachable === 'boolean') {
      if (crowdsec.reachable) {
        document.getElementById('dash-cs-stat').innerHTML = statusBadge('LAPI reachable', 'success');
      } else {
        document.getElementById('dash-cs-stat').innerHTML = statusBadge('LAPI unreachable', 'danger');
        attention.push(alertView('danger', 'CrowdSec LAPI is unreachable',
          crowdsec.last_message || 'The LAPI probe failed. Check the CrowdSec integration settings and service.'));
      }
      document.getElementById('dash-cs-sub').textContent = crowdsec.last_message || 'Reachability probe completed';
    }

    if (!decisionsFailure) {
      const count = decisionsCount(decisions);
      if (count != null) {
        document.getElementById('dash-cs-sub').textContent +=
          (document.getElementById('dash-cs-sub').textContent ? ' · ' : '') + 'sample decisions: ' + count;
      }
    } else if (crowdsec && crowdsec.reachable) {
      document.getElementById('dash-cs-stat').innerHTML = statusBadge('LAPI reachable', 'warning');
      document.getElementById('dash-cs-sub').textContent += ' · Decisions unavailable';
      attention.push(alertView('warning', 'CrowdSec decisions unavailable', decisionsFailure));
    }

    if (Array.isArray(localEntries) || Array.isArray(sourceEntries)) {
      const localText = Array.isArray(localEntries) ? String(localEntries.length) : 'Unknown';
      const sourceText = Array.isArray(sourceEntries) ? String(sourceEntries.length) : 'Unknown';
      document.getElementById('dash-ipbl-stat').textContent = localText + ' · ' + sourceText;
    }

    if (Array.isArray(revisions)) {
      if (revisions.length) {
        const current = revisions.find((revision) => revision.is_current);
        document.getElementById('dash-revision-line').textContent = current
          ? 'Revision row matches managed SHA ' + shortSha(current.sha) + ' · ' + (current.created_at ? formatHostTime(current.created_at) : 'time unavailable') + '.'
          : 'No revision row matches the managed live config checksum.';
        if (!current) attention.push(alertView('unknown', 'Recorded revision does not match', 'No revision row matches the managed live config checksum. Persistent generations remain the apply source of truth.'));
      } else {
        document.getElementById('dash-revision-line').textContent = 'No revision snapshots have been recorded.';
      }
    }

    const servicesBox = document.getElementById('dash-services');
    if (servicesData && Array.isArray(servicesData.services)) {
      if (!servicesData.services.length) {
        servicesBox.innerHTML = stateView('empty', 'No systemd service rows were returned.');
      } else {
        const unhealthy = [];
        const rows = servicesData.services.map((service) => {
          const state = String(service.active_state || 'unknown');
          const tone = state === 'active' ? 'success' : (state === 'unknown' ? 'unknown' : 'warning');
          if (state !== 'active') unhealthy.push((service.label || service.unit || 'Service') + ': ' + state);
          return '<tr><td><code>' + esc(service.unit || '') + '</code></td><td>' +
            esc(service.label || '') + '</td><td>' + statusBadge(state, tone) + '</td></tr>';
        }).join('');
        servicesBox.innerHTML = '<div class="table-scroll"><table><thead><tr><th>Unit</th><th>Role</th><th>systemd ActiveState</th></tr></thead><tbody>' +
          rows + '</tbody></table></div>';
        if (unhealthy.length) attention.push(alertView('warning', 'Component state needs review', unhealthy.join(' · ')));
      }
    } else {
      servicesBox.innerHTML = stateView('error', 'systemd service state is unavailable. Use Refresh after checking API host access to systemd.');
    }

    const snapshot = { successCount, failedSources, attention, loadedAt: formatHostTime(Date.now()) };
    renderDashboardStatus(snapshot, trafficResult);
    dashStatsTimer = setInterval(() => {
      if (dashboardController) return;
      return runDashboardLoad(async (pollSignal) => {
        const result = await loadDashTraffic(pollSignal);
        if (dashboardIsCurrent(pollSignal)) renderDashboardStatus(snapshot, result);
      });
    }, 10000);
  }

  function renderDashboardStatus(snapshot, traffic) {
    const failedSources = [...snapshot.failedSources, ...traffic.failures];
    const attention = [...snapshot.attention];
    if (failedSources.length) {
      attention.unshift(alertView('unknown', 'Dashboard data is incomplete',
        failedSources.join(' · ') + '. Unknown values are not replaced with zero.'));
    }
    if (!attention.length) {
      attention.push(alertView('success', 'No attention items in loaded data',
        'All requested sources responded and no loaded item currently reports a warning.'));
    }
    const attentionEl = document.getElementById('dash-attention-list');
    const attentionHTML = attention.join('');
    if (attentionEl.innerHTML !== attentionHTML) attentionEl.innerHTML = attentionHTML;

    const statusEl = document.getElementById('dash-status');
    const loadedAt = document.getElementById('dash-loaded-at');
    let state, message, freshness;
    if (snapshot.successCount + traffic.success === 0) {
      state = 'offline';
      message = 'Dashboard unavailable. Use Refresh after checking the API and network.';
      freshness = 'Not loaded';
    } else if (failedSources.length) {
      state = 'error';
      message = 'Partial data loaded. Unavailable sources remain Unknown.';
      freshness = snapshot.successCount === 0 ? 'HAProxy loaded at ' + formatHostTime(Date.now()) :
        'Partial data at ' + snapshot.loadedAt;
    } else {
      state = 'ready';
      message = 'Dashboard data loaded.';
      freshness = 'Loaded at ' + snapshot.loadedAt;
    }
    statusEl.dataset.state = state;
    if (statusEl.textContent !== message) statusEl.textContent = message;
    if (loadedAt.textContent !== freshness) loadedAt.textContent = freshness;
  }

  document.getElementById('btn-dashboard-refresh').onclick = () => {
    void withBusy(document.getElementById('btn-dashboard-refresh'), loadDashboard);
  };
  document.getElementById('btn-settings-load').onclick = loadSettingsTab;
  for (const id of ['btn-certs-settings-load', 'btn-security-settings-load', 'btn-cs-settings-load']) {
    document.getElementById(id).onclick = loadSettingsPanel;
  }

  const btnPromSave = document.getElementById('btn-prometheus-save');
  if (btnPromSave) {
    btnPromSave.onclick = async () => {
      const sm = document.getElementById('settings-msg');
      if (sm) {
        sm.textContent = '';
        sm.className = 'warn';
      }
      if (!cachedSettings) {
        if (sm) sm.textContent = 'Use Load from server first.';
        return;
      }
      const patch = { prometheus_enabled: !!document.getElementById('prometheus-enabled').checked };
      const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
      if (!r.ok) {
        if (sm) sm.textContent = await r.text();
        return;
      }
      cachedSettings = await r.json();
      if (sm) {
        sm.textContent = 'Prometheus toggle saved.';
        sm.className = 'ok';
      }
    };
  }
  const btnZabbixFw = document.getElementById('btn-zabbix-firewall-apply');
  if (btnZabbixFw) {
    btnZabbixFw.onclick = async () => {
      const sm = document.getElementById('settings-msg');
      if (sm) {
        sm.textContent = '';
        sm.className = 'warn';
      }
      if (!cachedSettings) {
        if (sm) sm.textContent = 'Use Load from server first.';
        return;
      }
      const enabled = !!document.getElementById('firewall-zabbix-agent').checked;
      const ok = await confirmDialog(
        enabled
          ? 'Apply the managed firewall with TCP 10050 allowed for Zabbix from RFC1918 and loopback? Click “Keep changes” within 90s to retain it.'
          : 'Apply the managed firewall with the Zabbix TCP 10050 rule removed? Click “Keep changes” within 90s to retain it.',
        { danger: true, okLabel: 'Apply' }
      );
      if (!ok) return;
      const r = await fetch('/api/v1/host/firewall/zabbix-agent', {
        method: 'POST',
        headers: hdr(),
        body: JSON.stringify({ enabled, reapply: true, rollback_seconds: 90 })
      });
      if (!r.ok) {
        const __m = await apiMessage(r);
        toast(__m, 'err');
        if (sm) sm.textContent = __m;
        return;
      }
      const j = await r.json();
      void loadZabbixFirewallStatus();
      try {
        const sr = await fetch('/api/v1/settings', { headers: hdr() });
        if (sr.ok) {
          cachedSettings = await sr.json();
          const zabbixEl = document.getElementById('firewall-zabbix-agent');
          if (zabbixEl) zabbixEl.checked = !!cachedSettings.firewall_zabbix_agent;
        }
      } catch (_) { /* keep local checkbox */ }
      if (j && j.status === 'unchanged') {
        const msg = enabled
          ? 'Preference saved. The managed Zabbix rule is already present.'
          : 'Preference saved. The managed Zabbix rule is already absent.';
        if (sm) { sm.textContent = msg; sm.className = 'ok'; }
        toast(msg, 'ok');
        return;
      }
      if (!j || !j.token || !j.operation_id || !j.expires_at) {
        clearHostRollbackCapability();
        if (sm) {
          sm.textContent = 'Applied, but the confirmation capability could not be verified. Waiting for the server safety rollback.';
          sm.className = 'warn';
        }
        toast('Applied, but confirmation cannot be verified. Waiting for the safety rollback.', 'err', 12000);
        await refreshHostRollbackStatus(true);
        return;
      }
      const capability = {
        kind: 'firewall',
        token: j.token,
        operation_id: j.operation_id,
        expires_at: j.expires_at,
        commit_url: '/api/v1/host/firewall/commit'
      };
      saveHostRollbackCapability(capability);
      if (!showHostRollbackBanner({
        kind: 'firewall',
        operation_id: j.operation_id,
        phase: 'pending',
        expires_at: j.expires_at,
        confirmable: true,
        total: 1
      }, capability)) {
        if (sm) {
          sm.textContent = 'Safety window expired. Verifying the current configuration.';
          sm.className = 'warn';
        }
        await refreshHostRollbackStatus(true);
        return;
      }
      await refreshHostRollbackStatus(false);
      toast('Applied — confirm within the safety window.', 'warn', 8000);
    };
  }
  async function saveCredentialSettings(button, patch, message, onSaved) {
    const session = sessionGeneration;
    await withFocusableBusy(button, async () => {
      let saved;
      try {
        const response = await fetch('/api/v1/settings', {method: 'PATCH', headers: hdr(), body: JSON.stringify(patch)});
        if (!response.ok) {
          const detail = await apiMessage(response);
          if (session === sessionGeneration) message.textContent = detail;
          return;
        }
        saved = await response.json();
        if (typeof saved?.acme_staging !== 'boolean') throw new Error('Invalid settings response');
      } catch (_) {
        if (session === sessionGeneration) message.textContent = 'Save outcome unknown. Load saved settings before retrying.';
        return;
      }
      if (session !== sessionGeneration) return;
      cachedSettings = saved;
      onSaved(saved);
    });
  }

  const btnNotifySave = document.getElementById('btn-notify-save');
  if (btnNotifySave) {
    btnNotifySave.onclick = async () => {
      const sm = document.getElementById('settings-msg');
      if (sm) {
        sm.textContent = '';
        sm.className = 'warn';
      }
      if (!cachedSettings) {
        if (sm) sm.textContent = 'Use Load from server first.';
        return;
      }
      const spike = parseInt(document.getElementById('notify-spike-threshold').value || '0', 10);
      const patch = {
        notify_webhook_url: document.getElementById('notify-webhook-url').value.trim(),
        notify_telegram_chat_id: document.getElementById('notify-telegram-chat').value.trim(),
        notify_telegram_bot_token: document.getElementById('notify-telegram-token').value.trim(),
        notify_blocked_spike_threshold: Number.isFinite(spike) ? spike : 0,
      };
      await saveCredentialSettings(btnNotifySave, patch, sm, saved => {
        const tokenField = document.getElementById('notify-telegram-token');
        const hasNewDraft = tokenField.value.trim() !== patch.notify_telegram_bot_token;
        if (!hasNewDraft) tokenField.value = '';
        tokenField.placeholder = saved.notify_telegram_bot_token_set ? '•••• token stored — enter a new one to replace' : '123456:ABC... from @BotFather';
        sm.textContent = hasNewDraft ? 'Notifications saved. The token entered during save is still a draft.' : 'Notifications saved.';
        sm.className = 'ok';
      });
    };
  }
  const btnNotifyTest = document.getElementById('btn-notify-test');
  if (btnNotifyTest) {
    btnNotifyTest.onclick = async () => {
      const r = await fetch('/api/v1/notify/test', { method: 'POST', headers: hdr() });
      if (!r.ok) { toast(await apiMessage(r), 'err'); return; }
      toast('Test notification sent.', 'ok');
    };
  }

  document.getElementById('btn-acme-settings-save').onclick = async () => {
    const msg = document.getElementById('certs-settings-msg');
    if (msg) {
      msg.textContent = '';
      msg.className = 'warn';
    }
    if (!cachedSettings) {
      if (msg) msg.textContent = 'Load saved settings on this page before saving.';
      return;
    }
    if (!document.getElementById('acme-email').checkValidity()) {
      if (msg) msg.textContent = 'Enter a valid email address.';
      return;
    }
    const patch = {
      acme_email: document.getElementById('acme-email').value.trim(),
      acme_staging: document.getElementById('acme-staging').checked
    };
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
    if (r.ok) {
      cachedSettings = await r.json();
      renderACMEConfigurationStatus(cachedSettings);
      if (msg) {
        msg.textContent = 'ACME saved.';
        msg.className = 'ok';
      }
    } else if (msg) {
      msg.textContent = await r.text();
    }
  };

  document.getElementById('btn-cs-settings-save').onclick = async () => {
    const msg = document.getElementById('cs-settings-msg');
    if (msg) {
      msg.textContent = '';
      msg.className = 'warn';
    }
    if (!cachedSettings) {
      if (msg) msg.textContent = 'Load saved settings on this page before saving.';
      return;
    }
    const patch = {
      crowdsec_lapi_url: document.getElementById('cs-lapi-url').value.trim(),
      spoe_config_path: document.getElementById('cs-spoe-path').value.trim(),
      crowdsec_engine_name: document.getElementById('cs-engine-name').value.trim()
    };
    const keyField = document.getElementById('cs-lapi-key');
    const csKey = keyField.value.trim();
    if (csKey) patch.crowdsec_lapi_key = csKey;
    await saveCredentialSettings(document.getElementById('btn-cs-settings-save'), patch, msg, saved => {
      const hasNewDraft = keyField.value.trim() !== csKey;
      if (!hasNewDraft) keyField.value = '';
      keyField.placeholder = saved.crowdsec_lapi_key_set
        ? '•••• key stored — enter new key to replace'
        : 'Machine bouncer key (cscli bouncers add -o raw)';
      if (msg) {
        msg.textContent = hasNewDraft ? 'CrowdSec settings saved. The key entered during save is still a draft.' : 'CrowdSec settings saved.';
        msg.className = 'ok';
      }
    });
  };

  document.getElementById('btn-waf-security-save').onclick = async () => {
    const msg = document.getElementById('waf-security-msg');
    msg.textContent = '';
    if (!cachedSettings) { msg.textContent = 'Load saved settings on this page before saving.'; return; }
    const patch = { waf_basic_rules_enabled: document.getElementById('waf-basic-enabled').checked };
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
    if (r.ok) {
      cachedSettings = await r.json();
      msg.textContent = 'WAF toggle saved.';
      msg.className = 'ok';
      markPendingApply(true);
    } else {
      msg.textContent = await r.text();
      msg.className = 'warn';
    }
  };

  document.getElementById('btn-edge-cloudflare').onclick = () => {
    const merged = Array.from(new Set(edgeLines('edge-trusted-proxies').concat(CLOUDFLARE_RANGES)));
    document.getElementById('edge-trusted-proxies').value = merged.join('\n');
    document.getElementById('edge-real-ip-header').value = 'CF-Connecting-IP';
  };

  document.getElementById('btn-edge-network-save').onclick = async () => {
    const msg = document.getElementById('edge-network-msg');
    msg.textContent = '';
    msg.className = 'warn';
    if (!cachedSettings) { msg.textContent = 'Load saved settings on this page before saving.'; return; }
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(edgeNetworkPatch()) });
    if (r.ok) {
      cachedSettings = await r.json();
      loadEdgeNetworkFromSettings();
      msg.textContent = 'Edge network saved. Apply HAProxy to use it.';
      msg.className = 'ok';
      markPendingApply(true);
    } else {
      msg.textContent = await r.text();
    }
  };

  document.getElementById('btn-geoip-settings-save').onclick = async () => {
    const geoMsg = document.getElementById('security-geo-msg');
    if (geoMsg) geoMsg.textContent = '';
    if (!cachedSettings) {
      const t = 'Load saved settings on this page before saving.';
      if (geoMsg) geoMsg.textContent = t;
      return;
    }
    const patch = {
      geoip_enabled: document.getElementById('geoip-enabled').checked,
      geoip_provider: document.getElementById('geoip-provider').value.trim().toLowerCase(),
      geoip_default_policy: document.getElementById('geoip-policy').value.trim().toLowerCase(),
      geoip_country_list: parseCountryListText(document.getElementById('geoip-countries').value),
      geoip_mmdb_path: document.getElementById('geoip-mmdb-path') ? document.getElementById('geoip-mmdb-path').value.trim() : ''
    };
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
    if (r.ok) {
      cachedSettings = await r.json();
      loadGeoIPFromSettings();
      markPendingApply(true);
      if (geoMsg) {
        geoMsg.textContent = 'GeoIP settings saved.';
        geoMsg.className = 'ok';
      }
    } else {
      const err = await r.text();
      if (geoMsg) {
        geoMsg.textContent = err;
        geoMsg.className = 'warn';
      }
    }
  };

  const geoipProviderEl = document.getElementById('geoip-provider');
  if (geoipProviderEl) geoipProviderEl.addEventListener('change', () => { syncGeoIPMaxMindRow(); });

  document.getElementById('btn-geoip-validate-mm').onclick = async () => {
    const out = document.getElementById('geoip-lookup-out');
    out.textContent = '';
    const pathEl = document.getElementById('geoip-mmdb-path');
    const path = pathEl ? pathEl.value.trim() : '';
    if (!path) {
      out.textContent = 'Enter MMDB path first.';
      return;
    }
    const q =
      'ip=' +
      encodeURIComponent('8.8.8.8') +
      '&nocache=1&probe_mmdb_path=' +
      encodeURIComponent(path);
    const r = await fetch('/api/v1/geoip/lookup?' + q, { headers: hdr() });
    const txt = await r.text();
    try {
      out.textContent = JSON.stringify(JSON.parse(txt), null, 2);
    } catch {
      out.textContent = txt;
    }
  };

  document.getElementById('btn-geoip-upload').onclick = async () => {
    const out = document.getElementById('geoip-lookup-out');
    const msg = document.getElementById('security-geo-msg');
    const input = document.getElementById('geoip-mmdb-file');
    const btn = document.getElementById('btn-geoip-upload');
    const file = input && input.files && input.files[0];
    out.textContent = '';
    if (!file) { msg.textContent = 'Choose a .mmdb or .tar.gz file first.'; return; }

    const mb = (file.size / (1024 * 1024)).toFixed(1);
    msg.textContent = 'Uploading ' + file.name + ' (' + mb + ' MB)…';
    btn.disabled = true;
    try {
      // Raw body, not multipart: the server detects .mmdb vs .tar.gz from the
      // content and never trusts the file name.
      const r = await fetch('/api/v1/geoip/database', {
        method: 'POST',
        headers: hdr({ 'Content-Type': 'application/octet-stream' }),
        body: file,
      });
      const txt = await r.text();
      let data = null;
      try { data = JSON.parse(txt); } catch { /* keep raw text */ }
      out.textContent = data ? JSON.stringify(data, null, 2) : txt;
      if (!r.ok) {
        msg.textContent = 'Upload rejected — the previous database is still active.';
        return;
      }
      const pathEl = document.getElementById('geoip-mmdb-path');
      if (pathEl && data && data.path) pathEl.value = data.path;
      msg.textContent =
        'Installed ' + (data && data.database_type ? data.database_type : 'database') +
        (data && data.reloaded
          ? ' — live now, lookup cache cleared.'
          : ' — press "Save GeoIP settings" to activate this path.');
      input.value = '';
      await refreshGeoIPProvidersNote();
    } catch (e) {
      msg.textContent = 'Upload failed: ' + e;
    } finally {
      btn.disabled = false;
    }
  };

  document.getElementById('btn-geoip-lookup').onclick = async () => {
    const ip = document.getElementById('geoip-lookup-ip').value.trim();
    const out = document.getElementById('geoip-lookup-out');
    out.textContent = '';
    if (!ip) { out.textContent = 'Enter an IP'; return; }
    const r = await fetch('/api/v1/geoip/lookup?ip=' + encodeURIComponent(ip), { headers: hdr() });
    const txt = await r.text();
    try { out.textContent = JSON.stringify(JSON.parse(txt), null, 2); } catch { out.textContent = txt; }
  };

  document.getElementById('btn-certs').onclick = () => { loadCertDashboard(); };

  function csOut(obj) {
    document.getElementById('crowdsec-out').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  }

  async function loadCrowdsecDecisionsTable() {
    const wrap = document.getElementById('cs-decisions-table-wrap');
    const msg = document.getElementById('cs-decisions-msg');
    if (!wrap) return;
    if (msg) {
      msg.textContent = '';
      msg.className = 'warn';
    }
    tableState(wrap, 'loading');
    const r = await fetch('/api/v1/integrations/crowdsec/decisions', { headers: hdr() });
    if (r.status === 401 || r.status === 403) {
      if (r.status === 401) setTok('');
      refreshSession();
      return;
    }
    if (!r.ok) {
      tableState(wrap, 'error', { message: await apiMessage(r) });
      return;
    }
    const txt = await r.text();
    let arr = [];
    try {
      const j = JSON.parse(txt);
      if (Array.isArray(j)) arr = j;
      else if (j && Array.isArray(j.data)) arr = j.data;
    } catch (_) {
      tableState(wrap, 'error', { message: 'Invalid JSON from decisions API' });
      return;
    }
    if (!arr.length) {
      tableState(wrap, 'empty', { message: 'No active decisions (or LAPI not connected).' });
      return;
    }
    const rows = arr.map((d) => {
      const id = d.id != null ? String(d.id) : '';
      const ip = d.value != null ? String(d.value) : '';
      const typ = esc(d.type || '');
      const typRaw = (d.type || '').toLowerCase();
      const isWL = typRaw === 'whitelist';
      const btnLabel = isWL ? 'Remove' : 'Unban';
      const scen = esc(d.scenario || '');
      const dur = esc(d.duration || d.decision || '');
      const exp = esc(formatHostTime(d.expires_at || d.until));
      return (
        '<tr><td><code>' + esc(id) + '</code></td><td><code>' + esc(ip) + '</code></td><td>' + typ + '</td><td>' + scen +
        '</td><td>' + dur + '</td><td>' + exp + '</td><td><button type="button" class="secondary cs-unban" data-id="' +
        esc(id) + '" data-ip="' + esc(ip) + '" data-wl="' + (isWL ? '1' : '0') + '">' + btnLabel + '</button></td></tr>'
      );
    }).join('');
    wrap.innerHTML =
      '<table><thead><tr><th>ID</th><th>Value (IP)</th><th>Type</th><th>Scenario</th><th>Duration</th><th>Expires</th><th></th></tr></thead><tbody>' +
      rows +
      '</tbody></table>';
  }

  let fail2banGeneration = 0;
  async function loadFail2banOverview() {
    const generation = ++fail2banGeneration;
    const session = sessionGeneration;
    const current = () => generation === fail2banGeneration && session === sessionGeneration;
    const msg = document.getElementById('f2b-status-msg');
    const wrap = document.getElementById('f2b-jails-wrap');
    const jailSel = document.getElementById('f2b-unban-jail');
    const unban = document.getElementById('btn-f2b-unban');
    const placeholder = '<option value="">Select a jail</option>';
    jailSel.disabled = unban.disabled = true;
    jailSel.innerHTML = placeholder;
    msg.textContent = 'Loading Fail2Ban jails…';
    msg.className = 'warn';
    tableState(wrap, 'loading');
    let j;
    try {
      const r = await fetch('/api/v1/integrations/fail2ban', {headers: hdr()});
      if (!r.ok) throw new Error('HTTP ' + r.status);
      j = await r.json();
      if (typeof j?.status?.running !== 'boolean' || !Array.isArray(j.jails) ||
          !j.jails.every(row => typeof row?.name === 'string' && row.name &&
            (row.unavailable === true || Array.isArray(row.banned_ips)))) throw new Error('Invalid jail list');
    } catch (error) {
      if (!current()) return;
      msg.textContent = 'Jail list unavailable. Select Refresh jails to retry.';
      tableState(wrap, 'error', {message: error.message});
      return;
    }
    if (!current()) return;
    const st = j.status;
    if (msg) {
      if (st.running) {
        msg.textContent = 'Daemon: running (' + (st.message || 'pong') + ')';
        msg.className = 'ok';
      } else {
        msg.textContent = 'Daemon: ' + (st.message || 'not running');
        msg.className = 'warn';
      }
    }
    const jails = st.running ? j.jails : [];
    const available = jails.filter(row => !row.unavailable);
    if (available.length < jails.length) {
      msg.textContent += ' Some jail details are unavailable. Refresh jails to retry.';
      msg.className = 'warn';
    }
    jailSel.innerHTML = placeholder + available.map(x => '<option value="' + esc(x.name) + '">' + esc(x.name) + '</option>').join('');
    jailSel.disabled = unban.disabled = !available.length;
    if (!jails.length) {
      tableState(wrap, st.running ? 'empty' : 'error', { message: st.running ? 'No jails configured.' : 'Jail details unavailable.' });
      return;
    }
    const rows = jails.map((jail) => {
      if (jail.unavailable) return '<tr><td><code>' + esc(jail.name) + '</code></td><td colspan="2">Unavailable</td></tr>';
      const ips = Array.isArray(jail.banned_ips) ? jail.banned_ips : [];
      const ipCells = ips.length
        ? ips.map((ip) =>
            '<code>' + esc(ip) + '</code> <button type="button" class="secondary f2b-unban-row" data-jail="' +
            esc(jail.name) + '" data-ip="' + esc(ip) + '">Unban</button>'
          ).join('<br />')
        : '<span class="dash-note">none</span>';
      return '<tr><td><code>' + esc(jail.name) + '</code></td><td>' + ips.length + '</td><td>' + ipCells + '</td></tr>';
    }).join('');
    wrap.innerHTML =
      '<table><thead><tr><th>Jail</th><th>Banned</th><th>IPs</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  document.getElementById('btn-f2b-refresh').onclick = () => { void loadFail2banOverview(); };

  (function bindFail2banUnban() {
    const wrap = document.getElementById('f2b-jails-wrap');
    if (wrap) {
      wrap.addEventListener('click', async (ev) => {
        const btn = ev.target && ev.target.closest && ev.target.closest('button.f2b-unban-row');
        if (!btn) return;
        const jail = btn.getAttribute('data-jail');
        const ip = btn.getAttribute('data-ip');
        if (!jail || !ip) return;
        await confirmFail2banUnban(btn, jail, ip);
      });
    }
  })();

  async function confirmFail2banUnban(button, jail, ip) {
    const generation = fail2banGeneration;
    const session = sessionGeneration;
    return withFocusableBusy(button, async () => {
      const ok = await confirmDialog('Unban ' + ip + ' from jail ' + jail + '?', {okLabel: 'Unban'});
      if (!ok || session !== sessionGeneration) return false;
      if (generation !== fail2banGeneration) {
        document.getElementById('f2b-unban-msg').textContent = 'The jail list changed. Review it before unbanning.';
        return false;
      }
      return postFail2banUnban(jail, ip);
    });
  }

  async function postFail2banUnban(jail, ip) {
    const msg = document.getElementById('f2b-unban-msg');
    if (msg) {
      msg.textContent = '';
      msg.className = 'warn';
    }
    const session = sessionGeneration;
    const r = await fetch('/api/v1/integrations/fail2ban/unban', {
      method: 'POST',
      headers: hdr(),
      body: JSON.stringify({ jail: jail, ip: ip })
    }).catch(() => null);
    if (session !== sessionGeneration) return false;
    if (!r) {
      msg.textContent = 'Unban outcome unknown. Check the refreshed jail list before retrying.';
      await loadFail2banOverview();
      return false;
    }
    if (!r.ok) {
      if (msg) msg.textContent = await r.text().catch(() => r.statusText);
      return;
    }
    if (msg) {
      msg.textContent = 'Unban OK.';
      msg.className = 'ok';
    }
    await loadFail2banOverview();
    return true;
  }

  document.getElementById('btn-f2b-unban').onclick = async () => {
    const jailEl = document.getElementById('f2b-unban-jail');
    const ipEl = document.getElementById('f2b-unban-ip');
    const jail = jailEl ? jailEl.value : '';
    const ip = ipEl && ipEl.value ? ipEl.value.trim() : '';
    if (!jail || !ip) {
      const msg = document.getElementById('f2b-unban-msg');
      if (msg) msg.textContent = 'Select jail and enter IP.';
      return;
    }
    if (await confirmFail2banUnban(document.getElementById('btn-f2b-unban'), jail, ip) && ipEl.value.trim() === ip) ipEl.value = '';
  };

  document.getElementById('btn-cs-ping').onclick = async () => {
    const r = await fetch('/api/v1/integrations/crowdsec', { headers: hdr() });
    csOut(await r.json().catch(() => ({})));
  };
  document.getElementById('btn-cs-dec').onclick = () => {
    void loadCrowdsecDecisionsTable();
  };

  (function bindCrowdsecDecisionActions() {
    const wrap = document.getElementById('cs-decisions-table-wrap');
    if (!wrap) return;
    wrap.addEventListener('click', async (ev) => {
      const btn = ev.target && ev.target.closest && ev.target.closest('button.cs-unban');
      if (!btn) return;
      const id = btn.getAttribute('data-id');
      const ip = btn.getAttribute('data-ip') || '';
      if (!id) return;
      const isWL = btn.getAttribute('data-wl') === '1';
      const verb = isWL ? 'whitelist entry' : 'ban';
      const okRm = await confirmDialog('Remove ' + verb + ' for ' + ip + '? Decision ID: ' + id, { danger: true, okLabel: 'Remove' });
      if (!okRm) return;
      const msg = document.getElementById('cs-decisions-msg');
      if (msg) {
        msg.textContent = '';
        msg.className = 'warn';
      }
      await withBusy(btn, async () => {
        const r = await fetch('/api/v1/integrations/crowdsec/decisions/' + encodeURIComponent(id), {
          method: 'DELETE',
          headers: hdr()
        });
        if (!r.ok) {
          { const __m = await apiMessage(r); toast(__m, 'err'); if (msg) msg.textContent = __m; }
          return;
        }
        toast('Decision removed.', 'ok');
        await loadCrowdsecDecisionsTable();
      });
    });
  })();

  document.getElementById('btn-cs-allow').onclick = async () => {
    const msg = document.getElementById('cs-allow-msg');
    const ipEl = document.getElementById('cs-allow-ip');
    const reasonEl = document.getElementById('cs-allow-reason');
    if (msg) {
      msg.textContent = '';
      msg.className = 'warn';
    }
    const ip = ipEl && ipEl.value ? ipEl.value.trim() : '';
    if (!ip) {
      if (msg) msg.textContent = 'Enter an IP address.';
      return;
    }
    const reason = reasonEl && reasonEl.value.trim() ? reasonEl.value.trim() : 'manual allowlist from UI';
    const body = { ip: ip, type: 'whitelist', duration: 'permanent', reason: reason };
    const r = await fetch('/api/v1/integrations/crowdsec/decisions', {
      method: 'POST',
      headers: hdr(),
      body: JSON.stringify(body)
    });
    if (!r.ok) {
      if (msg) msg.textContent = await apiMessage(r);
      return;
    }
    if (msg) {
      msg.textContent = 'Whitelist submitted.';
      msg.className = 'ok';
    }
    if (ipEl) ipEl.value = '';
    if (reasonEl) reasonEl.value = '';
    await loadCrowdsecDecisionsTable();
  };

  document.getElementById('btn-cs-ban').onclick = async () => {
    const banBtn = document.getElementById('btn-cs-ban');
    await withBusy(banBtn, async () => {
      const msg = document.getElementById('cs-ban-msg');
      const ipEl = document.getElementById('cs-ban-ip');
      const durEl = document.getElementById('cs-ban-duration');
      const reasonEl = document.getElementById('cs-ban-reason');
      if (msg) {
        msg.textContent = '';
        msg.className = 'warn';
      }
      const ip = ipEl && ipEl.value ? ipEl.value.trim() : '';
      if (!ip) {
        if (msg) msg.textContent = 'Enter an IP address.';
        return;
      }
      const duration = durEl ? durEl.value : '24h';
      const reason = reasonEl && reasonEl.value.trim() ? reasonEl.value.trim() : 'manual ban from UI';
      const body = { ip: ip, type: 'ban', duration: duration, reason: reason };
      const r = await fetch('/api/v1/integrations/crowdsec/decisions', {
        method: 'POST',
        headers: hdr(),
        body: JSON.stringify(body)
      });
      if (!r.ok) {
        { const __m = await apiMessage(r); toast(__m, 'err'); if (msg) msg.textContent = __m; }
        return;
      }
      toast('Ban submitted.', 'ok');
      if (msg) {
        msg.textContent = 'Ban submitted.';
        msg.className = 'ok';
      }
      if (ipEl) ipEl.value = '';
      if (reasonEl) reasonEl.value = '';
      await loadCrowdsecDecisionsTable();
    });
  };

  let managementTLSGeneration = 0;
  function clearManagementTLSForm() {
    managementTLSGeneration++;
    document.getElementById('tls-cert').value = '';
    document.getElementById('tls-key').value = '';
    document.getElementById('tls-msg').textContent = '';
    document.getElementById('btn-tls-save').disabled = false;
  }

  document.getElementById('btn-tls-save').onclick = async (event) => {
    const button = event.currentTarget;
    if (button.disabled) return;
    const generation = managementTLSGeneration;
    const cert = document.getElementById('tls-cert');
    const key = document.getElementById('tls-key');
    const msg = document.getElementById('tls-msg');
    const body = {certificate_pem: cert.value, private_key_pem: key.value};
    msg.textContent = 'Installing management certificate…';
    button.disabled = true;
    try {
      const r = await fetch('/api/v1/settings/management-tls', {method: 'PUT', headers: hdr(), body: JSON.stringify(body)});
      if (!r.ok) {
        const reason = await apiMessage(r);
        if (generation === managementTLSGeneration) msg.textContent = reason;
        return;
      }
      if (generation !== managementTLSGeneration) return;
      if (cert.value === body.certificate_pem) cert.value = '';
      if (key.value === body.private_key_pem) key.value = '';
      msg.textContent = 'Management certificate installed. Reconnect over HTTPS to verify it.';
    } catch (_) {
      if (generation === managementTLSGeneration) msg.textContent = 'Could not confirm installation. Check the certificate over HTTPS before retrying.';
    } finally {
      if (generation === managementTLSGeneration) button.disabled = false;
    }
  };

  document.getElementById('btn-ipbl-fetch-cidrs-save').onclick = async () => {
    const msg = document.getElementById('ipbl-fetch-cidrs-msg');
    if (msg) msg.textContent = '';
    if (!cachedSettings) {
      if (msg) msg.textContent = 'Load saved settings on this page before saving.';
      return;
    }
    const patch = { ipbl_fetch_allowed_cidrs: parseIpblFetchCIDRsTextarea() };
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
    if (r.ok) {
      cachedSettings = await r.json();
      loadIpblFetchCIDRsFromSettings();
      if (msg) {
        msg.textContent = 'Trusted CIDRs saved.';
        msg.className = 'ok';
      }
    } else if (msg) {
      msg.textContent = await r.text();
      msg.className = 'warn';
    }
  };

  document.getElementById('btn-ipbl-load').onclick = async () => {
    const box = document.getElementById('ipbl-table');
    document.getElementById('ipbl-msg').textContent = '';
    tableState(box, 'loading');
    const r = await fetch('/api/v1/ipbl/local', { headers: hdr() });
    const txt = await r.text();
    let j = [];
    try { j = JSON.parse(txt); } catch (_) { j = {}; }
    if (!r.ok) {
      tableState(box, 'error', { message: (j && j.error) || txt || r.statusText });
      document.getElementById('ipbl-msg').textContent = (j && j.error) || txt;
      return;
    }
    const list = Array.isArray(j) ? j : [];
    if (!list.length) {
      tableState(box, 'empty', { message: 'No local blacklist entries. Add a CIDR below.' });
      return;
    }
    const escLocal = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const rows = list.map((e) => `<tr><td><code>${escLocal(e.cidr)}</code></td><td>${escLocal(e.note)}</td><td>${e.enabled ? 'yes' : 'no'}</td><td><button type="button" class="secondary" data-ipbl-del="${escLocal(e.id)}" data-rule-value="${escLocal(e.cidr)}">Delete</button></td></tr>`).join('');
    box.innerHTML = `<table><thead><tr><th>CIDR</th><th>Note</th><th>Enabled</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    box.querySelectorAll('[data-ipbl-del]').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, async () => {
        if (!(await confirmProtectiveRuleChange('blacklist-delete', btn.getAttribute('data-rule-value')))) return;
        const id = btn.getAttribute('data-ipbl-del');
        const d = await fetch('/api/v1/ipbl/local/' + encodeURIComponent(id), { method: 'DELETE', headers: hdr() });
        if (!d.ok) { const __m = await apiMessage(d); toast(__m, 'err'); document.getElementById('ipbl-msg').textContent = __m; return; }
        markPendingApply(true);
        document.getElementById('btn-ipbl-load').click();
        document.getElementById('btn-ipbl-load').focus();
      });
    });
  };
  document.getElementById('btn-ipbl-sync').onclick = async () => {
    document.getElementById('ipbl-msg').textContent = '';
    const r = await fetch('/api/v1/ipbl/sync', { method: 'POST', headers: hdr(), body: '{}' });
    if (r.ok) {
      markPendingApply(true);
      document.getElementById('ipbl-msg').textContent = 'Sync OK (map updated).';
    } else {
      document.getElementById('ipbl-msg').textContent = await r.text();
    }
  };
  document.getElementById('btn-ipbl-add').onclick = async () => {
    document.getElementById('ipbl-msg').textContent = '';
    const body = {
      cidr: document.getElementById('ipbl-cidr').value.trim(),
      note: document.getElementById('ipbl-note').value.trim(),
      enabled: true
    };
    const r = await fetch('/api/v1/ipbl/local', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    if (!r.ok) { const __m = await apiMessage(r); toast(__m, 'err'); document.getElementById('ipbl-msg').textContent = __m; return; } 
    markPendingApply(true);
    document.getElementById('ipbl-cidr').value = '';
    document.getElementById('ipbl-note').value = '';
    document.getElementById('btn-ipbl-load').click();
  };

  document.getElementById('btn-ipwl-load').onclick = async () => {
    const box = document.getElementById('ipwl-table');
    document.getElementById('ipwl-msg').textContent = '';
    tableState(box, 'loading');
    const r = await fetch('/api/v1/ipwl/local', { headers: hdr() });
    const txt = await r.text();
    let j = [];
    try { j = JSON.parse(txt); } catch (_) { j = {}; }
    if (!r.ok) {
      tableState(box, 'error', { message: (j && j.error) || txt || r.statusText });
      return;
    }
    const list = Array.isArray(j) ? j : [];
    if (!list.length) {
      tableState(box, 'empty', { message: 'No allowlist entries. Add a trusted CIDR below.' });
      return;
    }
    const escLocal = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const rows = list.map((e) => `<tr><td><code>${escLocal(e.cidr)}</code></td><td>${escLocal(e.comment)}</td><td><button type="button" class="secondary" data-ipwl-del="${escLocal(e.id)}" data-rule-value="${escLocal(e.cidr)}">Delete</button></td></tr>`).join('');
    box.innerHTML = `<table><thead><tr><th>CIDR</th><th>Comment</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    box.querySelectorAll('[data-ipwl-del]').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, async () => {
        if (!(await confirmProtectiveRuleChange('allowlist-delete', btn.getAttribute('data-rule-value')))) return;
        const id = btn.getAttribute('data-ipwl-del');
        const d = await fetch('/api/v1/ipwl/local/' + encodeURIComponent(id), { method: 'DELETE', headers: hdr() });
        if (!d.ok) { const __m = await apiMessage(d); toast(__m, 'err'); document.getElementById('ipwl-msg').textContent = __m; return; }
        markPendingApply(true);
        document.getElementById('btn-ipwl-load').click();
        document.getElementById('btn-ipwl-load').focus();
      });
    });
  };
  document.getElementById('btn-ipwl-add').onclick = async () => {
    document.getElementById('ipwl-msg').textContent = '';
    const body = {
      cidr: document.getElementById('ipwl-cidr').value.trim(),
      comment: document.getElementById('ipwl-comment').value.trim()
    };
    const r = await fetch('/api/v1/ipwl/local', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    if (!r.ok) { const __m = await apiMessage(r); toast(__m, 'err'); document.getElementById('ipwl-msg').textContent = __m; return; } 
    markPendingApply(true);
    document.getElementById('ipwl-cidr').value = '';
    document.getElementById('ipwl-comment').value = '';
    document.getElementById('btn-ipwl-load').click();
  };
  document.getElementById('btn-ipwl-settings-save').onclick = async () => {
    document.getElementById('ipwl-msg').textContent = '';
    if (!cachedSettings) { document.getElementById('ipwl-msg').textContent = 'Load saved settings on this page before saving.'; return; }
    const patch = { ipwl_enabled: document.getElementById('ipwl-enabled').checked };
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
    if (r.ok) {
      cachedSettings = await r.json();
      markPendingApply(true);
      document.getElementById('ipwl-msg').textContent = 'Saved. Apply HAProxy to use new allowlist toggle.';
    } else {
      document.getElementById('ipwl-msg').textContent = await r.text();
    }
  };

  document.getElementById('btn-ua-settings-save').onclick = async () => {
    document.getElementById('ua-msg').textContent = '';
    if (!cachedSettings) { document.getElementById('ua-msg').textContent = 'Load saved settings on this page before saving.'; return; }
    const patch = {
      block_empty_ua: document.getElementById('ua-block-empty').checked,
      blocked_user_agents_enabled: document.getElementById('ua-blocklist-enabled').checked
    };
    const r = await fetch('/api/v1/settings', { method: 'PATCH', headers: hdr(), body: JSON.stringify(patch) });
    if (r.ok) {
      cachedSettings = await r.json();
      loadBotProtectionFromSettings();
      markPendingApply(true);
      document.getElementById('ua-msg').textContent = 'Saved. Apply HAProxy to activate UA rules.';
    } else {
      document.getElementById('ua-msg').textContent = await r.text();
    }
  };

  async function loadBlockedUATable() {
    const box = document.getElementById('ua-table');
    if (!box) return;
    document.getElementById('ua-msg').textContent = '';
    tableState(box, 'loading');
    const r = await fetch('/api/v1/security/blocked-ua', { headers: hdr() });
    const txt = await r.text();
    let j = [];
    try { j = JSON.parse(txt); } catch (_) { j = {}; }
    if (!r.ok) {
      tableState(box, 'error', { message: (j && j.error) || txt || r.statusText });
      return;
    }
    const list = Array.isArray(j) ? j : [];
    if (!list.length) {
      tableState(box, 'empty', { message: 'No blocked User-Agent patterns. Add one below, then Apply HAProxy.' });
      return;
    }
    const escLocal = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const rows = list.map((e) => `<tr><td><code>${escLocal(e.pattern)}</code></td><td>${escLocal(e.comment)}</td><td><button type="button" class="secondary" data-ua-del="${escLocal(e.id)}" data-rule-value="${escLocal(e.pattern)}">Delete</button></td></tr>`).join('');
    box.innerHTML = `<table><thead><tr><th>Pattern</th><th>Comment</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    box.querySelectorAll('[data-ua-del]').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, async () => {
        if (!(await confirmProtectiveRuleChange('user-agent-delete', btn.getAttribute('data-rule-value')))) return;
        const id = btn.getAttribute('data-ua-del');
        const d = await fetch('/api/v1/security/blocked-ua/' + encodeURIComponent(id), { method: 'DELETE', headers: hdr() });
        if (!d.ok) { const __m = await apiMessage(d); toast(__m, 'err'); document.getElementById('ua-msg').textContent = __m; return; }
        markPendingApply(true);
        await loadBlockedUATable();
        document.getElementById('btn-ua-load').focus();
      });
    });
  }
  document.getElementById('btn-ua-load').onclick = loadBlockedUATable;
  document.getElementById('btn-ua-add').onclick = async () => {
    document.getElementById('ua-msg').textContent = '';
    const body = {
      pattern: document.getElementById('ua-pattern').value.trim(),
      comment: document.getElementById('ua-comment').value.trim()
    };
    const r = await fetch('/api/v1/security/blocked-ua', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
    if (!r.ok) { const __m = await apiMessage(r); toast(__m, 'err'); document.getElementById('ua-msg').textContent = __m; return; } 
    markPendingApply(true);
    document.getElementById('ua-pattern').value = '';
    document.getElementById('ua-comment').value = '';
    loadBlockedUATable();
  };

  const listenModeEl = document.getElementById('listen-mode');
  if (listenModeEl) listenModeEl.addEventListener('change', syncListenModeUI);
  document.getElementById('app-cert').addEventListener('change', () => {
    syncPublicationCertificateUI();
    updatePublicationReview();
  });
  document.getElementById('app-security-mode').addEventListener('change', syncSecurityModeHelp);
  document.getElementById('app-cert-mode').addEventListener('change', syncPublicationCertificateCreateFields);
  document.getElementById('btn-app-cert-refresh').onclick = async () => {
    await withBusy(document.getElementById('btn-app-cert-refresh'), loadCertOptionsForApps);
  };
  document.getElementById('btn-app-cert-create-toggle').onclick = () => {
    const button = document.getElementById('btn-app-cert-create-toggle');
    const panel = document.getElementById('app-cert-create-panel');
    const opening = panel.classList.contains('hidden');
    panel.classList.toggle('hidden', !opening);
    button.setAttribute('aria-expanded', String(opening));
    if (opening) {
      const domain = document.getElementById('app-cert-domain');
      if (!domain.value.trim()) domain.value = document.getElementById('host').value.trim().toLowerCase();
      domain.focus();
    }
  };
  document.getElementById('btn-app-cert-create').onclick = async () => {
    await withBusy(document.getElementById('btn-app-cert-create'), createPublicationCertificate);
  };
  document.getElementById('btn-app-review').onclick = reviewPublicationDraft;
  for (const id of ['name', 'host', 'backend', 'port']) {
    document.getElementById(id).addEventListener('input', () => {
      if (id === 'host') {
        const domain = document.getElementById('app-cert-domain');
        if (!domain.dataset.edited) domain.value = document.getElementById('host').value.trim().toLowerCase();
      }
      updatePublicationReview();
    });
  }
  document.getElementById('app-cert-domain').addEventListener('input', (event) => { event.currentTarget.dataset.edited = 'true'; });

  document.getElementById('save').onclick = async () => {
    const saveBtn = document.getElementById('save');
    await withBusy(saveBtn, async () => {
      const edit = document.getElementById('app-edit-id');
      const editId = edit.value.trim();
      if (editId && !edit.dataset.updatedAt) {
        showPublicationErrors({}, 'Open the publication from the list to load its current settings before saving.');
        return;
      }
      const draft = readPublicationBasics();
      const basicsErrors = validatePublicationBasics(draft, selectedPublicationCertificate());
      if (Object.keys(basicsErrors).length) {
        showPublicationErrors(basicsErrors);
        return;
      }
      let backendServers;
      try {
        backendServers = parseBackendServers(document.getElementById('backend-servers').value);
      } catch (e) {
        showPublicationErrors({}, e.message + ' Nothing has been submitted.');
        return;
      }
      const body = {
        name: draft.name,
        public_host: draft.public_host,
        backend_host: draft.backend_host,
        backend_port: draft.backend_port,
        backend_servers: backendServers,
        backend_balance: document.getElementById('backend-balance').value,
        forward_auth_url: document.getElementById('app-fwd-auth').value.trim(),
        forward_auth_bypass_cidrs: document.getElementById('app-fwd-auth-bypass').value.split(/[\s,]+/).filter(Boolean),
        backend_https: document.getElementById('behttps').checked,
        websocket: document.getElementById('ws').checked,
        profile: document.getElementById('profile').value,
        listen_mode: draft.listen_mode,
        certificate_id: draft.certificate_id,
        restricted_paths: collectRestrictedPaths()
      };
      const healthPath = document.getElementById('app-health-path');
      const checkPath = healthPath.value.trim();
      if (!editId || checkPath !== healthPath.defaultValue.trim()) body.health_path = checkPath;
      const maintenance = document.getElementById('app-maint');
      if (!editId || maintenance.checked !== maintenance.defaultChecked) body.maintenance = maintenance.checked;
      const bypass = document.getElementById('app-maint-bypass');
      const cidrs = bypass.value.split(/[\s,]+/).filter(Boolean);
      const savedCIDRs = bypass.defaultValue.split(/[\s,]+/).filter(Boolean);
      if (!editId || cidrs.join(',') !== savedCIDRs.join(',')) body.maintenance_bypass_cidrs = cidrs;
      const pathPolicy = collectPathPolicy();
      if (pathPolicy) body.path_policy = pathPolicy;
      body.policy_rules = collectPublicationRules();
      if (editId) {
        body.id = editId;
        body.expected_updated_at = edit.dataset.updatedAt;
        const prev = appsListCache.find((x) => x.id === editId);
        if (prev && prev.security) body.security = prev.security;
      } else {
        body.enabled = true;
      }
      const selectedMode = document.getElementById('app-security-mode').value || 'balanced';
      body.security = securityForPublication(selectedMode, body.security);
      body.security = withBodyPolicy(body.security);
      if (selectedMode === 'reverse-proxy-only') {
        const accepted = await confirmDialog(
          'Save "' + body.name + '" as Reverse Proxy Only?\n\nAll WAF-style protection layers are disabled for ' + body.public_host + '. Routing and TLS still apply. You can restore a protection preset by editing the application.',
          { danger: true, okLabel: 'Save without WAF layers' }
        );
        if (!accepted) return;
      }
      clearPublicationErrors();
      let r;
      try {
        r = await fetch('/api/v1/applications', { method: 'POST', headers: hdr(), body: JSON.stringify(body) });
      } catch (_) {
        showPublicationErrors({}, 'Application was not saved because the API is unavailable. Your input is still available.');
        return;
      }
      if (r.ok) {
        await reportApplicationSaved(r, 'Application');
        clearAppFormFields();
        setAppFormCollapsed(true);
        loadApps();
      } else if (r.status === 409) {
        showPublicationErrors({}, 'This publication changed or was deleted. Your draft is still open. Review the current settings before saving.');
        void loadApps().catch(() => {});
      } else {
        const message = await apiMessage(r);
        showPublicationErrors({}, 'Application was not saved: ' + message + '. Your input is still available.');
        toast(message, 'err');
      }
    });
  };

  const HOST_CRITICAL_UNITS = ['easy-waf-api.service', 'haproxy.service', 'postgresql.service'];
  const HOST_SERVICE_ACTIONS = ['start', 'stop', 'restart', 'reload', 'enable', 'disable'];
  const HOST_ROLLBACK_STORAGE_KEY = 'easy-waf.host-rollback-capability.v1';
  let hostRollback = { kind: null, token: null, operationID: null, commitUrl: null, phase: null, timer: null, statusRetry: null, deadline: 0, polling: false, statusUnknown: true, statusWarned: false, expiryNotified: false };

  const HOST_PROTECTED_USERNAMES = ['root', 'easy-waf'];
  const HOST_USERNAME_RE = /^[a-z_][a-z0-9_-]{0,31}$/;

  function sshKeysEditorDialog(username, initialKeys) {
    return modalDialog({
      title: 'SSH keys for ' + String(username || ''),
      message: 'One OpenSSH public key per line (ssh-ed25519, ssh-rsa, …). Empty lines and lines beginning with # are ignored.',
      cancelValue: null,
      wide: true,
      render: ({ content, actions, addFocusable, close }) => {
        const label = document.createElement('label');
        label.setAttribute('for', 'ssh-keys-editor');
        label.textContent = 'Public keys';
        const ta = document.createElement('textarea');
        ta.id = 'ssh-keys-editor';
        ta.rows = 10;
        ta.style.width = '100%';
        ta.style.fontFamily = 'ui-monospace, monospace';
        ta.style.fontSize = '12px';
        ta.value = Array.isArray(initialKeys) ? initialKeys.join('\n') : '';
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'secondary';
        cancel.textContent = 'Cancel';
        const save = document.createElement('button');
        save.type = 'button';
        save.textContent = 'Save keys';
        cancel.onclick = () => close(null);
        save.onclick = () => {
          const keys = ta.value.split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
          close(keys);
        };
        content.appendChild(label);
        content.appendChild(ta);
        actions.appendChild(cancel);
        actions.appendChild(save);
        addFocusable(ta);
        addFocusable(cancel);
        addFocusable(save);
        return ta;
      }
    });
  }

  async function loadUsersTable() {
    const box = document.getElementById('users-table');
    if (!box) return;
    tableState(box, 'loading');
    const r = await fetch('/api/v1/host/users', { headers: hdr() });
    if (!r.ok) {
      tableState(box, 'error', { message: await apiMessage(r) });
      return;
    }
    const j = await r.json().catch(() => ({}));
    const list = Array.isArray(j.users) ? j.users : [];
    if (!list.length) {
      tableState(box, 'empty', { message: 'No local users found.' });
      return;
    }
    list.sort((a, b) => String(a.username).localeCompare(String(b.username)));
    const rows = list.map((u) => {
      const name = String(u.username || '');
      const keys = Array.isArray(u.ssh_keys) ? u.ssh_keys : [];
      const keyLabel = keys.length ? keys.length + ' key' + (keys.length === 1 ? '' : 's') : '—';
      const protectedUser = HOST_PROTECTED_USERNAMES.includes(name);
      const delBtn = protectedUser
        ? '<span class="dash-note" title="Protected account">—</span>'
        : `<button type="button" class="secondary users-del" data-user="${esc(name)}">Delete</button>`;
      return `<tr>
        <td><code>${esc(name)}</code></td>
        <td>${esc(u.uid || '—')}</td>
        <td><code>${esc(u.home || '—')}</code></td>
        <td><code>${esc(u.shell || '—')}</code></td>
        <td>${esc(keyLabel)}</td>
        <td class="row" style="gap:0.25rem;flex-wrap:wrap">
          <button type="button" class="secondary users-ssh" data-user="${esc(name)}">SSH keys</button>
          ${delBtn}
        </td>
      </tr>`;
    }).join('');
    box.innerHTML = `<table><thead><tr><th>User</th><th>UID</th><th>Home</th><th>Shell</th><th>Keys</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`;
    box.querySelectorAll('.users-ssh').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, () => editUserSSHKeys(btn.getAttribute('data-user')));
    });
    box.querySelectorAll('.users-del').forEach((btn) => {
      btn.onclick = () => withFocusableBusy(btn, () => deleteHostUser(btn.getAttribute('data-user')));
    });
  }

  async function editUserSSHKeys(username) {
    if (!username) return;
    const r = await fetch('/api/v1/host/users', { headers: hdr() });
    if (!r.ok) {
      toast(await apiMessage(r), 'err');
      return;
    }
    const j = await r.json().catch(() => ({}));
    const list = Array.isArray(j.users) ? j.users : [];
    const ac = list.find((u) => u.username === username);
    const keys = ac && Array.isArray(ac.ssh_keys) ? ac.ssh_keys : [];
    const newKeys = await sshKeysEditorDialog(username, keys);
    if (newKeys === null) return;
    const msg = document.getElementById('users-msg');
    const put = await fetch('/api/v1/host/users/' + encodeURIComponent(username) + '/ssh-keys', {
      method: 'PUT',
      headers: hdr(),
      body: JSON.stringify({ keys: newKeys })
    });
    if (!put.ok) {
      const err = await apiMessage(put);
      toast(err, 'err');
      if (msg) {
        msg.textContent = err;
        msg.className = 'warn';
      }
      return;
    }
    toast('SSH keys updated for ' + username, 'ok');
    if (msg) {
      msg.textContent = 'SSH keys saved for ' + username + '.';
      msg.className = 'ok';
    }
    await loadUsersTable();
  }

  async function deleteHostUser(username) {
    if (!username || HOST_PROTECTED_USERNAMES.includes(username)) return;
    const ok = await confirmDialog(
      'Delete local user ' + username + '?\n\nTheir SSH access ends and the home directory is removed. Recreate the account and restore its files from backup to recover it.',
      { title: 'Delete local user and home', danger: true, okLabel: 'Delete user' }
    );
    if (!ok) return;
    const msg = document.getElementById('users-msg');
    const r = await fetch('/api/v1/host/users/' + encodeURIComponent(username), {
      method: 'DELETE',
      headers: hdr()
    });
    if (!r.ok) {
      const err = await apiMessage(r);
      toast(err, 'err');
      if (msg) {
        msg.textContent = err;
        msg.className = 'warn';
      }
      return;
    }
    toast('User ' + username + ' deleted', 'ok');
    if (msg) {
      msg.textContent = 'User ' + username + ' deleted.';
      msg.className = 'ok';
    }
    await loadUsersTable();
  }

  function loadUsersTab() {
    void loadUsersTable();
  }

  document.getElementById('btn-users-refresh').onclick = () => loadUsersTable();

  document.getElementById('btn-users-create').onclick = async () => {
    const input = document.getElementById('users-new-name');
    const msg = document.getElementById('users-msg');
    const name = (input && input.value ? input.value : '').trim().toLowerCase();
    if (!HOST_USERNAME_RE.test(name)) {
      toast('Invalid username (use lowercase letters, digits, _ - ; start with letter or _)', 'err');
      if (msg) {
        msg.textContent = 'Invalid username.';
        msg.className = 'warn';
      }
      return;
    }
    if (HOST_PROTECTED_USERNAMES.includes(name)) {
      toast('That username is reserved', 'err');
      return;
    }
    const ok = await confirmDialog('Create local user ' + name + '?', { okLabel: 'Create' });
    if (!ok) return;
    await withBusy(document.getElementById('btn-users-create'), async () => {
      const r = await fetch('/api/v1/host/users', {
        method: 'POST',
        headers: hdr(),
        body: JSON.stringify({ username: name })
      });
      if (!r.ok) {
        const err = await apiMessage(r);
        toast(err, 'err');
        if (msg) {
          msg.textContent = err;
          msg.className = 'warn';
        }
        return;
      }
      if (input) input.value = '';
      toast('User ' + name + ' created', 'ok');
      if (msg) {
        msg.textContent = 'User ' + name + ' created.';
        msg.className = 'ok';
      }
      await loadUsersTable();
    });
  };

  function updateHostRollbackApplyButtons() {
    const np = document.getElementById('btn-net-netplan-apply');
    const fw = document.getElementById('btn-net-firewall-apply');
    const busy = !!hostRollback.kind || hostRollback.statusUnknown;
    if (np) np.disabled = busy;
    if (fw) fw.disabled = busy;
  }

  function readHostRollbackCapability() {
    try {
      const value = JSON.parse(sessionStorage.getItem(HOST_ROLLBACK_STORAGE_KEY) || 'null');
      if (!value || !value.kind || !value.token || !value.operation_id || !value.expires_at || !value.commit_url) return null;
      return value;
    } catch (_) {
      return null;
    }
  }

  function saveHostRollbackCapability(value) {
    try { sessionStorage.setItem(HOST_ROLLBACK_STORAGE_KEY, JSON.stringify(value)); } catch (_) { /* browser storage unavailable */ }
  }

  function clearHostRollbackCapability() {
    try { sessionStorage.removeItem(HOST_ROLLBACK_STORAGE_KEY); } catch (_) { /* browser storage unavailable */ }
  }

  function hideHostRollbackBanner(clearCapability = false) {
    const banner = document.getElementById('host-rollback-banner');
    if (banner) banner.classList.add('hidden');
    if (hostRollback.timer) {
      clearInterval(hostRollback.timer);
      hostRollback.timer = null;
    }
    hostRollback.kind = null;
    hostRollback.token = null;
    hostRollback.operationID = null;
    hostRollback.commitUrl = null;
    hostRollback.phase = null;
    hostRollback.deadline = 0;
    if (clearCapability) {
      hostRollback.expiryNotified = false;
      clearHostRollbackCapability();
    }
    updateHostRollbackApplyButtons();
  }

  function showHostRollbackBanner(change, capability = null) {
    const previousOperationID = hostRollback.operationID;
    hideHostRollbackBanner(false);
    hostRollback.kind = change.kind;
    hostRollback.operationID = change.operation_id || null;
    if (previousOperationID !== hostRollback.operationID) hostRollback.expiryNotified = false;
    hostRollback.phase = change.phase || 'pending';
    hostRollback.deadline = change.expires_at ? new Date(change.expires_at).getTime() : 0;
    const ownsCapability = !!(capability && capability.operation_id === hostRollback.operationID && capability.kind === hostRollback.kind);
    hostRollback.token = ownsCapability && change.confirmable ? capability.token : null;
    hostRollback.commitUrl = ownsCapability && change.confirmable ? capability.commit_url : null;
    const banner = document.getElementById('host-rollback-banner');
    const title = document.getElementById('host-rollback-title');
    const message = document.getElementById('host-rollback-message');
    const keep = document.getElementById('btn-host-rollback-keep');
    if (banner) banner.classList.remove('hidden');
    if (keep) keep.classList.toggle('hidden', !hostRollback.token);
    updateHostRollbackApplyButtons();
    const tick = () => {
      const labelText = hostRollback.kind === 'netplan' ? 'Netplan' : 'Firewall';
      const extra = Number(change.total) > 1 ? ' (' + (Number(change.total) - 1) + ' other change also active)' : '';
      const capabilityHint = !hostRollback.token ? ' Confirmation is available only in the tab that started the change.' : '';
      if (hostRollback.phase === 'pending') {
        if (title) title.textContent = 'Safety window active';
        if (Number.isFinite(hostRollback.deadline) && hostRollback.deadline > 0) {
          const left = Math.max(0, Math.ceil((hostRollback.deadline - Date.now()) / 1000));
          if (message) {
            message.textContent = labelText + ' will auto-revert in ' + left + 's unless it is confirmed.' + capabilityHint + extra;
          }
          if (left <= 0) {
            hostRollback.phase = 'expired';
            hostRollback.token = null;
            hostRollback.commitUrl = null;
            clearHostRollbackCapability();
            if (keep) keep.classList.add('hidden');
            if (title) title.textContent = 'Safety window expired';
            if (message) message.textContent = labelText + ' rollback is being verified…' + extra;
            if (!hostRollback.expiryNotified) {
              hostRollback.expiryNotified = true;
              toast('Safety window expired — verifying the server-confirmed rollback state.', 'warn', 12000);
            }
          }
        } else {
          if (title) title.textContent = 'Safety window active';
          if (message) message.textContent = labelText + ' has a pending legacy safety change; the server has no persisted countdown.' + extra;
        }
      } else {
        if (title) title.textContent = hostRollback.phase === 'reverting' ? 'Rollback in progress' : 'Safety window expired';
        if (message) message.textContent = labelText + ' is no longer confirmable; waiting for the server to verify the effective configuration…' + extra;
      }
      if ((hostRollback.phase !== 'pending' || hostRollback.deadline <= 0) && !hostRollback.polling) {
        void refreshHostRollbackStatus(true);
      }
    };
    tick();
    hostRollback.timer = setInterval(tick, 1500);
    return hostRollback.phase === 'pending' && Number.isFinite(hostRollback.deadline) && hostRollback.deadline > Date.now();
  }

  async function refreshHostRollbackStatus(reloadOnSettled = false) {
    if (hostRollback.polling) return;
    clearTimeout(hostRollback.statusRetry);
    hostRollback.statusRetry = null;
    hostRollback.polling = true;
    hostRollback.statusUnknown = true;
    updateHostRollbackApplyButtons();
    try {
      const r = await fetch('/api/v1/host/changes/pending', { headers: hdr(), cache: 'no-store' });
      if (r.status === 503 && r.headers.get('Retry-After') === '1') {
        hostRollback.statusRetry = setTimeout(() => void refreshHostRollbackStatus(reloadOnSettled), 1000);
        return;
      }
      if (!r.ok) throw new Error(await apiMessage(r));
      const payload = await r.json();
      if (!payload || !Array.isArray(payload.changes)) throw new Error('Invalid rollback status response');
      const changes = payload.changes;
      hostRollback.statusUnknown = false;
      hostRollback.statusWarned = false;
      if (changes.length === 0) {
        const settledKind = hostRollback.kind;
        hideHostRollbackBanner(true);
        if (settledKind && reloadOnSettled) {
          await Promise.all([
            loadNetworkTab({ skipRollbackStatus: true }),
            refreshZabbixFirewallAfterSettlement(settledKind)
          ]);
        }
        return;
      }
      let capability = readHostRollbackCapability();
      let change = capability ? changes.find((item) => item.operation_id === capability.operation_id && item.kind === capability.kind) : null;
      if (!change && capability) {
        clearHostRollbackCapability();
        capability = null;
      }
      if (!change) {
        change = [...changes].sort((a, b) => {
          if (a.phase !== b.phase) return a.phase === 'pending' ? 1 : -1;
          const aTime = a.expires_at ? new Date(a.expires_at).getTime() : Number.POSITIVE_INFINITY;
          const bTime = b.expires_at ? new Date(b.expires_at).getTime() : Number.POSITIVE_INFINITY;
          return aTime - bTime;
        })[0];
      }
      showHostRollbackBanner({ ...change, total: changes.length }, capability);
    } catch (err) {
      if (!hostRollback.statusWarned) {
        hostRollback.statusWarned = true;
        toast('Could not verify the network/firewall safety state. Refresh after checking connectivity.', 'err', 12000);
      }
    } finally {
      hostRollback.polling = false;
      updateHostRollbackApplyButtons();
    }
  }

  function refreshZabbixFirewallAfterSettlement(kind) {
    if (kind === 'firewall' && document.getElementById('tab-settings').classList.contains('active')) {
      return loadZabbixFirewallStatus();
    }
  }

  document.getElementById('btn-host-rollback-keep').onclick = async () => {
    if (!hostRollback.token || !hostRollback.commitUrl) return;
    const r = await fetch(hostRollback.commitUrl, {
      method: 'POST',
      headers: hdr(),
      body: JSON.stringify({ token: hostRollback.token })
    });
    if (!r.ok) {
      toast(await apiMessage(r), 'err');
      await refreshHostRollbackStatus(true);
      return;
    }
    toast('Changes kept.', 'ok');
    const settledKind = hostRollback.kind;
    hideHostRollbackBanner(true);
    await Promise.all([loadNetworkTab(), refreshZabbixFirewallAfterSettlement(settledKind)]);
  };

  async function applyHostWithRollback(opts) {
    const netplan = opts.kind === 'netplan';
    const name = netplan ? 'Netplan configuration' : 'firewall rules';
    const preview = netplan ? opts.body.yaml : opts.body.ruleset;
    if (!preview.trim()) {
      opts.msgEl.textContent = 'Enter the ' + name + ' before applying.';
      return;
    }
    const ok = await confirmDialog(
      'Review the replacement configuration below. Applying it can interrupt access. Reconnect and select Keep changes within 90 seconds or the appliance will roll back.',
      { title: 'Review ' + name, preview, danger: true, okLabel: 'Apply ' + name }
    );
    if (!ok || hostRollback.kind || hostRollback.statusUnknown) return;
    const r = await fetch(opts.applyUrl, {
      method: 'POST',
      headers: hdr(),
      body: JSON.stringify(opts.body)
    });
    if (!r.ok) {
      { const __m = await apiMessage(r); toast(__m, 'err'); if (opts.msgEl) opts.msgEl.textContent = __m; }
      return;
    }
    const editor = document.getElementById(netplan ? 'net-netplan-yaml' : 'net-firewall-rules');
    if (editor) editor.defaultValue = preview;
    const j = await r.json();
    if (!j || !j.token || !j.operation_id || !j.expires_at) {
      clearHostRollbackCapability();
      if (opts.msgEl) {
        opts.msgEl.textContent = 'Applied, but the confirmation capability could not be verified. Waiting for the server safety rollback.';
        opts.msgEl.className = 'warn';
      }
      toast('Applied, but confirmation cannot be verified. Waiting for the safety rollback.', 'err', 12000);
      await refreshHostRollbackStatus(true);
      return;
    }
    const capability = {
      kind: opts.kind,
      token: j.token,
      operation_id: j.operation_id,
      expires_at: j.expires_at,
      commit_url: opts.commitUrl
    };
    saveHostRollbackCapability(capability);
    if (!showHostRollbackBanner({
      kind: opts.kind,
      operation_id: j.operation_id,
      phase: 'pending',
      expires_at: j.expires_at,
      confirmable: true,
      total: 1
    }, capability)) {
      if (opts.msgEl) {
        opts.msgEl.textContent = 'Safety window expired. Verifying the current configuration.';
        opts.msgEl.className = 'warn';
      }
      await refreshHostRollbackStatus(true);
      return;
    }
    await refreshHostRollbackStatus(false);
    toast('Applied — confirm within the safety window.', 'warn', 8000);
    if (opts.msgEl) {
      opts.msgEl.textContent = 'Applied. Click “Keep changes” before the timer ends.';
      opts.msgEl.className = 'ok';
    }
  }

  let mcpConnectionsGeneration = 0;
  async function loadMCPConnections() {
    const generation = ++mcpConnectionsGeneration;
    const viewHash = location.hash;
    const isCurrent = () => generation === mcpConnectionsGeneration && location.hash === viewHash && currentRole === 'admin';
    const help = document.getElementById('mcp-connect-help');
    const endpoint = document.getElementById('mcp-endpoint');
    const copy = document.getElementById('mcp-copy');
    const grants = document.getElementById('mcp-grants');
    const refresh = document.getElementById('mcp-refresh-grants');
    const consent = document.getElementById('mcp-consent');
    consent.hidden = true;
    refresh.hidden = true;
    copy.hidden = true;
    endpoint.textContent = '';
    grants.replaceChildren();
    if (location.protocol !== 'https:') {
      help.textContent = 'Open the panel over trusted HTTPS to connect a Gateway.';
      return;
    }
    if (currentRole === 'viewer') {
      help.textContent = 'An administrator can approve and revoke diagnostic access.';
      return;
    }
    const path = '/api/v1/integrations/mcp/grants';
    refresh.hidden = false;
    refresh.disabled = true;
    grants.textContent = 'Checking approved connections…';
    try {
      const response = await fetch(path, {headers: hdr(), cache: 'no-store'});
      if (!response.ok) throw new Error();
      const rows = await response.json();
      if (!Array.isArray(rows)) throw new Error();
      if (!isCurrent()) return;
      endpoint.textContent = location.origin + '/mcp';
      copy.dataset.copy = endpoint.textContent;
      copy.hidden = false;
      help.textContent = 'In OpenClaw Settings → MCP, add this address, select OAuth and sign in. The Gateway must trust the management HTTPS certificate.';
      grants.textContent = '';
      const query = viewHash.split('?')[1] || '';
      if (query) {
        const params = new URLSearchParams(query);
        document.getElementById('mcp-consent-detail').textContent =
          (params.get('client_name') || 'Client') + ' requests read-only access to diagnostics. Confirm that this callback belongs to your Gateway: ' + params.get('redirect_uri');
        consent.hidden = false;
        const approve = document.getElementById('mcp-approve');
        const deny = document.getElementById('mcp-deny');
        approve.disabled = deny.disabled = false;
        const decide = async action => {
          if (!isCurrent() || approve.disabled || deny.disabled) return;
          approve.disabled = deny.disabled = refresh.disabled = true;
          try {
            const result = await fetch('/api/v1/integrations/mcp/' + action, {method: 'POST', headers: hdr(), body: JSON.stringify({query})});
            if (!result.ok) {
              const message = await apiMessage(result);
              if (isCurrent()) toast(message, 'err');
              return;
            }
            const {redirect} = await result.json();
            if (!redirect) throw new Error();
            if (isCurrent()) location.replace(redirect);
          } catch (_) {
            if (isCurrent()) toast(action === 'deny' ? 'Could not return the denial to the client. Try again.' :
              'Could not confirm approval. Refresh connections before starting sign-in again.', 'warn');
          } finally {
            if (isCurrent()) approve.disabled = deny.disabled = refresh.disabled = false;
          }
        };
        approve.onclick = () => decide('approve');
        deny.onclick = () => decide('deny');
      }
      if (!rows.length) grants.textContent = 'No approved connections.';
      for (const row of rows) {
        const line = document.createElement('p');
        line.append(row.name + ' · Issuer: ' + row.issuer + ' · Callback: ' + row.redirect_uri + ' · Approved by ' + row.approved_by + ' · ' + (row.last_used ? 'Last used ' + formatHostTime(row.last_used) : 'Awaiting first use') + ' ');
        const revoke = document.createElement('button');
        revoke.type = 'button';
        revoke.className = 'secondary';
        revoke.textContent = 'Revoke access';
        revoke.onclick = () => withBusy(revoke, async () => {
          if (!isCurrent()) return;
          try {
            const result = await fetch(path + '/' + encodeURIComponent(row.id), {method: 'DELETE', headers: hdr()});
            if (!isCurrent()) return;
            if (!result.ok) {
              const message = await apiMessage(result);
              if (isCurrent()) toast(message, 'err');
              return;
            }
            toast('Access revoked for ' + row.name + '.', 'ok');
          } catch (_) {
            if (!isCurrent()) return;
            toast('Could not confirm revocation. Checking approved connections again.', 'warn');
          }
          await loadMCPConnections();
        });
        line.append(revoke);
        grants.append(line);
      }
    } catch (_) {
      if (isCurrent()) {
        help.textContent = 'Verify that management HTTPS and MCP diagnostics are configured.';
        grants.textContent = 'Could not load approved connections. Try refreshing.';
      }
    } finally {
      if (isCurrent()) refresh.disabled = false;
    }
  }
  document.getElementById('mcp-refresh-grants').onclick = loadMCPConnections;

  async function loadMCPStatus() {
    const status = document.getElementById('mcp-service-status');
    const refresh = document.getElementById('mcp-refresh');
    if (refresh.disabled) return;
    refresh.disabled = true;
    status.textContent = 'Checking service…';
    try {
      const response = await fetch('/api/v1/integrations/mcp/status', { headers: hdr(), cache: 'no-store' });
      if (!response.ok) throw new Error();
      const { active_state } = await response.json();
      const labels = new Map([
        ['active', 'Running'], ['inactive', 'Stopped'], ['failed', 'Failed'],
        ['activating', 'Starting…'], ['deactivating', 'Stopping…'], ['reloading', 'Reloading…']
      ]);
      status.textContent = labels.get(active_state) || 'Service state unavailable';
    } catch (_) {
      status.textContent = 'Could not check the service. Try refreshing.';
    } finally {
      refresh.disabled = false;
    }
  }
  document.getElementById('mcp-refresh').onclick = loadMCPStatus;

  async function loadSystemTab() {
    void loadHostTimezone();
    void loadBackupStatus();
    await loadSystemServicesTable();
    const aptOut = document.getElementById('sys-apt-output');
    if (aptOut && !aptOut.textContent) aptOut.textContent = 'Click “Check for updates”.';
    void loadHostDiskPanel();
    void tryAttachRunningAptUpgrade();
  }

  let hostTimezoneLoadGeneration = 0;

  let backupStatusGeneration = 0;
  let lastBackupStatus = null;

  function renderBackupStatus() {
    const label = document.getElementById('system-backup-status');
    const status = lastBackupStatus;
    if (!label || !status) return;
    const when = status.finished_at ? ' at ' + formatHostTime(status.finished_at) : '';
    switch (status.state) {
      case 'running': label.textContent = 'Backup service is running.'; break;
      case 'succeeded': label.textContent = 'Last backup service run succeeded' + when + '.'; break;
      case 'failed': label.textContent = 'Last backup service run failed' + when + '. Check the appliance journal.'; break;
      default: label.textContent = 'Backup service result unavailable. Check the appliance journal for earlier runs.';
    }
  }

  async function loadBackupStatus() {
    const generation = ++backupStatusGeneration;
    const label = document.getElementById('system-backup-status');
    lastBackupStatus = null;
    label.textContent = 'Checking the backup service…';
    let result;
    try {
      const response = await fetch('/api/v1/host/backup/status', {headers: hdr(), cache: 'no-store'});
      if (response.ok) result = await response.json();
    } catch (_) { /* Keep the unavailable state on connection failure. */ }
    if (generation !== backupStatusGeneration) return;
    lastBackupStatus = result || {state: 'unavailable'};
    renderBackupStatus();
  }

  async function loadHostTimezone() {
    const select = document.getElementById('system-timezone');
    const save = document.getElementById('btn-sys-timezone-save');
    const status = document.getElementById('system-timezone-status');
    if (save.getAttribute('aria-busy') === 'true') return;
    const generation = ++hostTimezoneLoadGeneration;
    select.disabled = save.disabled = true;
    status.textContent = 'Loading host time zone…';
    try {
      const response = await fetch('/api/v1/host/timezone', {headers: hdr(), cache: 'no-store'});
      if (!response.ok) throw new Error(await apiMessage(response));
      const data = await response.json();
      if (generation !== hostTimezoneLoadGeneration) return;
      const zones = new Set([data.timezone, ...data.available]);
      select.replaceChildren(...Array.from(zones).sort().map(zone => new Option(zone, zone)));
      select.value = data.timezone;
      const supported = setHostTimezone(data.timezone);
      renderBackupStatus();
      select.disabled = save.disabled = false;
      status.textContent = supported ? '' : 'This browser displays panel times in UTC for the selected zone.';
    } catch (err) {
      if (generation === hostTimezoneLoadGeneration) {
        status.textContent = err.message || 'The host time zone could not be loaded.';
      }
    }
  }

  document.getElementById('system-timezone-form').onsubmit = (event) => {
    event.preventDefault();
    const select = document.getElementById('system-timezone');
    const save = document.getElementById('btn-sys-timezone-save');
    if (select.disabled || !select.value) return;
    const status = document.getElementById('system-timezone-status');
    return withFocusableBusy(save, async () => {
      const timezone = select.value;
      select.disabled = true;
      status.textContent = 'Saving host time zone…';
      try {
        const response = await fetch('/api/v1/host/timezone', {
          method: 'PUT', headers: hdr(), body: JSON.stringify({timezone})
        });
        if (!response.ok) throw new Error(await apiMessage(response));
        const data = await response.json();
        if (!Array.from(select.options).some(option => option.value === data.timezone)) {
          select.add(new Option(data.timezone, data.timezone));
        }
        select.value = data.timezone;
        const supported = setHostTimezone(data.timezone);
        renderBackupStatus();
        clearHostJournalSnapshot('Load a new journal snapshot to see times in the updated zone.');
        status.textContent = 'Host time zone set to ' + data.timezone + '.' +
          (supported ? '' : ' This browser displays panel times in UTC for this zone.');
      } catch (err) {
        status.textContent = err.message || 'The host time zone could not be changed.';
      } finally {
        select.disabled = false;
      }
    });
  };

  function formatBytes(n) {
    const x = Number(n);
    if (!Number.isFinite(x) || x < 0) return '0 B';
    if (x < 1024) return x + ' B';
    if (x < 1024 * 1024) return (x / 1024).toFixed(1) + ' KB';
    if (x < 1024 * 1024 * 1024) return (x / (1024 * 1024)).toFixed(1) + ' MB';
    return (x / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  }

  function diskBarClass(pct) {
    if (pct >= 90) return 'err';
    if (pct >= 80) return 'warn';
    return '';
  }

  async function loadHostDiskPanel() {
    const mountsEl = document.getElementById('sys-disk-mounts');
    const reclaimEl = document.getElementById('sys-disk-reclaim');
    const cleanBtn = document.getElementById('btn-sys-apt-clean');
    if (!mountsEl) return;
    const r = await fetch('/api/v1/host/disk', { headers: hdr() });
    if (!r.ok) {
      mountsEl.innerHTML = '<p class="warn">Disk info unavailable.</p>';
      return;
    }
    const j = await r.json().catch(() => ({}));
    const mounts = Array.isArray(j.mounts) ? j.mounts : [];
    mountsEl.innerHTML = mounts.map((m) => {
      const pct = typeof m.used_percent === 'number' ? m.used_percent : 0;
      const used = formatBytes(m.used_bytes);
      const total = formatBytes(m.total_bytes);
      const free = formatBytes(m.free_bytes);
      const barCls = diskBarClass(pct);
      const path = esc(m.path || '/');
      return `<div style="margin-bottom:0.5rem">
        <div style="font-size:13px">Disk ${path}: ${used} used of ${total} (${pct}%) · ${free} free</div>
        <div class="disk-bar-track"><div class="disk-bar-fill ${barCls}" style="width:${Math.min(100, Math.max(0, pct))}%"></div></div>
      </div>`;
    }).join('');
    const hints = [];
    const cache = Number(j.cache_bytes);
    if (Number.isFinite(cache) && cache > 0) {
      hints.push('Package cache: ' + formatBytes(cache));
    }
    const rem = j.removable_count;
    if (typeof rem === 'number' && rem > 0) {
      hints.push('Removable packages: ' + rem);
    }
    if (reclaimEl) reclaimEl.textContent = hints.join(' · ');
    if (cleanBtn) {
      aptCacheSmall = !Number.isFinite(cache) || cache < 1024 * 1024;
      cleanBtn.disabled = !!aptInteraction || aptCacheSmall;
      cleanBtn.title = aptCacheSmall ? 'Package cache is already small' : 'Remove downloaded .deb files from /var/cache/apt/archives';
    }
  }

  let aptStatusRevision = 0;
  let aptInteraction = null;
  let aptCacheSmall = false;

  function invalidateAptStatus() {
    aptStatusRevision++;
  }

  function beginAptInteraction() {
    if (aptInteraction) return null;
    const owner = {};
    aptInteraction = owner;
    setAptButtonsDisabled(true);
    return owner;
  }

  function endAptInteraction(owner) {
    if (aptInteraction !== owner) return;
    aptInteraction = null;
    setAptButtonsDisabled(false);
  }

  async function tryAttachRunningAptUpgrade() {
    if (!getTok() || aptInteraction) return;
    const revision = ++aptStatusRevision;
    const msg = document.getElementById('sys-apt-msg');
    const initialText = msg && msg.textContent;
    const isCurrent = () => revision === aptStatusRevision && (!msg || msg.textContent === initialText);
    const statusNotice = (text) => {
      if (msg && isCurrent()) {
        msg.textContent = text;
        msg.className = 'warn';
        msg.dataset.aptStatusText = text;
      }
    };
    let j;
    try {
      const st = await fetch('/api/v1/host/updates/upgrade/status', { headers: hdr(), cache: 'no-store' });
      if (!st.ok) throw new Error('Status request failed');
      j = await st.json();
      if (!j || typeof j !== 'object' || Array.isArray(j) ||
          !Object.prototype.hasOwnProperty.call(j, 'active') || typeof j.active !== 'boolean' ||
          ['error', 'action', 'run_id'].some(key => j[key] !== undefined && typeof j[key] !== 'string') ||
          (j.stream !== undefined && typeof j.stream !== 'boolean') ||
          (j.exit_code !== undefined && !Number.isSafeInteger(j.exit_code))) {
        throw new Error('Invalid package status');
      }
    } catch (_) {
      statusNotice('Cannot verify package status. Refresh status or check the saved package log.');
      return;
    }
    // A delayed poll must not replace a message from a newer user action.
    if (!isCurrent() || aptInteraction) return;
    if (!j.active) {
      const outcome = j.error || (j.exit_code === -1
        ? 'Previous package outcome is unavailable. Check the saved package log.'
        : (j.exit_code !== undefined && j.exit_code !== 0
          ? 'Previous package operation exited with code ' + j.exit_code + '. Check the saved package log.'
          : ''));
      const ownsNotice = msg && msg.dataset.aptStatusText !== undefined && msg.textContent === msg.dataset.aptStatusText;
      if (msg && (ownsNotice || (!msg.textContent && outcome))) {
        msg.textContent = outcome;
        msg.className = outcome ? 'warn' : '';
        if (outcome) msg.dataset.aptStatusText = outcome;
        else delete msg.dataset.aptStatusText;
      } else if (msg) {
        delete msg.dataset.aptStatusText;
      }
      return;
    }
    if (j.error) {
      statusNotice(j.error);
      return;
    }
    if (typeof j.run_id !== 'string' || !/^[a-f0-9]{32}$/.test(j.run_id)) {
      statusNotice('Automatic reconnect is unavailable. Check the saved package log.');
      return;
    }
    if (msg) {
      msg.textContent = 'Following package operation…';
      msg.className = 'warn';
      delete msg.dataset.aptStatusText;
    }
    await runAptStream('/api/v1/host/updates/attach/stream?run_id=' + encodeURIComponent(j.run_id), {
      reconnect: true,
      successMsg: 'Package operation finished.',
      successToast: 'Package operation complete'
    });
  }

  async function loadSystemServicesTable() {
    const box = document.getElementById('sys-services-table');
    if (!box) return;
    tableState(box, 'loading');
    const r = await fetch('/api/v1/host/services', { headers: hdr() });
    if (!r.ok) {
      tableState(box, 'error', { message: await apiMessage(r) });
      return;
    }
    const j = await r.json();
    const list = Array.isArray(j.services) ? j.services : [];
    if (!list.length) {
      tableState(box, 'empty', { message: 'No services.' });
      return;
    }
    const actionBtns = (unit) => HOST_SERVICE_ACTIONS.map((act) =>
      `<button type="button" class="secondary sys-svc-act" data-unit="${esc(unit)}" data-action="${esc(act)}">${esc(act)}</button>`
    ).join(' ');
    const rows = list.map((s) => `<tr>
      <td><code>${esc(s.unit)}</code></td>
      <td>${esc(s.active_state || '—')}</td>
      <td>${esc(s.enabled_state || '—')}</td>
      <td class="row" style="gap:0.25rem;flex-wrap:wrap">${actionBtns(s.unit)}</td>
    </tr>`).join('');
    box.innerHTML = `<table><thead><tr><th>Unit</th><th>Active</th><th>Enabled</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`;
    box.querySelectorAll('.sys-svc-act').forEach((btn) => {
      btn.onclick = () => withBusy(btn, () => runHostServiceAction(btn.getAttribute('data-unit'), btn.getAttribute('data-action')));
    });
  }

  async function runHostServiceAction(unit, action) {
    let msg = `Run ${action} on ${unit}?`;
    let danger = false;
    if (HOST_CRITICAL_UNITS.includes(unit) && (action === 'stop' || action === 'disable')) {
      danger = true;
      msg = `Stopping or disabling ${unit} may take down the management UI or published traffic. Continue?`;
    } else if (action === 'stop' || action === 'disable' || action === 'restart' || action === 'reload') {
      danger = true;
      msg = `${action} ${unit}?`;
    }
    const ok = await confirmDialog(msg, danger ? { danger: true, okLabel: action } : {});
    if (!ok) return;
    const r = await fetch(`/api/v1/host/services/${encodeURIComponent(unit)}/${encodeURIComponent(action)}`, {
      method: 'POST',
      headers: hdr(),
      body: '{}'
    });
    if (!r.ok) {
      toast(await apiMessage(r), 'err');
      return;
    }
    toast(`${unit}: ${action} OK`, 'ok');
    await loadSystemServicesTable();
  }

  document.getElementById('btn-sys-services-refresh').onclick = () => loadSystemServicesTable();

  document.getElementById('btn-sys-apt-check').onclick = async () => {
    const owner = beginAptInteraction();
    if (!owner) return;
    const msg = document.getElementById('sys-apt-msg');
    const out = document.getElementById('sys-apt-output');
    if (msg) msg.textContent = '';
    try {
      await withBusy(document.getElementById('btn-sys-apt-check'), async () => {
        const u = await fetch('/api/v1/host/updates/update', { method: 'POST', headers: hdr(), body: '{}' });
        if (!u.ok) {
          { const __m = await apiMessage(u); toast(__m, 'err'); if (msg) msg.textContent = __m; }
          return;
        }
        const r = await fetch('/api/v1/host/updates', { headers: hdr() });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) {
          toast(await apiMessage(r), 'err');
          return;
        }
        if (out) out.textContent = j.output || '(no output)';
        if (msg) {
          msg.textContent = 'Package list refreshed.';
          msg.className = 'ok';
        }
        toast('Update check done', 'ok');
      });
    } finally {
      endAptInteraction(owner);
    }
  };

  let aptLogStickBottom = true;

  function appendAptLog(line) {
    const out = document.getElementById('sys-apt-output');
    if (!out) return;
    out.style.display = 'block';
    const atBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 40;
    if (!atBottom) aptLogStickBottom = false;
    const text = out.textContent + (out.textContent ? '\n' : '') + line;
    const limit = 2 * 1024 * 1024; // UTF-16 code units, including the notice.
    if (text.length > limit) {
      const notice = '[Earlier live log output omitted. Check the saved package log.]\n';
      let tail = text.slice(-(limit - notice.length));
      if (/^[\uDC00-\uDFFF]/.test(tail)) tail = tail.slice(1);
      out.textContent = notice + tail;
    } else {
      out.textContent = text;
    }
    if (aptLogStickBottom || atBottom) {
      out.scrollTop = out.scrollHeight;
      aptLogStickBottom = true;
    }
  }

  function setAptButtonsDisabled(disabled) {
    if (disabled) invalidateAptStatus();
    ['btn-sys-apt-check', 'btn-sys-apt-upgrade', 'btn-sys-apt-autoremove', 'btn-sys-apt-clean'].forEach((id) => {
      const b = document.getElementById(id);
      if (b) b.disabled = !!disabled || (id === 'btn-sys-apt-clean' && aptCacheSmall);
    });
  }

  async function refreshAptPackageList() {
    const revision = aptStatusRevision;
    const out = document.getElementById('sys-apt-output');
    const r = await fetch('/api/v1/host/updates', { headers: hdr() });
    if (r.ok) {
      const j = await r.json().catch(() => ({}));
      if (out && j.output && revision === aptStatusRevision) out.textContent = j.output;
    }
  }

  document.getElementById('btn-sys-apt-clear-log').onclick = () => {
    const out = document.getElementById('sys-apt-output');
    if (out) out.textContent = '';
    aptLogStickBottom = true;
  };

  document.getElementById('btn-sys-apt-last-log').onclick = async () => {
    const out = document.getElementById('sys-apt-output');
    const r = await fetch('/api/v1/host/updates/upgrade/log', { headers: hdr() });
    if (!r.ok) {
      toast(await apiMessage(r), 'err');
      return;
    }
    const text = await r.text();
    if (out) {
      out.textContent = text || '(no upgrade log saved yet)';
      out.style.display = 'block';
    }
  };

  async function consumeAptStream(resp, opts) {
    const o = opts || {};
    const msg = document.getElementById('sys-apt-msg');
    const reader = resp.body.getReader();
    const dec = new TextDecoder('utf-8', { fatal: true });
    const recordLimit = 8 * 1024 * 1024; // Original UTF-8 bytes, excluding LF.
    let buf = '';
    let recordBytes = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) throw new Error('Package log ended without a complete exit event.');
        let start = 0;
        while (start < value.length) {
          const nl = value.indexOf(10, start);
          const end = nl < 0 ? value.length : nl;
          recordBytes += end - start;
          if (recordBytes > recordLimit) throw new Error('Package log event exceeds its size limit.');
          buf += dec.decode(value.subarray(start, end), { stream: nl < 0 });
          start = end + 1;
          if (nl < 0) continue;
          const line = buf.trim();
          buf = '';
          recordBytes = 0;
          if (!line) continue;
          let ev;
          try {
            ev = JSON.parse(line);
          } catch (_) {
            throw new Error('Invalid package log JSON event.');
          }
          if (!ev || typeof ev !== 'object' || Array.isArray(ev) ||
              !['line', 'exit'].includes(ev.type) ||
              (ev.data !== undefined && typeof ev.data !== 'string') ||
              (ev.error !== undefined && typeof ev.error !== 'string') ||
              (ev.code !== undefined && !Number.isSafeInteger(ev.code))) {
            throw new Error('Invalid package log event fields.');
          }
          if (ev.type === 'line') {
            if (ev.data !== undefined) {
              if (ev.data.includes('attaching to apt action already in progress') && msg) {
                msg.textContent = 'Reconnected to running apt action…';
                msg.className = 'warn';
              }
              appendAptLog(ev.data);
            }
          } else {
            if (!Number.isSafeInteger(ev.code) || (ev.code === 0 && ev.error)) {
              throw new Error('Invalid package log exit event.');
            }
            const exitErr = ev.error || '';
            if (!o.reconnect) finishAptStream(ev.code, exitErr, o);
            else finishAptStreamReconnect(ev.code, exitErr, o);
            return { exitCode: ev.code, exitErr };
          }
        }
      }
    } finally {
      // Cancel observation only; host package execution is independently owned.
      try { await reader.cancel(); } catch (_) { /* already errored/closed */ }
      reader.releaseLock();
    }
  }

  function finishAptStream(exitCode, exitErr, opts) {
    const o = opts || {};
    const msg = document.getElementById('sys-apt-msg');
    const successMsg = o.successMsg || 'Finished.';
    const successToast = o.successToast || 'Complete';
    if (exitCode === 0) {
      if (msg) {
        msg.textContent = successMsg;
        msg.className = 'ok';
      }
      toast(successToast, 'ok');
    } else if (exitCode === -1 && exitErr) {
      if (msg) {
        msg.textContent = exitErr;
        msg.className = 'warn';
      }
      toast(exitErr, 'warn', 8000);
    } else {
      const detail = exitErr || ('apt exit code ' + exitCode);
      if (msg) {
        msg.textContent = detail;
        msg.className = 'warn';
      }
      toast(detail, 'err', 10000);
    }
    void refreshAptPackageList();
  }

  function finishAptStreamReconnect(exitCode, exitErr, opts) {
    const o = opts || {};
    const msg = document.getElementById('sys-apt-msg');
    const successMsg = o.successMsg || 'Finished.';
    const successToast = o.successToast || 'Complete';
    if (exitCode === 0) {
      if (msg) {
        msg.textContent = successMsg;
        msg.className = 'ok';
      }
      toast(successToast, 'ok');
    } else {
      const detail = exitErr || (exitCode === -1
        ? 'Package outcome is unavailable. Check the saved package log.'
        : 'apt exit code ' + exitCode);
      if (msg) {
        msg.textContent = detail;
        msg.className = 'warn';
      }
      toast(detail, exitCode === -1 ? 'warn' : 'err', 8000);
    }
    void refreshAptPackageList();
  }

  async function runAptStream(streamUrl, opts) {
    const owner = beginAptInteraction();
    if (!owner) return { exitCode: -1, exitErr: 'Another package interaction is already in progress.' };
    const o = opts || {};
    const msg = document.getElementById('sys-apt-msg');
    const out = document.getElementById('sys-apt-output');
    aptLogStickBottom = true;
    if (out && !o.reconnect) {
      out.textContent = '';
      out.style.display = 'block';
    }
    if (msg && o.startMsg) {
      msg.textContent = o.startMsg;
      msg.className = 'warn';
    }
    try {
      const resp = await fetch(streamUrl, {
        method: 'POST',
        headers: hdr({ Accept: 'application/x-ndjson' }),
        credentials: 'same-origin',
        body: '{}'
      });
      if (!resp.ok || !resp.body) {
        const detail = await apiMessage(resp);
        if (msg) {
          msg.textContent = detail;
          msg.className = 'warn';
        }
        if (!o.reconnect) toast(detail, 'err');
        return { exitCode: -1, exitErr: detail };
      }
      return await consumeAptStream(resp, o);
    } catch (e) {
      const transport = e && e.message ? e.message : 'network error';
      if (o.reconnect) {
        if (msg) {
          msg.textContent = 'Package log connection interrupted. Refresh status to reconnect.';
          msg.className = 'warn';
        }
        return { exitCode: -1, exitErr: transport };
      }
      if (msg) {
        msg.textContent =
          'Stream interrupted — apt may still be running on the host. Reopen System tab or retry to re-attach.';
        msg.className = 'warn';
      }
      toast('Stream interrupted: ' + transport, 'warn', 10000);
      void refreshAptPackageList();
      return { exitCode: -1, exitErr: transport };
    } finally {
      endAptInteraction(owner);
    }
  }

  document.getElementById('btn-sys-apt-clean').onclick = async () => {
    const owner = beginAptInteraction();
    if (!owner) return;
    const msg = document.getElementById('sys-apt-msg');
    if (msg) {
      msg.textContent = 'Cleaning cache…';
      msg.className = 'warn';
    }
    try {
      const r = await fetch('/api/v1/host/updates/clean', {
        method: 'POST',
        headers: hdr(),
        body: '{}'
      });
      if (!r.ok) {
        { const __m = await apiMessage(r); toast(__m, 'err'); if (msg) msg.textContent = __m; }
        return;
      }
      const j = await r.json().catch(() => ({}));
      const freed = Number(j.freed_bytes);
      toast('Freed ' + formatBytes(Number.isFinite(freed) ? freed : 0), 'ok');
      if (msg) {
        msg.textContent = 'Apt cache cleaned.';
        msg.className = 'ok';
      }
      await loadHostDiskPanel();
    } finally {
      endAptInteraction(owner);
    }
  };

  document.getElementById('btn-sys-apt-upgrade').onclick = async () => {
    const ok = await confirmDialog(
      'Upgrading packages may restart services. Run now?',
      { danger: true, okLabel: 'Upgrade' }
    );
    if (!ok) return;
    await runAptStream('/api/v1/host/updates/upgrade/stream', {
      startMsg: 'Upgrade running…',
      successMsg: 'Upgrade finished.',
      successToast: 'Upgrade complete'
    });
  };

  document.getElementById('btn-sys-apt-autoremove').onclick = async () => {
    const prev = await fetch('/api/v1/host/updates/autoremove/preview', { headers: hdr() });
    if (!prev.ok) {
      toast(await apiMessage(prev), 'err');
      return;
    }
    const j = await prev.json().catch(() => ({}));
    const pkgs = Array.isArray(j.packages) ? j.packages : [];
    const raw = (j.output || '').trim();
    const nothing =
      pkgs.length === 0 &&
      (raw === '' ||
        (raw.toLowerCase().includes('0 to remove') && !/\bremv\b/i.test(raw)));
    if (nothing) {
      toast('Nothing to clean up', 'ok');
      return;
    }
    let confirmBody = 'The following packages will be removed:\n\n';
    if (pkgs.length) {
      confirmBody += pkgs.join('\n');
    } else {
      confirmBody += raw.length > 4000 ? raw.slice(0, 4000) + '\n…' : raw;
    }
    confirmBody += '\n\nProceed?';
    const ok = await confirmDialog(confirmBody, { danger: true, okLabel: 'Remove' });
    if (!ok) return;
    await runAptStream('/api/v1/host/updates/autoremove/stream', {
      startMsg: 'Cleaning up…',
      successMsg: 'Cleanup finished.',
      successToast: 'Cleanup complete'
    });
  };

  document.getElementById('btn-sys-reboot').onclick = async () => {
    const ok = await confirmDialog(
      'The appliance will reboot. Management UI will be unavailable during boot. Continue?',
      { danger: true, okLabel: 'Reboot' }
    );
    if (!ok) return;
    await withBusy(document.getElementById('btn-sys-reboot'), async () => {
      const r = await fetch('/api/v1/host/power/reboot', { method: 'POST', headers: hdr(), body: '{}' });
      if (!r.ok) toast(await apiMessage(r), 'err');
      else toast('Rebooting…', 'warn', 10000);
    });
  };

  document.getElementById('btn-sys-shutdown').onclick = async () => {
    const ok = await confirmDialog(
      'The appliance will power off. Physical or hypervisor access is required to turn it back on. Continue?',
      { danger: true, okLabel: 'Shutdown' }
    );
    if (!ok) return;
    await withBusy(document.getElementById('btn-sys-shutdown'), async () => {
      const r = await fetch('/api/v1/host/power/shutdown', { method: 'POST', headers: hdr(), body: '{}' });
      if (!r.ok) toast(await apiMessage(r), 'err');
      else toast('Shutting down…', 'warn', 10000);
    });
  };

  function formatNetOverview(ov) {
    const lines = [];
    if (ov.hostname) lines.push('Hostname: ' + ov.hostname);
    if (ov.ntp_synced != null && ov.ntp_synced !== '') lines.push('NTP synchronized: ' + ov.ntp_synced);
    if (Array.isArray(ov.dns) && ov.dns.length) lines.push('DNS: ' + ov.dns.join(', '));
    const links = Array.isArray(ov.links) ? ov.links : [];
    links.forEach((raw) => {
      const l = raw && typeof raw === 'object' ? raw : null;
      if (l && l.ifname) lines.push('Interface ' + l.ifname + ': ' + (l.operstate || l.state || '—'));
    });
    const addrs = Array.isArray(ov.addresses) ? ov.addresses : [];
    addrs.forEach((raw) => {
      try {
        const a = raw && typeof raw === 'object' ? raw : JSON.parse(raw);
        if (a && a.ifname && Array.isArray(a.addr_info)) {
          a.addr_info.forEach((ai) => {
            if (ai.local) lines.push('  ' + a.ifname + ' ' + (ai.family || '') + ' ' + ai.local + '/' + (ai.prefixlen || ''));
          });
        }
      } catch (_) { /* skip */ }
    });
    const routes = Array.isArray(ov.routes) ? ov.routes : [];
    routes.forEach((raw) => {
      try {
        const rt = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (rt && rt.dst !== undefined) {
          lines.push('Route: ' + (rt.dst || 'default') + ' via ' + (rt.gateway || '—') + ' dev ' + (rt.dev || '—'));
        }
      } catch (_) { /* skip */ }
    });
    return lines.length ? lines.join('\n') : '(no overview data)';
  }

  function findEasyWafNetplan(files) {
    return Array.isArray(files) ? files.find(file => file?.path === '/etc/netplan/99-easy-waf.yaml') : undefined;
  }

  let networkLoadGeneration = 0;

  function clearNetworkEditors() {
    networkLoadGeneration++;
    for (const id of ['net-netplan-yaml', 'net-firewall-rules']) {
      const editor = document.getElementById(id);
      editor.value = editor.defaultValue = '';
    }
    for (const id of ['net-overview', 'net-netplan-msg', 'net-netplan-source', 'net-firewall-msg', 'net-firewall-load-status']) {
      document.getElementById(id).textContent = '';
    }
  }

  function refreshNetworkEditor(id, saved, messageId) {
    const editor = document.getElementById(id);
    if (!editor) return;
    const dirty = editor.value !== editor.defaultValue;
    if (!dirty) editor.value = saved;
    if (dirty && editor.value !== saved && editor.defaultValue !== saved) {
      document.getElementById(messageId).textContent = 'The host configuration changed. Your edits are still in the editor. Review them before applying.';
    }
    editor.defaultValue = saved;
  }

  async function loadNetworkTab(options = {}) {
    const generation = ++networkLoadGeneration;
    const ovBox = document.getElementById('net-overview');
    if (ovBox) ovBox.textContent = 'Loading…';
    const pendingTask = options.skipRollbackStatus ? Promise.resolve() : refreshHostRollbackStatus(false);
    const firewallStatus = document.getElementById('net-firewall-load-status');
    async function loadSection(path, label, status, render) {
      try {
        const response = await fetch(path, { headers: hdr(), cache: 'no-store' });
        if (!response.ok) throw new Error(await apiMessage(response));
        const data = await response.json();
        if (generation === networkLoadGeneration) render(data);
      } catch (err) {
        if (generation === networkLoadGeneration) {
          status.textContent = label + ' could not be loaded.' + (err.message ? ' ' + err.message : '');
        }
      }
    }
    await Promise.all([
      loadSection('/api/v1/host/network', 'Network configuration', ovBox, ov => {
        ovBox.textContent = formatNetOverview(ov);
        const file = findEasyWafNetplan(ov.netplan_files);
        const source = document.getElementById('net-netplan-source');
        if (typeof file?.content === 'string' || ov.managed_netplan_state === 'absent') {
          refreshNetworkEditor('net-netplan-yaml', file?.content ?? '', 'net-netplan-msg');
          source.textContent = file ? '' : 'The managed file does not exist yet. Applying creates it.';
        } else {
          source.textContent = 'The current managed file could not be read. Applying will write the editor contents to the managed file.';
        }
      }),
      loadSection('/api/v1/host/firewall', 'Firewall configuration', firewallStatus, fw => {
        if (typeof fw.managed_ruleset !== 'string') {
          firewallStatus.textContent = 'The current managed firewall file could not be read. The editor may show an earlier configuration.';
          return;
        }
        refreshNetworkEditor('net-firewall-rules', fw.managed_ruleset, 'net-firewall-msg');
        firewallStatus.textContent = '';
      }),
      pendingTask
    ]);
    if (generation === networkLoadGeneration) updateHostRollbackApplyButtons();
  }

  document.getElementById('btn-net-netplan-apply').onclick = async () => {
    if (hostRollback.kind || hostRollback.statusUnknown) return;
    const yaml = document.getElementById('net-netplan-yaml').value;
    const msgEl = document.getElementById('net-netplan-msg');
    await applyHostWithRollback({
      kind: 'netplan',
      applyUrl: '/api/v1/host/network/netplan/apply',
      commitUrl: '/api/v1/host/network/netplan/commit',
      body: { yaml, rollback_seconds: 90 },
      msgEl
    });
  };

  document.getElementById('btn-net-firewall-apply').onclick = async () => {
    if (hostRollback.kind || hostRollback.statusUnknown) return;
    const ruleset = document.getElementById('net-firewall-rules').value;
    const msgEl = document.getElementById('net-firewall-msg');
    await applyHostWithRollback({
      kind: 'firewall',
      applyUrl: '/api/v1/host/firewall/apply-rollback',
      commitUrl: '/api/v1/host/firewall/commit',
      body: { ruleset, rollback_seconds: 90 },
      msgEl
    });
  };

  refreshSession();
