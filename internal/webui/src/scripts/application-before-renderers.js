  const TOK = 'easy_waf_token';
  let sessionGeneration = 0;
  let stepUpPrompt = null;
  const getTok = () => sessionStorage.getItem(TOK) || '';
  const setTok = (t) => {
    sessionGeneration++;
    if (stepUpPrompt) {
      stepUpPrompt.controller.abort();
      stepUpPrompt = null;
    }
    if (t) sessionStorage.setItem(TOK, t);
    else {
      sessionStorage.removeItem(TOK);
      mcpConnectionsGeneration++;
      clearNetworkEditors();
      clearManagementTLSForm();
      clearTOTPSecrets();
      clearSettingsDrafts();
    }
  };

  const hdr = (extra) => {
    const t = getTok();
    const h = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    };
    if (t) h['Authorization'] = 'Bearer ' + t;
    if (extra && typeof extra === 'object') Object.assign(h, extra);
    return h;
  };

  let modalSequence = 0;

  function modalDialog(options) {
    const o = options || {};
    return new Promise((resolve) => {
      const previousFocus = document.activeElement;
      const returnFocus = o.returnFocus || previousFocus;
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      const box = document.createElement('div');
      box.className = 'modal-box';
      if (o.wide) box.className += ' modal-box-wide';
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      const title = document.createElement('h2');
      title.id = 'modal-title-' + (++modalSequence);
      title.textContent = o.title || 'Confirm action';
      box.setAttribute('aria-labelledby', title.id);
      const p = document.createElement('p');
      p.className = 'modal-message';
      p.id = title.id + '-description';
      p.textContent = String(o.message || '');
      box.setAttribute('aria-describedby', p.id);
      const content = document.createElement('div');
      const actions = document.createElement('div');
      actions.className = 'modal-actions row';
      const focusables = [];
      const addFocusable = (el) => {
        focusables.push(el);
        return el;
      };
      let closed = false;
      const close = (value) => {
        if (closed) return;
        closed = true;
        if (typeof o.onClose === 'function') o.onClose();
        overlay.remove();
        if (returnFocus && returnFocus.isConnected) returnFocus.focus();
        resolve(value);
      };
      const initialFocus = typeof o.render === 'function'
        ? o.render({ content, actions, addFocusable, close })
        : null;
      overlay.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          e.stopPropagation();
          if (o.dismissible !== false) close(o.cancelValue);
          return;
        }
        if (e.key !== 'Tab') return;
        const available = focusables.filter((el) => el && el.isConnected && !el.disabled);
        if (!available.length) return;
        const first = available[0];
        const last = available[available.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      });
      overlay.onclick = (e) => { if (e.target === overlay && o.dismissible !== false) close(o.cancelValue); };
      box.appendChild(title);
      box.appendChild(p);
      box.appendChild(content);
      box.appendChild(actions);
      overlay.appendChild(box);
      document.body.appendChild(overlay);
      (initialFocus || focusables[0] || box).focus();
    });
  }

  // Resolves to the password, or null when cancelled.
  function passwordDialog(message, signal) {
    let dismiss;
    return modalDialog({
      title: 'Confirm privileged action',
      message,
      cancelValue: null,
      onClose: () => signal?.removeEventListener('abort', dismiss),
      render: ({ content, actions, addFocusable, close }) => {
      dismiss = () => close(null);
      signal?.addEventListener('abort', dismiss, {once: true});
      const form = document.createElement('form');
      form.id = 'step-up-form-' + modalSequence;
      const input = document.createElement('input');
      input.type = 'password';
      input.autocomplete = 'current-password';
      input.required = true;
      input.id = 'step-up-password';
      const label = document.createElement('label');
      label.setAttribute('for', input.id);
      label.textContent = 'Password';
      label.appendChild(input);
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'secondary';
      cancel.textContent = 'Cancel';
      const ok = document.createElement('button');
      ok.type = 'submit';
      ok.setAttribute('form', form.id);
      ok.textContent = 'Confirm';
      cancel.onclick = () => close(null);
      form.onsubmit = (e) => {
        e.preventDefault();
        close(input.value);
      };
      form.appendChild(label);
      content.appendChild(form);
      actions.appendChild(cancel);
      actions.appendChild(ok);
      addFocusable(input);
      addFocusable(cancel);
      addFocusable(ok);
      return input;
      }
    });
  }

  function oneTimeCredentialDialog(username, credential, returnFocus) {
    let secret = String(credential || '');
    let value = null;
    return modalDialog({
      title: 'Temporary password created',
      message: 'Temporary password for "' + String(username || '') + '". It is available only in this dialog and must be changed at first sign-in.',
      cancelValue: false,
      dismissible: false,
      returnFocus,
      onClose: () => {
        if (value) value.textContent = '';
        secret = '';
      },
      render: ({ content, actions, addFocusable, close }) => {
        const credentialBox = document.createElement('div');
        credentialBox.className = 'credential-box';
        const label = document.createElement('strong');
        label.textContent = 'Temporary password';
        value = document.createElement('code');
        value.className = 'credential-value';
        value.textContent = 'Hidden until revealed';
        const status = document.createElement('p');
        status.className = 'dash-note';
        status.setAttribute('role', 'status');
        status.setAttribute('aria-live', 'polite');
        status.textContent = 'Reveal or copy it, store it securely, then acknowledge below.';
        credentialBox.appendChild(label);
        credentialBox.appendChild(value);
        credentialBox.appendChild(status);
        content.appendChild(credentialBox);

        const reveal = document.createElement('button');
        reveal.type = 'button';
        reveal.className = 'secondary';
        reveal.textContent = 'Reveal password';
        reveal.setAttribute('aria-pressed', 'false');
        reveal.onclick = () => {
          const shown = reveal.getAttribute('aria-pressed') === 'true';
          value.textContent = shown ? 'Hidden until revealed' : secret;
          reveal.textContent = shown ? 'Reveal password' : 'Hide password';
          reveal.setAttribute('aria-pressed', shown ? 'false' : 'true');
        };
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'secondary';
        copy.textContent = 'Copy password';
        copy.onclick = async () => {
          try {
            await navigator.clipboard.writeText(secret);
            status.textContent = 'Copied. Store the password securely before closing this dialog.';
          } catch (_) {
            status.textContent = 'Copy failed. Reveal the password and copy it manually.';
          }
        };
        const saved = document.createElement('button');
        saved.type = 'button';
        saved.textContent = 'I saved it';
        saved.onclick = () => close(true);
        actions.appendChild(reveal);
        actions.appendChild(copy);
        actions.appendChild(saved);
        addFocusable(reveal);
        addFocusable(copy);
        addFocusable(saved);
        return reveal;
      }
    });
  }

  const nativeFetch = window.fetch.bind(window);
  let currentRole = '';
  let sessionExpired = false;

  function confirmationFailure(status, error) {
    return Response.json({error}, {status});
  }

  async function promptStepUp(signal) {
    let message = 'This is a privileged operation. Enter your password to continue.';
    for (;;) {
      const password = await passwordDialog(message, signal);
      if (signal.aborted || password === null) return null;
      try {
        const r = await nativeFetch('/api/v1/auth/confirm', {
          method: 'POST', headers: hdr(), body: JSON.stringify({ password }), signal
        });
        const j = await r.json().catch(() => null);
        if (signal.aborted) return null;
        if (r.ok && typeof j?.token === 'string' && j.token) {
          sessionStorage.setItem(TOK, j.token);
          return true;
        }
        if (r.status === 401 && j?.error === 'password incorrect') {
          message = 'Incorrect password. Try again.';
          continue;
        }
        if (r.status === 401) {
          handleSessionExpired();
          return null;
        }
        if (r.status === 429) return confirmationFailure(429, 'Too many attempts. Try again later.');
      } catch (_) {
        if (signal.aborted) return null;
      }
      return confirmationFailure(503, 'Password confirmation unavailable. Retry the operation.');
    }
  }

  // Requests made while the dialog is open wait for the same answer.
  function confirmStepUp() {
    if (!stepUpPrompt) {
      const controller = new AbortController();
      const promise = promptStepUp(controller.signal).finally(() => {
        if (stepUpPrompt?.controller === controller) stepUpPrompt = null;
      });
      stepUpPrompt = {controller, promise};
    }
    return stepUpPrompt.promise;
  }

  function requestMeta(url, init) {
    const raw = url instanceof Request ? url.url : String(url || '');
    let path = raw;
    try { path = new URL(raw, window.location.origin).pathname; } catch (_) { /* relative path */ }
    const method = String((init && init.method) || (url instanceof Request ? url.method : 'GET') || 'GET').toUpperCase();
    return { path, method };
  }

  function isPublicAuthPath(path) {
    return path === '/api/v1/auth/status' || path === '/api/v1/auth/login' || path === '/api/v1/auth/enroll';
  }

  function handleSessionExpired() {
    if (sessionExpired) return;
    sessionExpired = true;
    currentRole = '';
    setTok('');
    document.body.classList.remove('role-viewer');
    stopDashStatsTimer();
    stopAuditRefreshTimer();
    if (typeof clearHostJournalSnapshot === 'function') clearHostJournalSnapshot('Sign in as an administrator to load a journal snapshot.');
    closeMobileNav(false);
    show('view-enroll', false);
    show('view-pass', false);
    show('view-app', false);
    show('view-login', true);
    const err = document.getElementById('login-err');
    if (err) err.textContent = 'Your session expired. Sign in again. No blocked write was submitted.';
    const password = document.getElementById('login-pass');
    if (password) {
      password.value = '';
      password.focus();
    }
  }

  function finalizeAuthenticatedResponse(response, meta, hadToken) {
    if (response.status === 401 && hadToken && !isPublicAuthPath(meta.path)) handleSessionExpired();
    return response;
  }

  // Privileged operations answer 403 step_up_required until the password is
  // confirmed; ask for it once here and repeat the request, so no caller has to know.
  window.fetch = async (url, init) => {
    const meta = requestMeta(url, init);
    const hadToken = !!getTok();
    const generation = sessionGeneration;
    const sessionChanged = () => confirmationFailure(409, 'Session changed. Review the operation before trying again.');
    const readMethod = meta.method === 'GET' || meta.method === 'HEAD' || meta.method === 'OPTIONS';
    const viewerSelfService = meta.path === '/api/v1/auth/logout' || meta.path === '/api/v1/auth/change-password';
    if (currentRole === 'viewer' && !readMethod && !viewerSelfService) {
      return new Response(JSON.stringify({ error: 'read_only' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    const retryInput = url instanceof Request ? url.clone() : url;
    const r = await nativeFetch(url, init);
    if (hadToken && generation !== sessionGeneration) return sessionChanged();
    if (r.status !== 403) return finalizeAuthenticatedResponse(r, meta, hadToken);
    const j = await r.clone().json().catch(() => null);
    if (!hadToken || !j || j.error !== 'step_up_required') {
      return finalizeAuthenticatedResponse(r, meta, hadToken);
    }
    if (generation !== sessionGeneration) return sessionChanged();
    const confirmed = await confirmStepUp();
    if (generation !== sessionGeneration) return sessionChanged();
    if (confirmed !== true) return confirmed ? confirmed.clone() : r;
    const retryHeaders = new Headers((init && init.headers) || (url instanceof Request ? url.headers : undefined));
    retryHeaders.set('Authorization', 'Bearer ' + getTok());
    const retried = await nativeFetch(retryInput, { ...init, headers: retryHeaders });
    if (generation !== sessionGeneration) return sessionChanged();
    return finalizeAuthenticatedResponse(retried, meta, true);
  };

  const HASH_TO_PANEL = {
    '#dashboard': 'dashboard',
    '#apps': 'apps',
    '#certs': 'certs',
    '#security': 'security',
    '#crowdsec': 'crowdsec',
    '#fail2ban': 'fail2ban',
    '#system': 'system',
    '#network': 'network',
    '#users': 'users',
    '#config': 'config',
    '#settings': 'settings',
    '#logs': 'logs',
    '#mcp': 'mcp',
    '#about': 'about'
  };

  function show(el, on) { document.getElementById(el).classList.toggle('hidden', !on); }

  let pendingApply = false;
  let edgeStatusCache = null;

  function toast(message, kind, timeoutMs) {
    const host = document.getElementById('toast-host');
    if (!host) return;
    const variants = {
      ok: { label: 'Success', role: 'status' },
      err: { label: 'Error', role: 'alert' },
      warn: { label: 'Warning', role: 'status' },
      info: { label: 'Information', role: 'status' }
    };
    const k = variants[kind] ? kind : 'info';
    const variant = variants[k];
    const ms = k === 'err' ? 0 : (timeoutMs == null ? 5000 : timeoutMs);
    const el = document.createElement('div');
    el.className = 'toast toast-' + k;
    el.setAttribute('role', variant.role);
    el.setAttribute('aria-label', variant.label + ' notification');
    const body = document.createElement('span');
    body.className = 'toast-body';
    const label = document.createElement('strong');
    label.className = 'toast-label';
    label.textContent = variant.label + ': ';
    const messageText = document.createElement('span');
    messageText.textContent = String(message);
    body.appendChild(label);
    body.appendChild(messageText);
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'toast-close secondary';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.textContent = '×';
    let timer;
    const dismiss = () => {
      if (timer) clearTimeout(timer);
      el.remove();
    };
    closeBtn.onclick = dismiss;
    el.appendChild(body);
    el.appendChild(closeBtn);
    host.appendChild(el);
    if (ms > 0) timer = setTimeout(dismiss, ms);
  }

  async function apiMessage(r) {
    let message = (await r.text().catch(() => '')).trim();
    try {
      const j = JSON.parse(message);
      if (j && typeof j === 'object') {
        if (typeof j.error === 'string' && j.error.trim()) message = j.error.trim();
        else if (typeof j.message === 'string' && j.message.trim()) message = j.message.trim();
      }
    } catch (_) { /* plain text */ }
    if (message === 'step_up_required') return 'Cancelled: this operation needs your password.';
    if (message === 'read_only') return 'Read-only account: ask an admin to make this change.';
    return message || r.statusText || ('HTTP ' + r.status);
  }

  function confirmDialog(message, opts) {
    const o = opts || {};
    return modalDialog({
      title: o.title || 'Confirm action',
      message: String(message),
      wide: typeof o.preview === 'string',
      cancelValue: false,
      render: ({ content, actions, addFocusable, close }) => {
        if (typeof o.preview === 'string') {
          const preview = document.createElement('pre');
          preview.className = 'configuration-preview';
          preview.tabIndex = 0;
          preview.textContent = o.preview;
          content.appendChild(preview);
          addFocusable(preview);
        }
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.className = 'secondary';
        cancel.textContent = 'Cancel';
        const ok = document.createElement('button');
        ok.type = 'button';
        if (o.danger) ok.className = 'modal-ok-danger';
        ok.textContent = o.okLabel || 'OK';
        cancel.onclick = () => close(false);
        ok.onclick = () => close(true);
        actions.appendChild(cancel);
        actions.appendChild(ok);
        addFocusable(cancel);
        addFocusable(ok);
        return o.danger ? cancel : ok;
      }
    });
  }

  function confirmProtectiveRuleChange(action, rawValue) {
    const value = String(rawValue || '');
    const prompts = {
      'blacklist-add': {
        title: 'Blacklist client',
        message: 'Add ' + value + ' to the local IP blacklist?\n\nRequests from this address will be blocked after Apply HAProxy. Remove the entry to restore access.',
        okLabel: 'Add to blacklist'
      },
      'blacklist-delete': {
        title: 'Delete blacklist entry',
        message: 'Delete blacklist entry ' + value + '?\n\nThe CIDR is removed from the local blacklist after Apply HAProxy. Requests blocked only by this entry may be allowed. Add the CIDR again to restore the rule.',
        okLabel: 'Delete entry'
      },
      'allowlist-delete': {
        title: 'Remove trusted allowlist entry',
        message: 'Remove trusted CIDR ' + value + '?\n\nThe CIDR is removed from the trusted allowlist after Apply HAProxy. If the allowlist is enabled, it stops bypassing IP blocklists. Add the CIDR again to restore trusted access.',
        okLabel: 'Remove entry'
      },
      'user-agent-delete': {
        title: 'Delete blocked User-Agent pattern',
        message: 'Delete blocked User-Agent pattern "' + value + '"?\n\nThe pattern is removed after Apply HAProxy. If User-Agent blocking is enabled, matching clients may be allowed. Add the pattern again to restore the rule.',
        okLabel: 'Delete pattern'
      }
    };
    const prompt = prompts[action];
    if (!prompt) return Promise.resolve(false);
    return confirmDialog(prompt.message, { title: prompt.title, danger: true, okLabel: prompt.okLabel });
  }

  async function withBusy(btn, fn) {
    if (!btn) return fn();
    const prevDisabled = btn.disabled;
    const prevText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '… working';
    try {
      return await fn();
    } finally {
      btn.disabled = prevDisabled;
      btn.textContent = prevText;
    }
  }

  async function withFocusableBusy(btn, fn) {
    if (!btn) return fn();
    if (btn.getAttribute('aria-busy') === 'true') return;
    btn.setAttribute('aria-busy', 'true');
    try {
      return await fn();
    } finally {
      btn.removeAttribute('aria-busy');
    }
  }

