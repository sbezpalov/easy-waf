  function statusBadge(label, tone) {
    const safeTone = ['success', 'warning', 'danger', 'info', 'neutral', 'unknown'].includes(tone) ? tone : 'unknown';
    return '<span class="status-badge status-badge-' + safeTone + '">' + esc(label) + '</span>';
  }

  function alertView(tone, title, message) {
    const safeTone = ['success', 'warning', 'danger', 'info', 'unknown'].includes(tone) ? tone : 'unknown';
    return '<div class="alert alert-' + safeTone + '"><strong class="alert-title">' + esc(title) +
      '</strong><p>' + esc(message) + '</p></div>';
  }

  function stateView(state, message) {
    return '<div class="state-view" data-state="' + esc(state || 'unknown') + '">' + esc(message || 'Unavailable') + '</div>';
  }

  function tableState(box, state, opts) {
    if (!box) return;
    const o = opts || {};
    const msg = o.message || (state === 'loading' ? 'Loading…' : state === 'empty' ? 'No data.' : 'Failed to load.');
    if (state === 'loading') {
      box.innerHTML = '<p class="table-state">' + esc(msg) + '</p>';
    } else if (state === 'empty') {
      box.innerHTML = '<p class="table-state dash-note">' + esc(msg) + '</p>';
    } else if (state === 'error') {
      box.innerHTML = '<p class="table-state warn">' + esc(msg) + '</p>';
    }
  }

