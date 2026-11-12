/* Concord local sandbox. Authentication, authorization and signing remain server-side. */
(() => {
  'use strict';

  const root = document.getElementById('app');
  const dialogs = document.getElementById('dialogs');
  const state = { session: null, data: null, app: location.pathname.startsWith('/guardian') ? 'guardian' : 'wallet', page: location.hash.slice(1) || 'overview', filter: 'all', search: '', refreshing: false, error: null };
  const pendingApprovals = new Map();
  const approvalHostAllowed = url => ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
    || (location.hostname.endsWith('.ray') && url.hostname === location.hostname && url.protocol === location.protocol);
  const paths = {
    grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    check: '<path d="m5 12 4 4L19 6"/>', shield: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z"/><path d="m8 12 3 3 5-6"/>',
    bank: '<path d="m3 8 9-5 9 5M3 8h18M5 10v8m5-8v8m4-8v8m5-8v8M3 21h18M3 18h18"/>',
    network: '<rect x="8" y="3" width="8" height="6" rx="1"/><rect x="2" y="15" width="7" height="6" rx="1"/><rect x="15" y="15" width="7" height="6" rx="1"/><path d="M12 9v3H5v3m7-3h7v3"/>',
    activity: '<path d="M3 12h4l3-7 4 14 3-7h4"/>', arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
    send: '<path d="m21 3-7 18-4-7-7-4L21 3ZM10 14 21 3"/>', download: '<path d="M12 3v12m-4-4 4 4 4-4M4 16v4h16v-4"/>',
    upload: '<path d="M12 16V4m-4 4 4-4 4 4M4 16v4h16v-4"/>', users: '<circle cx="9" cy="8" r="3"/><path d="M3 20v-3a6 6 0 0 1 12 0v3m1-16a3 3 0 0 1 0 6m2 4a5 5 0 0 1 3 4v2"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    chevron: '<path d="m9 5 7 7-7 7"/>', close: '<path d="m6 6 12 12M6 18 18 6"/>', plus: '<path d="M12 5v14M5 12h14"/>',
    refresh: '<path d="M20 8a8 8 0 1 0 1 7M20 3v5h-5"/>', logout: '<path d="M9 3H4v18h5m6-14 5 5-5 5m-7-5h12"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
    document: '<path d="M14 3H5v18h14V8l-5-5ZM14 3v5h5M8 12h8m-8 4h5"/>', info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.1"/>',
    wallet: '<path d="M20 8V5H5a2 2 0 0 0 0 4h16v11H5a2 2 0 0 1-2-2V7m18 5h-5v5h5m-3-2.5h.1"/>', copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>', globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>'
  };
  const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.document}</svg>`;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const arr = value => Array.isArray(value) ? value : [];
  const permissions = () => arr(state.session?.permissions);
  const can = name => permissions().includes(name);
  const user = () => state.session?.user || {};
  const operations = () => arr(state.data?.operations);
  const testCurrency = currency => `Test${esc(currency || '')}`;
  const issuer = value => esc(value || 'Sandbox issuer (legal entity undecided)');
  const short = (value, size = 10) => value ? `${String(value).slice(0, size)}${String(value).length > size ? '…' : ''}` : '—';
  const initials = name => (String(name || 'User').split(/\s+/).slice(0, 2).map(part => part[0]).join('')).toUpperCase();
  const human = value => ({ refund: 'Escrow return', bankadmin: 'Bank administrator', bankmaker: 'Bank payment maker', bankapprover: 'Bank payment approver', corporatemaker: 'Corporate payment maker', corporateapprover: 'Corporate payment approver', institutionguardian: 'Institution guardian', payment_failed: 'Bank payout failed', refund_requested: 'Escrow return requested' }[value] || String(value || 'Not available').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase()));
  const number = value => Number.isFinite(Number(value)) ? new Intl.NumberFormat('en-GB').format(Number(value)) : '—';
  function money(value, currency, minor = true) {
    if (value === undefined || value === null || value === '') return '—';
    const numeric = Number(value) / (minor ? 100 : 1);
    return `${Number.isFinite(numeric) ? new Intl.NumberFormat('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(numeric) : esc(value)}${currency ? ` <span>${testCurrency(currency)}</span>` : ''}`;
  }
  const opMoney = operation => money(operation.amount_minor ?? operation.amount, '', operation.amount_minor !== undefined);
  function date(value, full = false) {
    if (!value) return '—';
    const parsed = new Date(typeof value === 'number' && value < 100000000000 ? value * 1000 : value);
    if (Number.isNaN(parsed.getTime())) return esc(value);
    return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', ...(full ? { year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' } : {}) }).format(parsed) + (full ? ' UTC' : '');
  }
  const isPending = operation => !['settled', 'rejected', 'failed', 'cancelled'].includes(operation.state);
  const isException = operation => ['bank_unknown', 'failed', 'payment_failed'].includes(operation.state) || Boolean(operation.error);
  function badge(status, label) {
    const success = ['settled', 'confirmed', 'ready', 'healthy', 'reconciled', 'active', 'success', 'available', 'complete'].includes(status);
    const error = ['rejected', 'failed', 'unavailable', 'unreachable', 'mismatch', 'error'].includes(status);
    const neutral = ['draft', 'not_started', 'not_applicable', 'unconfigured'].includes(status);
    return `<span class="badge ${success ? 'success' : error ? 'error' : neutral ? 'neutral' : 'pending'}"><span class="dot"></span>${esc(label || human(status))}</span>`;
  }
  const button = (action, label, style = '', symbol = '', attrs = '') => `<button type="button" class="button ${style}" data-action="${action}" ${attrs}>${symbol ? icon(symbol) : ''}${esc(label)}</button>`;
  function empty(title, detail, action = '') { return `<div class="empty-state"><span class="empty-icon">${icon('document')}</span><h3>${esc(title)}</h3><p>${esc(detail)}</p>${action}</div>`; }
  const brand = () => '<div class="brand"><span class="brand-mark">C</span><div><div class="brand-name">Concord</div><div class="brand-caption">Institutional settlement</div></div></div>';

  async function api(path, options = {}) {
    const method = options.method || 'GET';
    const response = await fetch(path, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: { Accept: 'application/json', ...(method !== 'GET' ? { 'Content-Type': 'application/json', 'X-CSRF-Token': state.session?.csrf || '' } : {}), ...options.headers },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {})
    });
    let payload;
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) {
      if (response.status === 401 && !path.endsWith('/login')) { state.session = null; state.data = null; closeDialog(); renderLogin('Your session ended. Sign in to continue.'); }
      const error = new Error(payload.message || payload.error?.message || (typeof payload.error === 'string' ? payload.error : `Request failed (${response.status}).`));
      error.status = response.status;
      throw error;
    }
    return payload;
  }
  function notify(message, error = false) {
    const element = document.createElement('div');
    element.className = `toast${error ? ' error' : ''}`;
    element.setAttribute('role', error ? 'alert' : 'status');
    element.innerHTML = `${icon(error ? 'info' : 'check')}<span>${esc(message)}</span><button type="button" aria-label="Dismiss notification">${icon('close')}</button>`;
    element.querySelector('button').addEventListener('click', () => element.remove());
    document.getElementById('notifications').append(element);
    window.setTimeout(() => element.remove(), error ? 14000 : 7000);
  }
  function renderLogin(message = '') {
    document.title = `Sign in · Concord ${state.app === 'guardian' ? 'guardian' : 'wallet'}`;
    const guardian = state.app === 'guardian';
    root.innerHTML = `<main class="login-shell"><section class="login-story">${brand()}<h1>A shared standard.<br><em>A stronger foundation.</em></h1><p class="intro">Confidential settlement for institutions. Clear oversight for the federation that safeguards it.</p><div class="login-points"><span>${icon('shield')}Federated oversight</span><span>${icon('lock')}Confidential by design</span></div><footer>Built for banks and the businesses they serve.<br>Concord institutional settlement · Local development sandbox</footer></section><section class="login-form-side"><div class="login-card"><div class="login-badge">${icon(guardian ? 'shield' : 'wallet')} ${guardian ? 'Federation guardian' : 'Institutional wallet'}</div><h2>Welcome to your workspace.</h2><p class="muted">Sign in with your assigned ${guardian ? 'guardian institution' : 'bank or corporate'} account.</p><form id="login-form" data-testid="login-form"><div class="form-field"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus data-testid="username"></div><div class="form-field"><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required data-testid="password"></div><p id="login-error" class="login-error ${message ? '' : 'hidden'}" role="alert">${esc(message)}</p><button class="button primary" type="submit" data-testid="login-submit">Sign in securely ${icon('arrow')}</button></form><div class="login-notice">${icon('info')}<span><strong>Local sandbox only.</strong> Reserve accounts and bank payments are simulated. Test tokens have no real-world redemption promise.</span></div><p class="login-switch">${guardian ? 'Bank or corporate customer?' : 'A member of the federation?'} <a href="/${guardian ? 'wallet' : 'guardian'}">Open ${guardian ? 'institutional wallet' : 'guardian console'} ${icon('arrow')}</a></p></div></section></main>`;
    root.querySelector('form').addEventListener('submit', async event => {
      event.preventDefault();
      const form = event.currentTarget;
      const submit = form.querySelector('[type=submit]');
      const error = document.getElementById('login-error');
      submit.disabled = true; submit.textContent = 'Signing in…'; error.classList.add('hidden');
      try {
        const data = new FormData(form);
        const result = await api('/api/login', { method: 'POST', body: { username: data.get('username'), password: data.get('password') } });
        state.session = result.session || result;
        if (!state.session.user) state.session = await api('/api/session');
        await refresh();
      } catch (failure) { error.textContent = failure.message; error.classList.remove('hidden'); }
      finally { submit.disabled = false; submit.innerHTML = `Sign in securely ${icon('arrow')}`; }
    });
  }

  function navItems() {
    const items = state.app === 'guardian' ? [['overview', 'Overview', 'grid'], ['approvals', 'Approval queue', 'shield'], ['reserves', 'Reserve accounts', 'bank'], ['network', 'Network & key readiness', 'network'], ['activity', 'Activity log', 'activity']] : [['overview', 'Overview', 'grid'], ['payments', 'Payments', 'send'], ['beneficiaries', 'Beneficiaries', 'users'], ['activity', 'Activity log', 'activity']];
    if (can('view_bank')) items.splice(items.length - 1, 0, ['federation', 'Federation lifecycle', 'refresh']);
    return items;
  }
  const pageName = () => navItems().find(item => item[0] === state.page)?.[1] || 'Overview';
  function render() {
    if (!state.session?.user) return renderLogin();
    const account = user();
    const guardian = state.app === 'guardian';
    const pending = operations().filter(isPending).length;
    const nav = navItems();
    if (!nav.some(item => item[0] === state.page)) state.page = 'overview';
    document.title = `${pageName()} · Concord ${guardian ? 'guardian' : 'wallet'}`;
    root.innerHTML = `<div class="shell"><aside class="sidebar">${brand()}<div class="workspace-label">${icon(guardian ? 'shield' : 'wallet')} ${guardian ? 'Guardian console' : 'Institutional wallet'}<span class="dot"></span></div><div class="nav-label">Workspace</div><nav class="nav" aria-label="Workspace navigation">${nav.map(([id, label, symbol]) => `<a href="#${id}" class="${state.page === id ? 'active' : ''}" ${state.page === id ? 'aria-current="page"' : ''} data-testid="nav-${id}">${icon(symbol)}${label}${['approvals', 'payments'].includes(id) && pending ? `<span class="nav-badge">${pending}</span>` : ''}</a>`).join('')}</nav><div class="sidebar-foot"><div class="security-card">${icon('lock')}<strong>${guardian ? 'Independent guardian authority' : 'Institutional access controls'}</strong><p>${guardian ? 'Approvals use your institution’s configured signer. Private shares stay outside this browser.' : 'Your account determines your access. Payment approvals require a separate authorized person.'}</p></div><p>LOCAL DEVELOPMENT ENVIRONMENT<br>Sandbox issuer · Legal entity undecided</p></div></aside><div class="shell-main"><header class="topbar"><div class="breadcrumb">${guardian ? 'Federation' : esc(account.tenant || 'Institutional wallet')} ${icon('chevron')} <strong>${esc(pageName())}</strong></div><div class="top-actions"><span class="environment"><span class="dot gold"></span> LOCAL SANDBOX</span><span class="top-divider"></span><div class="user-info"><span class="avatar">${esc(initials(account.name))}</span><div class="user-copy"><div class="user-name">${esc(account.name || account.id)}</div><div class="user-role">${esc(human(account.role))}${account.institution_id ? ` · ${esc(account.institution_id)}` : ''}</div></div></div><button class="icon-button" data-action="logout" title="Sign out" aria-label="Sign out" data-testid="logout">${icon('logout')}</button></div></header><main class="content" id="main-content"><div class="sandbox-note">${icon('info')}<span><strong>LOCAL SANDBOX</strong> · Simulated bank reserves. TestEUR and TestUSD are test assets. Issuer: Sandbox issuer (legal entity undecided).</span></div>${state.error ? `<div class="error-banner" role="alert">${icon('info')}<span>${esc(state.error)}</span>${button('refresh', 'Try again', 'small')}</div>` : ''}${pageContent()}<footer class="footer"><span>Concord · Institutional settlement sandbox</span><span class="secure">${icon('lock')} Authenticated session · ${esc(account.tenant || account.institution_id || 'Restricted access')}</span></footer></main></div></div>`;
    bindRootEvents();
  }
  function pageHeading(title, subtitle, actions = '') { return `<div class="page-heading"><div><h1>${esc(title)}</h1><p>${esc(subtitle)}</p></div><div class="heading-right">${actions}</div></div>`; }
  function metric(label, value, detail, symbol, accent = false) { return `<article class="metric${accent ? ' accent' : ''}"><div class="metric-label">${esc(label)}${icon(symbol)}</div><div class="metric-value number">${value}</div><div class="metric-detail">${detail}</div></article>`; }
  function pageContent() {
    if (!state.data) return pageHeading('Opening your workspace', 'Retrieving your institution’s current records.') + '<div class="panel"><div class="loading-indicator" role="status">Loading workspace…</div></div>';
    if (state.page === 'federation' && can('view_bank')) return federationPage();
    if (state.app === 'guardian' && !can('view_bank')) return pageHeading('A guardian workspace is required', 'Your authenticated account has access to the institutional wallet.') + `<section class="panel">${empty('Restricted federation workspace', 'Use your bank or corporate wallet workspace to manage authorized accounts.', '<a class="button primary" href="/wallet">Open institutional wallet</a>')}</section>`;
    if (state.app === 'guardian') {
      if (state.page === 'reserves') return reservesPage();
      if (state.page === 'network') return networkPage();
      if (state.page === 'activity') return activityPage();
      return guardianOverview();
    }
    if (state.page === 'beneficiaries') return beneficiariesPage();
    if (state.page === 'activity') return activityPage();
    return walletOverview();
  }
  function guardianOverview() {
    const all = operations();
    const pending = all.filter(isPending);
    const requiringMine = all.filter(operation => arr(operation.allowed_actions).some(action => ['guardian_approve', 'guardian-approve'].includes(action)));
    const network = state.data.network || {};
    const guardianList = arr(state.data.guardians);
    const refreshing = button('refresh', 'Refresh', '', 'refresh', 'data-testid="refresh"');
    return pageHeading(state.page === 'approvals' ? 'Approval queue' : 'Federation overview', `Independent oversight, shared responsibility.${user().institution_id ? ` Acting for ${user().institution_id}.` : ''}`, refreshing) + rotationNotice() + `<div class="metrics">${metric('Awaiting your institution', number(requiringMine.length), 'Review before providing a guardian certificate', 'shield', true)}${metric('Active settlement requests', number(pending.length), `${number(all.filter(item => item.state === 'settled').length)} completed in this workspace`, 'clock')}${metric('Settlement exceptions', number(all.filter(isException).length), 'Bank uncertainty and chain errors', 'info')}${metric('Elements block height', number(network.height ?? network.block_height), network.connected ? 'Node connected · live adapter' : 'See network readiness for connection status', 'network')}</div><div class="panels"><section>${operationPanel(state.page === 'approvals' ? 'Requests for review' : 'Settlement requests', true)}</section><aside class="aside-panels">${networkCard()}${keyCard()}${recentActivityCard()}</aside></div>${disclosureCard()}`;
  }
  function accounts() {
    const raw = arr(state.data?.accounts);
    if (raw.length) return raw;
    return arr(state.data?.balances);
  }
  function walletActions() {
    const actions = [];
    const hold = federationData().hold_reason || federationData().rotation?.hold_reason || state.data?.network?.settlement_hold;
    const unavailable = hold ? ' disabled title="New requests are held during the recorded federation transition" aria-describedby="settlement-transition-hold"' : '';
    if (can('create_deposit')) actions.push(button('deposit', 'Deposit', '', 'download', 'data-testid="new-deposit"' + unavailable));
    if (can('create_redemption')) actions.push(button('redemption', 'Redeem', '', 'upload', 'data-testid="new-redemption"' + unavailable));
    if (can('create_transfer')) actions.push(button('transfer', 'New payment', 'primary', 'plus', 'data-testid="new-transfer"' + unavailable));
    return actions.join('');
  }
  function walletOverview() {
    const bankAdmin = can('simulate_bank');
    return pageHeading(state.page === 'payments' ? 'Payments' : 'Your treasury, in view.', state.page === 'payments' ? 'Create, review and track settlement across your permitted accounts.' : `${user().tenant || 'Your institution'} · Confidential settlement across test currencies.`, walletActions()) + rotationNotice() + (state.page === 'overview' ? balancesPanel() : '') + (bankAdmin ? `<div class="bank-simulator"><div><strong>${icon('bank')} Simulated bank connector</strong><p>Record a test reserve credit or update a test payout. No real bank instruction will be sent.</p></div>${button('bank-event', 'Record bank event', '', 'plus', 'data-testid="bank-event"')}</div>` : '') + `<div class="panels"><section>${operationPanel(state.page === 'payments' ? 'Payment activity' : 'Recent activity', false)}</section><aside class="aside-panels">${walletAccountCard()}${networkCard()}${recentActivityCard()}</aside></div>`;
  }
  function balancesPanel() {
    const balances = arr(state.data.balances);
    if (!balances.length) return `<div class="panel" style="margin-bottom:24px">${empty('No settlement balances yet', 'Your authorized accounts will appear here once configured. Create a deposit request when an account is available.', can('create_deposit') ? button('deposit', 'Deposit instructions', 'primary', 'download') : '')}</div>`;
    return `<div class="balance-grid">${balances.map(balance => `<article class="balance-card" data-testid="balance-${esc(balance.currency)}"><div class="balance-top"><div class="balance-currency"><span class="currency-flag">${balance.currency === 'EUR' ? '€' : balance.currency === 'USD' ? '$' : esc(balance.currency?.slice(0, 1))}</span><div><strong>${testCurrency(balance.currency)}</strong><span>${esc(balance.name || balance.account_name || 'Settlement account')}</span></div></div>${badge('active', 'Test asset')}</div><div class="balance-value number">${money(balance.balance_minor ?? balance.amount_minor ?? balance.balance, '', balance.balance_minor !== undefined || balance.amount_minor !== undefined)}</div><div class="balance-meta"><span>Available for payment</span><strong class="number">${money(balance.available_minor ?? balance.balance_minor ?? balance.amount_minor, '', true)} ${testCurrency(balance.currency)}</strong></div>${balance.reserved_minor ? `<div class="balance-meta"><span>Reserved / pending</span><strong>${money(balance.reserved_minor)} ${testCurrency(balance.currency)}</strong></div>` : ''}<div class="balance-issuer">${icon('bank')} ${issuer(balance.issuer)}<br><span>${balance.chain_reconciles === true ? 'Chain balance reconciled' : balance.chain_reconciles === false ? 'Chain balance differs · review reconciliation' : 'Chain balance not reported'}</span><br><span>${esc(balance.account_id || balance.id || '')}</span></div></article>`).join('')}</div>`;
  }
  function filteredOperations() {
    return operations().filter(operation => {
      if (state.filter === 'pending' && !isPending(operation)) return false;
      if (state.filter === 'settled' && operation.state !== 'settled') return false;
      if (state.filter === 'exceptions' && !isException(operation)) return false;
      if (state.search && ![operation.id, operation.kind, operation.currency, operation.destination, operation.account_id, operation.reference, operation.tenant].join(' ').toLowerCase().includes(state.search.toLowerCase())) return false;
      return true;
    }).sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  }
  function operationPanel(title, guardian) {
    const rows = filteredOperations();
    return `<section class="panel"><div class="panel-header"><div><h2>${esc(title)} <span class="count">${operations().length}</span></h2><p>${guardian ? 'Approval binds the exact request, destination and evidence.' : 'Blockchain settlement and bank payout are tracked separately.'}</p></div><div class="panel-actions"><button class="icon-button" aria-label="Export visible operations as CSV" title="Export CSV" data-action="export-operations" data-testid="export-operations">${icon('download')}</button></div></div><div class="toolbar"><div class="tabs" role="group" aria-label="Filter operations">${[['all', 'All'], ['pending', 'In progress'], ['settled', 'Settled'], ['exceptions', 'Exceptions']].map(([key, label]) => `<button type="button" class="tab ${state.filter === key ? 'active' : ''}" data-action="filter" data-filter="${key}" aria-pressed="${state.filter === key}">${label}</button>`).join('')}</div><label class="search">${icon('search')}<input type="search" placeholder="Search requests" aria-label="Search requests" value="${esc(state.search)}" data-testid="operation-search"></label></div><div id="operation-table">${operationTable(rows, guardian)}</div><div class="panel-footer"><span>${rows.length} ${rows.length === 1 ? 'request' : 'requests'} · Current authorized workspace</span><span>All times UTC</span></div></section>`;
  }
  function operationTable(rows, guardian) {
    if (!rows.length) return empty(operations().length ? 'No matching requests' : 'No settlement requests yet', operations().length ? 'Try a different filter or search term.' : guardian ? 'Requests will appear when a bank or corporate customer begins a settlement.' : 'Start with deposit instructions to fund a test account, or create a payment to a permitted beneficiary.');
    return `<div class="table-scroll"><table><thead><tr><th scope="col">Request / counterparty</th><th scope="col">Amount</th><th scope="col">Status</th>${guardian ? '<th scope="col">Guardian approvals</th>' : '<th scope="col">Created</th>'}<th scope="col"><span class="sr-only">Review</span></th></tr></thead><tbody>${rows.map(operation => `<tr data-testid="operation-row" data-operation-id="${esc(operation.id)}"><td><div class="operation-type"><span class="type-icon ${esc(operation.kind)}">${icon(operation.kind === 'deposit' ? 'download' : operation.kind === 'redemption' ? 'upload' : 'send')}</span><div><span class="cell-primary">${esc(operation.destination_name || operation.beneficiary_name || (operation.kind === 'deposit' ? 'Reserve deposit' : operation.kind === 'redemption' ? 'Bank redemption' : 'Settlement transfer'))}</span><span class="cell-secondary">${esc(human(operation.kind))} · ${esc(short(operation.id, 13))}</span></div></div></td><td class="amount-cell"><span class="cell-primary number">${opMoney(operation)}</span><span class="cell-secondary">${testCurrency(operation.currency)}</span></td><td>${badge(operation.state)}${operation.error ? '<span class="cell-secondary warning-text">Review required</span>' : ''}</td><td>${guardian ? quorum(operation) : `<span class="cell-primary">${date(operation.created_at)}</span><span class="cell-secondary">${esc(operation.account_id)}</span>`}</td><td><button class="link-button" type="button" data-action="detail" data-id="${esc(operation.id)}" data-testid="review-operation" aria-label="Review ${esc(operation.kind)} request ${esc(operation.id)}">Review ${icon('chevron')}</button></td></tr>`).join('')}</tbody></table></div>`;
  }
  function quorum(operation) {
    const count = Number(operation.guardian_approvals || 0);
    const required = Number(operation.guardian_threshold || 0);
    return `<div class="quorum"><span class="quorum-track">${Array.from({ length: Math.min(required, 15) }, (_, i) => `<span class="${i < count ? 'filled' : ''}"></span>`).join('')}</span><span>${number(count)} / ${required ? number(required) : '—'}</span></div>`;
  }
  function networkCard() {
    const network = state.data.network || {};
    const connected = network.connected === true;
    return `<section class="panel side-card"><div class="side-card-head"><h3>Network status</h3>${badge(connected ? 'healthy' : 'unavailable', connected ? 'Connected' : network.status ? human(network.status) : 'Not connected')}</div><div class="kv-list"><div class="kv"><span>Elements chain</span><strong>${esc(network.chain || network.network || '—')}</strong></div><div class="kv"><span>Block height</span><strong class="number">${number(network.height ?? network.block_height)}</strong></div><div class="kv"><span>Adapter</span><strong>${esc(human(network.adapter_status || (connected ? 'connected' : 'unavailable')))}</strong></div><div class="kv"><span>Asset registry</span><strong>${network.registry_version !== undefined ? `Version ${esc(network.registry_version)}` : 'Not reported'}</strong></div></div><p class="small-note">${esc(network.error || 'Chain actions require a configured native Elements adapter. Bank events use a local simulator.')}</p></section>`;
  }
  function keyCard() {
    const network = state.data.network || {};
    const audit = state.data.audit || network.audit || { threshold: network.audit_threshold, guardian_count: network.audit_guardians, roster_id: network.audit_version !== undefined ? `Audit version ${network.audit_version}` : null };
    const ready = audit.historical_ready === true;
    return `<section class="panel side-card"><div class="side-card-head"><h3>Audit key readiness</h3>${icon('shield')}</div><div class="kv-list"><div class="kv"><span>Current roster</span><strong>${esc(audit.roster_id || network.audit_roster_id || 'Not reported')}</strong></div><div class="kv"><span>Recovery threshold</span><strong>${audit.threshold ? `${esc(audit.threshold)} of ${esc(audit.guardian_count || '—')}` : 'Not reported'}</strong></div><div class="kv"><span>Historical outputs</span><strong>${ready ? 'Recovery attested' : 'Readiness not attested'}</strong></div></div><div class="readiness">${icon(ready ? 'check' : 'info')}<span>${ready ? 'Current guardians report access to historical recovery keys.' : 'A DynaFed update alone does not demonstrate historical key recovery.'}</span></div><a class="link-button" href="#network">View governance details ${icon('arrow')}</a></section>`;
  }
  function walletAccountCard() {
    return `<section class="panel side-card"><div class="side-card-head"><h3>Your workspace</h3>${icon('bank')}</div><div class="kv-list"><div class="kv"><span>Institution / customer</span><strong>${esc(user().tenant || '—')}</strong></div><div class="kv"><span>Authorized role</span><strong>${esc(human(user().role))}</strong></div><div class="kv"><span>Settlement accounts</span><strong>${accounts().length}</strong></div><div class="kv"><span>Payment approval</span><strong>Separate approver</strong></div></div><p class="small-note">Token issuer and reserve account arrangements remain undecided. Test tokens do not represent a legal claim to real funds.</p></section>`;
  }
  function recentActivityCard() {
    const activity = arr(state.data.activity).slice(0, 4);
    return `<section class="panel side-card"><div class="side-card-head"><h3>Latest activity</h3>${icon('activity')}</div>${activity.length ? `<ul class="activity-list">${activity.map(item => `<li><span class="activity-point"></span><div><strong>${esc(item.description || item.action || item.event || 'Recorded event')}</strong><p>${esc(item.actor_name || item.actor || '')} · ${date(item.created_at || item.timestamp)}</p></div></li>`).join('')}</ul>` : '<p class="small-note">No recorded activity for your workspace yet.</p>'}<a class="link-button" href="#activity">Open activity log ${icon('arrow')}</a></section>`;
  }
  function reservesPage() {
    const reserves = arr(state.data.reserves);
    return pageHeading('Reserve accounts', 'Simulated segregated accounts, independently reconciled by currency.', button('refresh', 'Refresh', '', 'refresh')) + (can('simulate_bank') ? `<div class="bank-simulator"><div><strong>Local reserve simulator</strong><p>Events are auditable test records. The simulator cannot move real fiat money.</p></div>${button('bank-event', 'Record bank event', '', 'plus')}</div>` : '') + `<section class="panel"><div class="panel-header"><div><h2>Reserve reconciliation</h2><p>Keep issuer liabilities, reserve credits and pending payouts distinct.</p></div>${badge('neutral', 'Simulated accounts')}</div>${reserves.length ? `<div class="table-scroll"><table><thead><tr><th>Currency / issuer</th><th>Segregated account</th><th>Reserve balance</th><th>Token liabilities</th><th>Reconciliation</th></tr></thead><tbody>${reserves.map(reserve => `<tr><td><span class="cell-primary">${testCurrency(reserve.currency)}</span><span class="cell-secondary">${issuer(reserve.issuer)}</span></td><td><span class="cell-primary">${esc(reserve.account_name || reserve.name || reserve.account_id || 'Simulated reserve')}</span><span class="cell-secondary">${esc(reserve.bank_account_masked || reserve.bank_account_ref || 'Local test ledger')}</span></td><td class="number">${money(reserve.cash_minor)} ${testCurrency(reserve.currency)}</td><td class="number">${money(reserve.token_liability_minor)} ${testCurrency(reserve.currency)}<span class="cell-secondary">Deposit payable ${money(reserve.deposit_payable_minor)} · Redemption payable ${money(reserve.redemption_payable_minor)}</span></td><td>${badge(reserve.frozen ? 'mismatch' : reserve.cash_reconciles && reserve.liabilities_reconcile && reserve.supply_reconciles && reserve.journal_balances ? 'reconciled' : 'mismatch', reserve.frozen ? 'Issuance frozen' : undefined)}<span class="cell-secondary">Escrow ${money(reserve.escrow_minor)} · Test payout mode: ${esc(human(reserve.payout_mode))}</span></td></tr>`).join('')}</tbody></table></div>` : empty('No reserve accounts reported', 'Configure a simulated reserve account and currency asset before issuing test tokens.')}<div class="panel-footer"><span>Operational evidence only · Legal segregation is a separate institution-level arrangement</span></div></section>`;
  }
  function networkPage() {
    const network = state.data.network || {};
    const audit = state.data.audit || network.audit || { threshold: network.audit_threshold, guardian_count: network.audit_guardians, roster_id: network.audit_version !== undefined ? `Audit version ${network.audit_version}` : null };
    const guardians = arr(state.data.guardians);
    const assets = arr(state.data.assets);
    return pageHeading('Network & key readiness', 'Track chain governance, settlement assets and historical audit access separately.', button('refresh', 'Refresh', '', 'refresh')) + `<div class="panels"><section><section class="panel"><div class="panel-header"><div><h2>Guardian institutions</h2><p>Authority is supplied by independently configured institution signers.</p></div>${guardians.length ? `<span class="badge neutral">${guardians.length} institutions</span>` : ''}</div>${guardians.length ? `<div class="table-scroll"><table><thead><tr><th>Institution</th><th>Approval signer</th><th>Audit key access</th></tr></thead><tbody>${guardians.map(guardian => `<tr><td><span class="cell-primary">${esc(guardian.name || guardian.institution_id || guardian.id)}</span><span class="cell-secondary">${esc(guardian.institution_id || guardian.id)}</span></td><td>${badge(guardian.status || (guardian.approval_url ? 'configured' : 'unconfigured'))}</td><td>${guardian.historical_ready === true ? badge('ready', 'History attested') : badge('not_started', 'Not attested')}</td></tr>`).join('')}</tbody></table></div>` : empty('Guardian roster not reported', 'The server must supply the current roster and signer readiness.')}</section><section class="panel"><div class="panel-header"><div><h2>Settlement asset registry</h2><p>Currency identity and legal issuer are separate registry attributes.</p></div>${network.registry_version !== undefined ? `<span class="badge neutral">Version ${esc(network.registry_version)}</span>` : ''}</div>${assets.length ? `<div class="table-scroll"><table><thead><tr><th>Test currency</th><th>Issuer</th><th>Asset identity</th><th>Status</th></tr></thead><tbody>${assets.map(asset => `<tr><td><strong>${testCurrency(asset.currency)}</strong></td><td>${issuer(asset.issuer)}</td><td><span class="mono">${esc(short(asset.asset_id || asset.id, 20))}</span>${asset.asset_id ? `<button class="icon-button" data-action="copy" data-copy="${esc(asset.asset_id)}" aria-label="Copy ${esc(asset.currency)} asset ID">${icon('copy')}</button>` : ''}</td><td>${badge(asset.status || (asset.registered ? 'active' : 'unconfigured'))}</td></tr>`).join('')}</tbody></table></div>` : empty('No native assets configured', 'The registry adapter must provide real Elements asset IDs. Test asset names alone cannot identify a native asset.')}</section><section class="panel"><div class="panel-header"><div><h2>Historical recovery readiness</h2><p>Current federation access must be established for each historical audit key.</p></div></div><div class="key-grid">${arr(audit.keys || state.data.historical_keys).length ? arr(audit.keys || state.data.historical_keys).map(key => `<div class="key-card"><div class="key-title"><strong>${esc(key.label || key.key_id)}</strong>${badge(key.ready ? 'ready' : 'not_started', key.ready ? 'Ready' : 'Not attested')}</div><p class="mono">${esc(key.key_id || key.public_key)}</p><p class="small-note">${esc(key.detail || 'Recovery readiness requires guardian evidence.')}</p></div>`).join('') : '<div class="notice-block">Historical key attestations have not been supplied by the native guardian service. This interface cannot infer them from DynaFed membership.</div>'}</div></section></section><aside class="aside-panels">${networkCard()}${keyCard()}</aside></div>${disclosureCard()}`;
  }
  function disclosureCard() {
    if (state.app !== 'guardian') return '';
    const disclosure = state.data.disclosure || {};
    return `<section class="panel" style="margin-top:22px"><div class="panel-header"><div><h2>Confidential disclosure cases</h2><p>Purpose-bound review · Recovery authority is distinct from settlement approval.</p></div>${badge(disclosure.connected ? 'healthy' : 'unconfigured', disclosure.connected ? 'Guardian service connected' : 'Native service not connected')}</div><div class="notice-block" style="margin:0 21px 21px">${esc(disclosure.message || 'The existing native guardian disclosure workflow is separate. This console does not request decryption shares or hold audit keys. Connect its case API before exposing disclosure actions here.')}</div></section>`;
  }
  function beneficiariesPage() {
    const beneficiaries = arr(state.data.beneficiaries);
    return pageHeading('Beneficiaries', 'Approved internal settlement accounts and bank redemption destinations.', '') + `<section class="panel"><div class="panel-header"><div><h2>Your beneficiaries <span class="count">${beneficiaries.length}</span></h2><p>Destinations are bound into the settlement request before approval.</p></div></div>${beneficiaries.length ? `<div class="table-scroll"><table><thead><tr><th>Name</th><th>Destination type</th><th>Currency</th><th>Account reference</th></tr></thead><tbody>${beneficiaries.map(beneficiary => `<tr><td><span class="cell-primary">${esc(beneficiary.name || beneficiary.id)}</span><span class="cell-secondary">${esc(beneficiary.id)}</span></td><td>${esc(beneficiary.kind === 'internal' ? 'Internal settlement account' : 'Bank redemption account')}</td><td>${testCurrency(beneficiary.currency)}</td><td><span class="cell-primary">${esc(beneficiary.account_reference_masked || beneficiary.bank_account_masked || beneficiary.destination || 'Reference held on server')}</span>${beneficiary.bank_account_ref_hash ? `<span class="cell-secondary mono">${esc(short(beneficiary.bank_account_ref_hash, 20))}</span>` : ''}</td></tr>`).join('')}</tbody></table></div>` : empty('No bank beneficiaries configured', 'Your sandbox administrator must configure a permitted simulated bank destination before you can request a redemption.', '')}<div class="panel-footer"><span>Approved destinations are administrator-configured for this pilot · Scoped to your authorized workspace</span></div></section>`;
  }
  function activityPage() {
    const activity = arr(state.data.activity).slice();
    return pageHeading('Activity log', 'An attributable record of requests, reviews and settlement events.', button('refresh', 'Refresh', '', 'refresh')) + `<section class="panel"><div class="panel-header"><div><h2>Recorded events</h2><p>Activity is scoped to the records your account can access.</p></div>${button('export-activity', 'Export CSV', 'small', 'download')}</div>${activity.length ? `<div class="table-scroll"><table><thead><tr><th>Event</th><th>Actor</th><th>Request</th><th>Recorded at</th></tr></thead><tbody>${activity.map(item => `<tr><td><span class="cell-primary">${esc(item.description || human(item.action || item.event))}</span>${item.detail ? `<span class="cell-secondary">${esc(item.detail)}</span>` : ''}</td><td>${esc(item.actor_name || item.actor || 'System')}</td><td>${item.operation_id ? `<button class="link-button" data-action="detail" data-id="${esc(item.operation_id)}">${esc(short(item.operation_id, 16))}${icon('chevron')}</button>` : '—'}</td><td>${date(item.created_at || item.timestamp, true)}</td></tr>`).join('')}</tbody></table></div>` : empty('No recorded events yet', 'Requests and authorized actions will create activity records.')}</section>`;
  }

  function federationData() { return state.data?.federation || {}; }
  function rotationActions() {
    const federation = federationData();
    return [...new Set([...arr(federation.allowed_actions), ...arr(federation.rotation?.allowed_actions)])];
  }
  function rotationNotice() {
    const federation = federationData();
    const rotation = federation.rotation;
    const hold = rotation?.hold_reason || federation.hold_reason || state.data?.network?.settlement_hold;
    if (!hold && !rotation) return '';
    if (!hold && ['complete', 'completed', 'cancelled'].includes(rotation.state)) return '';
    const message = typeof hold === 'string' ? hold : 'A federation handover is in progress. Settlement availability follows the recorded transition policy.';
    return `<div class="rotation-notice" id="settlement-transition-hold" role="status">${icon('refresh')}<div><strong>${hold ? 'Settlement transition hold' : 'Federation handover in progress'}</strong><p>${esc(message)}</p></div>${can('view_bank') ? '<a class="link-button" href="#federation">View handover</a>' : ''}</div>`;
  }
  function thresholdLabel(policy) {
    if (!policy || policy.threshold === undefined || (policy.count === undefined && policy.guardian_count === undefined && !Array.isArray(policy.members))) return 'Not reported';
    return `${number(policy.threshold)} of ${number(policy.count ?? policy.guardian_count ?? policy.members.length)}`;
  }
  function federationMembership(policy, title, iconName) {
    if (!policy) return `<div class="federation-domain"><div class="federation-domain-title">${icon(iconName)}<h4>${esc(title)}</h4></div><p class="small-note">Membership and threshold have not been reported.</p></div>`;
    const members = arr(policy.members);
    return `<div class="federation-domain"><div class="federation-domain-title">${icon(iconName)}<h4>${esc(title)}</h4><strong>${esc(thresholdLabel(policy))}</strong></div>${policy.state || policy.status ? badge(policy.state || policy.status) : ''}${policy.detail ? `<p class="small-note">${esc(policy.detail)}</p>` : ''}${members.length ? `<details class="federation-members"><summary>${number(members.length)} recorded members</summary><ul>${members.map(member => `<li>${esc(typeof member === 'object' && member !== null ? member.name || member.id || member.member || 'Member' : member)}</li>`).join('')}</ul></details>` : ''}${policy.script ? `<div class="federation-fingerprint"><span>Signing script</span><code title="${esc(policy.script)}">${esc(short(policy.script, 28))}</code></div>` : ''}</div>`;
  }
  function federationMembershipCard(value, incoming = false) {
    const heading = incoming ? 'Incoming membership' : 'Current membership';
    if (!value) return `<section class="panel federation-membership"><div class="panel-header"><div><p>${esc(heading)}</p><h2>${incoming ? 'Awaiting a prepared handover' : 'Membership unavailable'}</h2></div>${icon(incoming ? 'users' : 'shield')}</div>${empty(incoming ? 'No incoming membership recorded' : 'Current policy is not available', incoming ? 'An authorized administrator can prepare the next membership when the coordinator permits it.' : 'Refresh the workspace or check the federation coordinator.')}</section>`;
    return `<section class="panel federation-membership${incoming ? ' incoming' : ''}"><div class="panel-header"><div><p>${esc(heading)}${value.epoch !== undefined ? ` · Epoch ${esc(value.epoch)}` : ''}</p><h2>${esc(value.label || value.id || heading)}</h2></div>${value.state || value.status ? badge(value.state || value.status) : icon(incoming ? 'users' : 'shield')}</div>${federationMembership(value.block_signing, 'Block signing', 'network')}${federationMembership(value.audit, 'Historical audit recovery', 'shield')}${federationMembership(value.treasury, 'Treasury spending', 'bank')}</section>`;
  }
  function federationPage() {
    const federation = federationData();
    const rotation = federation.rotation;
    const actions = rotationActions();
    const network = state.data.network || {};
    const controls = [button('refresh', 'Refresh', '', 'refresh')];
    if (actions.includes('prepare')) controls.push(button('rotation-prepare', 'Prepare handover', 'primary', 'plus', 'data-testid="rotation-prepare"'));
    const chain = federation.genesis_hash || network.genesis_hash;
    const steps = arr(rotation?.steps);
    const migrations = arr(rotation?.migrations);
    const readiness = arr(rotation?.readiness);
    const outstanding = arr(rotation?.outstanding_cases);
    const approvals = rotation?.approval_count ?? rotation?.guardian_approvals ?? (Array.isArray(rotation?.approvals) ? rotation.approvals.length : undefined);
    const required = rotation?.approval_threshold ?? rotation?.guardian_threshold ?? rotation?.threshold;
    const audit = federation.current?.audit;
    const stage = rotation?.stage || rotation?.state || 'not_started';
    const done = steps.filter(step => ['complete', 'completed', 'confirmed', 'active'].includes(step.state || step.status)).length;
    const canApprove = actions.some(action => ['guardian-approve', 'guardian_approve', 'approve'].includes(action));
    const next = [];
    if (canApprove) next.push(button('rotation-approve', 'Review institution authorization', 'primary', 'shield', 'data-testid="rotation-approve"'));
    if (actions.includes('advance')) next.push(button('rotation-advance', 'Advance handover', 'primary', 'arrow', 'data-testid="rotation-advance"'));
    if (actions.includes('retry')) next.push(button('rotation-retry', 'Retry recorded stage', '', 'refresh', 'data-testid="rotation-retry"'));
    const identity = `<div class="federation-chain"><span class="federation-chain-icon">${icon('network')}</span><div><strong>${esc(federation.chain || network.chain || 'Elements chain')}</strong><p>Membership changes retain this chain, its history and its asset IDs.</p></div>${badge('neutral', 'Same-chain handover')}<div class="federation-genesis"><span>Genesis block</span><code>${esc(chain || 'Not reported')}</code>${chain ? `<button class="icon-button" data-action="copy" data-copy="${esc(chain)}" aria-label="Copy genesis block hash">${icon('copy')}</button>` : ''}</div></div>`;
    const progress = `<section class="panel"><div class="panel-header"><div><h2>Recorded handover stages</h2><p>${rotation ? `Request ${esc(short(rotation.id, 22))}${rotation.created_at ? ` · ${date(rotation.created_at, true)}` : ''}` : 'The coordinator records every stage before it advances.'}</p></div>${badge(stage)}</div>${steps.length ? `<ol class="rotation-steps">${steps.map((step, index) => { const status = step.state || step.status || 'not_reported'; return `<li class="rotation-step ${['complete', 'completed', 'confirmed', 'active'].includes(status) ? 'done' : ['failed', 'blocked', 'error'].includes(status) ? 'blocked' : ''}"><span class="rotation-step-number">${['complete', 'completed', 'confirmed', 'active'].includes(status) ? icon('check') : index + 1}</span><div><div class="rotation-step-title"><strong>${esc(step.label || human(step.id))}</strong>${badge(status)}</div>${step.detail ? `<p>${esc(step.detail)}</p>` : ''}${step.txid ? copyField('Elements transaction', step.txid) : ''}</div></li>`; }).join('')}</ol>` : empty('No handover stages recorded', 'Prepare a handover to inspect exact membership, readiness and authority migrations.')}</section>`;
    const keyReadiness = `<section class="panel side-card"><div class="side-card-head"><h3>Readiness evidence</h3>${icon('shield')}</div>${readiness.length ? `<ul class="rotation-readiness">${readiness.map(item => `<li><div><strong>${esc(item.label || item.id)}</strong>${item.detail ? `<p>${esc(item.detail)}</p>` : ''}</div>${badge(item.state || item.status || 'not_reported')}</li>`).join('')}</ul>` : '<p class="small-note">No readiness attestations are reported for this handover yet. An incoming roster alone does not establish possession of historical recovery shares.</p>'}</section>`;
    const authorize = `<section class="panel side-card"><div class="side-card-head"><h3>Handover authorization</h3>${icon('lock')}</div><div class="kv-list"><div class="kv"><span>Source institution approvals</span><strong>${approvals !== undefined ? `${number(approvals)} / ${required !== undefined ? number(required) : '—'}` : 'Not reported'}</strong></div><div class="kv"><span>Current stage</span><strong>${esc(human(stage))}</strong></div>${rotation?.activation_height !== undefined ? `<div class="kv"><span>Planned activation height</span><strong>${number(rotation.activation_height)}</strong></div>` : ''}</div>${rotation?.error ? `<div class="inline-warning" role="alert">${esc(rotation.error)}</div>` : ''}${rotation?.hold_reason ? `<div class="inline-warning">${esc(rotation.hold_reason)}</div>` : ''}${next.length ? `<div class="rotation-actions">${next.join('')}</div>` : '<p class="small-note">Your account has no permitted handover action at the recorded stage.</p>'}<p class="small-note">Source institutions authorize the exact prepared handover in their separate approval windows. The coordinator cannot supply their approval passphrases.</p>${rotation?.id ? button('rotation-record', 'Download handover record', 'small', 'download') : ''}</section>`;
    const transactions = `<section class="panel section-gap"><div class="panel-header"><div><h2>Treasury migrations</h2><p>Reissuance authority and recorded redemption escrows on the existing chain.</p></div></div>${migrations.length ? `<div class="table-scroll"><table><thead><tr><th scope="col">Authority / escrow</th><th scope="col">Test currency</th><th scope="col">Transaction</th><th scope="col">State</th></tr></thead><tbody>${migrations.map(item => `<tr><td><span class="cell-primary">${esc(item.label || human(item.kind))}</span>${item.operation_id ? `<span class="cell-secondary">Case ${esc(short(item.operation_id, 18))}</span>` : ''}</td><td>${item.currency ? testCurrency(item.currency) : '—'}</td><td>${item.txid ? `<button class="link-button mono" data-action="copy" data-copy="${esc(item.txid)}" title="Copy full migration transaction ID">${esc(short(item.txid, 20))}${icon('copy')}</button>` : 'Not recorded'}</td><td>${badge(item.state || item.status || 'not_reported')}</td></tr>`).join('')}</tbody></table></div>` : empty('No migration transactions recorded', 'Prepared and confirmed transactions will appear as authority is handed over.')}</section>`;
    const cases = `<section class="panel section-gap"><div class="panel-header"><div><h2>Outstanding settlement cases</h2><p>Recorded requests whose continuity must be preserved through the handover.</p></div></div>${outstanding.length ? `<div class="table-scroll"><table><thead><tr><th scope="col">Case</th><th scope="col">Amount</th><th scope="col">Settlement state</th></tr></thead><tbody>${outstanding.map(item => `<tr><td><button class="link-button" data-action="detail" data-id="${esc(item.id)}">${esc(human(item.kind))} · ${esc(short(item.id, 15))}${icon('chevron')}</button></td><td class="number">${money(item.amount_minor, item.currency)}</td><td>${badge(item.state)}${item.error ? `<span class="cell-secondary warning-text">${esc(item.error)}</span>` : ''}</td></tr>`).join('')}</tbody></table></div>` : empty(Array.isArray(rotation?.outstanding_cases) ? 'No outstanding cases recorded' : 'Outstanding cases not reported', 'The coordinator records the settlement cases included in the handover inventory.')}</section>`;
    return pageHeading('Federation lifecycle', 'Coordinate signing, historical recovery and treasury authority on the existing chain.', controls.join('')) + identity + rotationNotice() + `<div class="metrics federation-metrics">${metric('Handover stage', esc(human(stage)), steps.length ? `${number(done)} of ${number(steps.length)} recorded stages complete` : 'No stage completion inferred', 'refresh', true)}${metric('Current audit recovery', esc(thresholdLabel(audit)), 'Threshold from the recorded current membership', 'shield')}${metric('Institution authorizations', approvals !== undefined ? `${number(approvals)} / ${required !== undefined ? number(required) : '—'}` : '—', 'Exact source-policy authorization', 'lock')}${metric('Migration transactions', migrations.length ? number(migrations.length) : '—', 'Prepared and confirmed records shown below', 'bank')}</div><div class="federation-memberships">${federationMembershipCard(federation.current)}${federationMembershipCard(federation.incoming, true)}</div><div class="panels federation-progress"><section>${progress}${transactions}${cases}</section><aside class="aside-panels">${authorize}${keyReadiness}</aside></div>`;
  }
  function bindRootEvents() {
    root.querySelectorAll('[data-action]').forEach(element => element.addEventListener('click', () => handleAction(element)));
    root.querySelector('input[type=search]')?.addEventListener('input', event => {
      state.search = event.target.value;
      document.getElementById('operation-table').innerHTML = operationTable(filteredOperations(), state.app === 'guardian');
      document.getElementById('operation-table').querySelectorAll('[data-action]').forEach(element => element.addEventListener('click', () => handleAction(element)));
      const count = root.querySelector('.panel-footer span');
      if (count) count.textContent = `${filteredOperations().length} requests · Current authorized workspace`;
    });
  }
  async function handleAction(element) {
    const action = element.dataset.action;
    if (action === 'refresh') return refresh(true);
    if (action === 'filter') { state.filter = element.dataset.filter; render(); return; }
    if (action === 'detail') return openOperation(element.dataset.id);
    if (action === 'copy') return copyText(element.dataset.copy);
    if (['transfer', 'redemption', 'deposit'].includes(action)) return openSettlementForm(action);

    if (action === 'bank-event') return openBankEvent();
    if (action === 'export-operations') return exportOperations();
    if (action === 'export-activity') return exportActivity();
    if (action.startsWith('rotation-')) return handleRotationAction(action);
    if (action === 'logout') {
      element.disabled = true;
      try { await api('/api/logout', { method: 'POST', body: {} }); pendingApprovals.forEach(item => item.popup.close()); pendingApprovals.clear(); state.session = null; state.data = null; closeDialog(); renderLogin(); }
      catch (failure) { notify(failure.message, true); element.disabled = false; }
    }
  }
  async function refresh(explicit = false) {
    if (state.refreshing) return;
    state.refreshing = true;
    try {
      const result = await api('/api/dashboard');
      state.data = result;
      if (result.session?.user) state.session = result.session;
      state.error = null;
      render();
      if (explicit) notify('Workspace updated.');
    } catch (failure) {
      if (state.session?.user) { state.error = failure.message; render(); }
    } finally { state.refreshing = false; }
  }
  function closeDialog() {
    dialogs.querySelectorAll('dialog').forEach(dialog => { if (dialog.open) dialog.close(); });
    dialogs.innerHTML = '';
  }
  function openDialog({ title, description = '', content, footer = '', drawer = false, formId = '', onSubmit = null }) {
    closeDialog();
    const priorFocus = document.activeElement;
    const dialog = document.createElement('dialog');
    dialog.className = drawer ? 'drawer' : '';
    dialog.setAttribute('aria-labelledby', 'dialog-title');
    if (description) dialog.setAttribute('aria-describedby', 'dialog-description');
    const body = `<div class="dialog-header"><div><h2 id="dialog-title">${esc(title)}</h2>${description ? `<p id="dialog-description">${esc(description)}</p>` : ''}</div><button type="button" class="icon-button" data-close aria-label="Close dialog">${icon('close')}</button></div><div class="dialog-body">${content}<p class="field-error hidden" id="dialog-error" role="alert"></p></div>${footer ? `<div class="dialog-footer">${footer}</div>` : ''}`;
    dialog.innerHTML = formId ? `<form id="${formId}">${body}</form>` : body;
    dialogs.append(dialog);
    dialog.querySelectorAll('[data-close]').forEach(element => element.addEventListener('click', () => dialog.close()));
    dialog.querySelectorAll('[data-action]').forEach(element => element.addEventListener('click', () => handleAction(element)));
    dialog.addEventListener('close', () => { dialog.remove(); if (priorFocus?.isConnected) priorFocus.focus(); });
    if (onSubmit) dialog.querySelector('form').addEventListener('submit', event => { event.preventDefault(); onSubmit(event.currentTarget, dialog); });
    dialog.showModal();
    (dialog.querySelector('[autofocus]') || dialog.querySelector('input,select,textarea,[data-close]'))?.focus();
    return dialog;
  }
  function field(name, label, input, detail = '') { return `<div class="form-field"><label for="field-${name}">${esc(label)}</label>${input}${detail ? `<small>${esc(detail)}</small>` : ''}</div>`; }
  function input(name, options = '') { return `<input id="field-${name}" name="${name}" ${options}>`; }
  function select(name, items, options = '') { return `<select id="field-${name}" name="${name}" ${options}>${items.map(item => `<option value="${esc(item.value)}" ${item.disabled ? 'disabled' : ''}>${esc(item.label)}</option>`).join('')}</select>`; }
  function accountOptions(currency) {
    return accounts().filter(account => !currency || arr(account.currencies || [account.currency]).includes(currency)).map(account => ({ value: account.account_id || account.id, label: `${account.name || account.account_name || account.account_id || account.id}${account.tenant ? ` · ${account.tenant}` : ''}` }));
  }
  const amountField = () => field('amount', 'Amount', input('amount', 'type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" pattern="[0-9]+([.][0-9]{1,2})?" maxlength="16" required data-testid="amount"'), 'Enter an exact amount with up to two decimal places.');
  async function submitForm(form, dialog, path, body, message) {
    const error = dialog.querySelector('#dialog-error');
    const submit = form.querySelector('[type=submit]');
    const label = submit.innerHTML;
    submit.disabled = true; submit.textContent = 'Submitting…'; error.classList.add('hidden');
    try {
      const result = await api(path, { method: 'POST', body });
      dialog.close();
      notify(message);
      await refresh();
      return result;
    } catch (failure) { error.textContent = failure.message; error.classList.remove('hidden'); error.scrollIntoView({ block: 'nearest' }); return null; }
    finally { submit.disabled = false; submit.innerHTML = label; }
  }
  function openSettlementForm(kind) {
    const requiredPermission = `create_${kind}`;
    if (!can(requiredPermission)) return notify('Your account is not authorized to create this request.', true);
    const accountList = accountOptions();
    if (!accountList.length) return notify('No permitted settlement accounts are configured. Ask your bank administrator to configure an account.', true);
    const currencies = [...new Set(accounts().flatMap(account => account.currencies || [account.currency]).filter(Boolean))];
    const beneficiaries = kind === 'transfer' ? accounts().map(account => ({ id: account.id || account.account_id, account_id: account.id || account.account_id, name: account.name || account.id, currencies: account.currencies || [account.currency] })) : arr(state.data.beneficiaries).filter(beneficiary => beneficiary.kind === 'bank');
    const title = { transfer: 'New settlement payment', redemption: 'Request bank redemption', deposit: 'Deposit test funds' }[kind];
    let destinationField = '';
    if (kind !== 'deposit') {
      destinationField = field('beneficiary_id', kind === 'transfer' ? 'Settlement beneficiary' : 'Bank beneficiary', select('beneficiary_id', [{ value: '', label: 'Choose a configured destination' }, ...beneficiaries.map(beneficiary => ({ value: beneficiary.id, label: `${beneficiary.name || beneficiary.id}${beneficiary.currency ? ` · Test${beneficiary.currency}` : ''}` }))], 'required data-testid="beneficiary"'), kind === 'transfer' ? 'Only configured internal settlement accounts are available.' : 'Bank account details are recorded on the server and bound by their reference hash.');
    }
    const contents = `<div class="form-context"><strong>Sandbox issuer (legal entity undecided)</strong><br>${kind === 'deposit' ? 'This request creates local deposit instructions. Record a matching simulated reserve credit using the new request ID and exact amount. A separate user approval and guardian quorum are required before test-token issuance. Do not send real funds.' : kind === 'redemption' ? 'Tokens are held for redemption before a simulated bank payout. An unknown bank result remains pending reconciliation.' : 'The request must be approved by a separate authorized person and a guardian quorum before chain execution.'}</div>${field('account_id', kind === 'deposit' ? 'Credit account' : 'From account', select('account_id', accountList, 'required data-testid="account"'))}<div class="form-grid">${field('currency', 'Test currency', select('currency', currencies.map(currency => ({ value: currency, label: `Test${currency}` })), 'required data-testid="currency"'))}${amountField()}</div>${destinationField ? `<div style="margin-top:18px">${destinationField}</div>` : ''}<div id="destination-warning" class="inline-warning hidden">No eligible destination is configured for this account and currency. Your sandbox administrator must configure one.</div>`;
    const dialog = openDialog({ title, description: 'A request is created first. This action does not issue an immediate bank payment.', content: contents, formId: 'settlement-form', footer: `<button class="button" type="button" data-close>Cancel</button><button class="button primary" type="submit" data-testid="submit-request" ${kind !== 'deposit' && !beneficiaries.length ? 'disabled title="Add an eligible beneficiary first"' : ''}>Create request ${icon('arrow')}</button>`, onSubmit: async (form, currentDialog) => {
      const data = Object.fromEntries(new FormData(form));
      const beneficiary = beneficiaries.find(item => item.id === data.beneficiary_id);
      const body = { account_id: data.account_id, currency: data.currency, amount: data.amount };
      if (kind === 'transfer') body.to_account_id = beneficiary?.account_id;
      if (kind === 'redemption') body.beneficiary_id = data.beneficiary_id;
      await submitForm(form, currentDialog, `/api/${kind === 'transfer' ? 'transfers' : kind === 'redemption' ? 'redemptions' : 'deposits'}`, body, `${human(kind)} request created. Review its approval and settlement status in the activity list.`);
    } });
    const accountSelect = dialog.querySelector('[name=account_id]');
    const currencySelect = dialog.querySelector('[name=currency]');
    const syncDestination = () => {
      if (kind === 'deposit') return;
      const destinationSelect = dialog.querySelector('[name=beneficiary_id]');
      const prior = destinationSelect.value;
      const eligible = beneficiaries.filter(item => kind === 'transfer' ? item.account_id !== accountSelect.value && arr(item.currencies).includes(currencySelect.value) : item.account_id === accountSelect.value && (!item.currency || item.currency === currencySelect.value));
      destinationSelect.innerHTML = '<option value="">Choose a configured destination</option>' + eligible.map(item => `<option value="${esc(item.id)}">${esc(item.name || item.id)}</option>`).join('');
      if (eligible.some(item => item.id === prior)) destinationSelect.value = prior;
      dialog.querySelector('[type=submit]').disabled = !eligible.length;
      dialog.querySelector('#destination-warning').classList.toggle('hidden', Boolean(eligible.length));
    };
    const syncCurrency = () => {
      const account = accounts().find(item => (item.account_id || item.id) === accountSelect.value);
      const supported = arr(account?.currencies || [account?.currency]).filter(Boolean);
      const prior = currencySelect.value;
      currencySelect.innerHTML = supported.map(currency => `<option value="${esc(currency)}">${testCurrency(currency)}</option>`).join('');
      if (supported.includes(prior)) currencySelect.value = prior;
      syncDestination();
    };
    accountSelect.addEventListener('change', syncCurrency); currencySelect.addEventListener('change', syncDestination); syncCurrency();
  }
  function openBankEvent(operation = null) {
    if (!can('simulate_bank')) return notify('Only an authorized bank simulator operator can record bank events.', true);
    const requestOptions = operations().filter(item => ['deposit', 'redemption'].includes(item.kind)).map(item => ({ value: item.id, label: `${short(item.id, 15)} · ${human(item.kind)} · ${item.amount || (item.amount_minor / 100).toFixed(2)} Test${item.currency}` }));
    const content = `<div class="form-context"><strong>Simulated bank event</strong><br>This creates auditable local evidence. It does not contact a bank or move funds.</div>${field('event_id', 'Unique bank event reference', input('event_id', `required maxlength="100" value="${esc(`sim-${Date.now()}`)}"`), 'Repeated event references are rejected to prevent duplicate credits.')}${field('kind', 'Event type', select('kind', [{ value: 'credit', label: 'Incoming reserve credit' }, { value: 'payout_result', label: 'Resolve existing bank payout' }, { value: 'payout_mode', label: 'Set future simulated payout behavior' }, { value: 'freeze', label: 'Freeze new issuance and payouts' }, { value: 'unfreeze', label: 'Unfreeze new issuance and payouts' }], 'required'))}${field('currency', 'Currency', select('currency', [{ value: 'EUR', label: 'TestEUR' }, { value: 'USD', label: 'TestUSD' }], 'required'))}<div id="bank-request">${field('operation_id', 'Related settlement request', select('operation_id', [{ value: '', label: 'Choose request' }, ...requestOptions], 'required'))}</div><div id="bank-amount">${amountField()}</div><div id="bank-outcome" class="hidden">${field('outcome', 'Payout outcome', select('outcome', [{ value: 'settled', label: 'Confirmed paid' }, { value: 'failed', label: 'Confirmed not paid' }]))}<p class="small-note" id="bank-mode-note">Future behavior changes affect new simulated payout initiations only. Existing unknown payments require a definitive result.</p></div>`;
    const dialog = openDialog({ title: 'Record simulated bank event', description: 'Restricted to the bank simulator operator.', content, formId: 'bank-event-form', footer: '<button class="button" type="button" data-close>Cancel</button><button class="button primary" type="submit" data-testid="submit-bank-event">Record event</button>', onSubmit: async (form, currentDialog) => {
      const data = Object.fromEntries(new FormData(form));
      if (!['credit', 'payout_result'].includes(data.kind)) delete data.operation_id;
      if (data.kind !== 'credit') delete data.amount;
      if (!['payout_result', 'payout_mode'].includes(data.kind)) delete data.outcome;
      await submitForm(form, currentDialog, '/api/bank/events', data, 'Simulated bank event recorded.');
    } });
    const update = () => {
      const kind = dialog.querySelector('[name=kind]').value;
      dialog.querySelector('#bank-request').classList.toggle('hidden', !['credit', 'payout_result'].includes(kind));
      dialog.querySelector('[name=operation_id]').required = ['credit', 'payout_result'].includes(kind);
      dialog.querySelector('#bank-amount').classList.toggle('hidden', kind !== 'credit');
      dialog.querySelector('[name=amount]').required = kind === 'credit';
      dialog.querySelector('#bank-outcome').classList.toggle('hidden', !['payout_result', 'payout_mode'].includes(kind));
      dialog.querySelector('[name=outcome]').innerHTML = [{ value: 'settled', label: 'Confirmed paid' }, { value: 'failed', label: 'Confirmed not paid' }, ...(kind === 'payout_mode' ? [{ value: 'pending', label: 'Pending' }, { value: 'unknown', label: 'Unknown – needs reconciliation' }] : [])].map(item => `<option value="${item.value}">${item.label}</option>`).join('');
      dialog.querySelector('#bank-mode-note').classList.toggle('hidden', kind !== 'payout_mode');
    };
    dialog.querySelector('[name=kind]').addEventListener('change', update);
    if (operation) {
      dialog.querySelector('[name=operation_id]').value = operation.id;
      dialog.querySelector('[name=currency]').value = operation.currency;
      dialog.querySelector('[name=amount]').value = operation.amount || (operation.amount_minor / 100).toFixed(2);
      dialog.querySelector('[name=kind]').value = operation.kind === 'redemption' ? 'payout_result' : 'credit';
    }
    update();
  }

  function copyField(label, value) {
    if (!value) return '';
    return `<div style="margin-top:14px"><span class="muted" style="font-size:10px">${esc(label)}</span><div class="copy-field"><code>${esc(value)}</code><button class="icon-button" type="button" data-action="copy" data-copy="${esc(value)}" aria-label="Copy ${esc(label)}">${icon('copy')}</button></div></div>`;
  }
  function statuses(operation) {
    const chain = operation.chain_status || (operation.txid ? (['settled', 'escrow_confirmed', 'bank_pending', 'bank_unknown', 'payment_failed', 'refund_requested', 'cancelled'].includes(operation.state) ? 'Confirmed transaction' : 'Awaiting chain confirmation') : operation.stage ? human(operation.stage) : 'Not submitted');
    let bank = operation.bank_status;
    if (!bank) bank = ['transfer', 'refund'].includes(operation.kind) ? (operation.kind === 'refund' ? 'Failed payout · cancellation required' : 'Not applicable') : operation.state === 'awaiting_bank' ? 'Awaiting bank credit' : operation.state === 'bank_unknown' ? 'Unknown · reconcile' : operation.state === 'bank_pending' ? 'Payout pending' : operation.state === 'payment_failed' ? 'Confirmed not paid' : operation.state === 'refund_requested' ? 'Failed payout · return requested' : operation.state === 'cancelled' ? 'Cancelled · escrow returned' : operation.state === 'settled' ? 'Bank evidence recorded' : operation.bank_event_id ? 'Bank evidence recorded' : 'Not confirmed';
    return `<div class="status-pair"><div class="status-box"><span>ELEMENTS CHAIN</span><strong>${esc(human(chain))}</strong></div><div class="status-box"><span>SIMULATED BANK</span><strong>${esc(human(bank))}</strong></div></div>`;
  }
  async function openOperation(id) {
    let operation = operations().find(item => item.id === id);
    try { const result = await api(`/api/operations/${encodeURIComponent(id)}`); operation = result.operation || result; }
    catch (failure) { notify(failure.message, true); return; }
    const actions = arr(operation.allowed_actions);
    const actionButtons = [];
    if (actions.includes('approve')) actionButtons.push('<button class="button primary" type="button" data-review-action="approve" data-testid="approve-request">Approve request</button>');
    if (actions.includes('guardian_approve') || actions.includes('guardian-approve')) actionButtons.push('<button class="button primary" type="button" data-review-action="guardian-approve" data-testid="guardian-approve">Approve as guardian</button>');
    if (actions.includes('execute')) actionButtons.push('<button class="button primary" type="button" data-review-action="execute" data-testid="execute-request">Execute next stage</button>');
    if (actions.includes('reject')) actionButtons.push('<button class="button danger" type="button" data-review-action="reject" data-testid="reject-request">Reject</button>');
    if (actions.includes('cancel')) actionButtons.push('<button class="button" type="button" data-review-action="cancel" data-testid="request-escrow-return">Request escrow return</button>');
    const history = arr(operation.history || operation.events);
    const content = `<div class="detail-type">${esc(human(operation.kind))} request</div><div class="detail-amount number">${opMoney(operation)} <span style="font-size:19px">${testCurrency(operation.currency)}</span></div>${badge(operation.state)}${statuses(operation)}${operation.error ? `<div class="inline-warning" role="alert">${esc(operation.error)}</div>` : ''}<div class="detail-section"><h3>Request details</h3><div class="kv"><span>Request ID</span><strong class="mono">${esc(operation.id)}</strong></div><div class="kv"><span>Source account</span><strong>${esc(operation.account_id)}</strong></div><div class="kv"><span>Tenant / customer</span><strong>${esc(operation.tenant || '—')}</strong></div><div class="kv"><span>Destination</span><strong>${esc(operation.destination_name || operation.beneficiary_name || operation.approval_request?.destination || operation.destination || operation.to_account_id || 'Configured reserve credit account')}</strong></div><div class="kv"><span>Issuer</span><strong>${issuer(operation.issuer)}</strong></div><div class="kv"><span>Reference</span><strong>${esc(operation.reference || '—')}</strong></div><div class="kv"><span>Created</span><strong>${date(operation.created_at, true)}</strong></div>${copyField('Bound destination hash', operation.destination_hash)}${copyField('Bank destination reference hash', operation.bank_account_ref_hash)}${copyField('Simulated cash receipt / original redemption', operation.cash_receipt_id)}${copyField('Native asset ID', operation.asset_id)}${copyField('Bound transaction template hash', operation.transaction_template_hash)}${copyField('Elements transaction ID', operation.txid)}</div><div class="detail-section"><h3>Authorization</h3><div class="kv"><span>Separate user approval</span><strong>${operation.user_approved ? 'Recorded' : 'Awaiting authorized approver'}</strong></div><div class="kv"><span>Guardian certificate quorum</span>${quorum(operation)}</div>${operation.request_hash ? copyField('Bound request hash', operation.request_hash) : ''}<div class="kv"><span>Approval expiry</span><strong>${date(operation.expires_at, true)}</strong></div><p class="small-note">A guardian approval comes from your institution’s configured signer. A shared interface does not combine independent institution authority.</p></div>${history.length ? `<div class="detail-section"><h3>Request timeline</h3><ol class="detail-timeline">${history.map(event => `<li><strong>${esc(event.description || human(event.action || event.event || event.state))}</strong><span>${esc(event.actor || '')} · ${date(event.created_at || event.timestamp, true)}</span></li>`).join('')}</ol></div>` : ''}${!actionButtons.length ? '<div class="inline-warning">No action is currently available to your account for this request. Its status and approval policy are enforced by the server.</div>' : ''}`;
    const dialog = openDialog({ title: 'Settlement request', description: 'Review exact amounts, assets and destination before approving.', content, drawer: true, footer: `${button('receipt', 'Receipt', '', 'document')} ${actionButtons.join('')}` });
    dialog.querySelector('[data-action=receipt]')?.addEventListener('click', () => downloadReceipt(operation));
    dialog.querySelectorAll('[data-review-action]').forEach(element => element.addEventListener('click', () => reviewOperation(operation, element.dataset.reviewAction)));
    if (can('simulate_bank') && ['awaiting_bank', 'bank_pending', 'bank_unknown'].includes(operation.state)) {
      const footer = dialog.querySelector('.dialog-footer');
      const bankButton = document.createElement('button'); bankButton.type = 'button'; bankButton.className = 'button'; bankButton.textContent = 'Record bank event'; bankButton.addEventListener('click', () => openBankEvent(operation)); footer.prepend(bankButton);
    }
  }
  function reviewOperation(operation, action) {
    const guardian = action === 'guardian-approve';
    const reject = action === 'reject';
    const execute = action === 'execute';
    const refund = action === 'cancel';
    const title = reject ? 'Reject settlement request' : guardian ? 'Guardian approval' : execute ? 'Execute next settlement stage' : refund ? 'Request escrow return' : 'Approve settlement request';
    const context = guardian ? `Continue in ${user().institution_id || 'your institution'}’s independent approval window. That service verifies the exact request and asks for your institution passphrase. This console never receives the passphrase or signing key.` : execute ? 'The server will validate the current state and execute only the next permitted native chain stage. Bank payout status remains separate.' : reject ? 'The server will verify that rejection is permitted in the current state. This action records your identity and reason.' : refund ? 'This creates a new escrow-return request only after a definitive failed bank payout. A separate checker and independent guardian quorum must authorize the return. Unknown bank outcomes cannot use this workflow.' : 'Your approval is recorded separately from the maker. It does not by itself establish a guardian quorum or a bank payout.';
    openDialog({ title, description: 'Review the request exactly as it is bound for authorization.', formId: 'review-form', content: `<div class="form-context">${esc(context)}</div><div class="confirmation-summary"><span>${esc(human(operation.kind))}</span><strong class="number">${opMoney(operation)} ${testCurrency(operation.currency)}</strong></div><div class="kv"><span>Source</span><strong>${esc(operation.account_id)}</strong></div><div class="kv" style="margin-top:12px"><span>Destination</span><strong style="max-width:65%;overflow-wrap:anywhere">${esc(operation.approval_request?.destination || operation.destination || operation.to_account_id || 'Configured reserve credit account')}</strong></div>${copyField('Bound destination hash', operation.destination_hash)}${copyField('Bound bank account reference hash', operation.bank_account_ref_hash)}${copyField('Simulated cash receipt / original redemption', operation.cash_receipt_id)}${copyField('Native asset ID', operation.asset_id)}${copyField('Bound transaction template hash', operation.transaction_template_hash)}${field('reason', reject ? 'Reason for rejection' : 'Review note (optional)', `<textarea id="field-reason" name="reason" maxlength="500" ${reject ? 'required' : ''} rows="3" placeholder="${reject ? 'Provide an attributable rejection reason' : 'Optional review context'}"></textarea>`)}<label style="display:flex;align-items:flex-start;gap:9px;font-size:11px;margin-top:16px"><input type="checkbox" name="confirmed" required data-testid="confirm-review"><span>I have reviewed the exact amount, test currency, asset and destination for this request.</span></label>`, footer: `<button class="button" type="button" data-close>Cancel</button><button class="button ${reject ? 'danger' : 'primary'}" type="submit" data-testid="confirm-operation">${reject ? 'Confirm rejection' : guardian ? 'Open institution approval' : execute ? 'Execute next stage' : refund ? 'Create escrow-return request' : 'Confirm approval'}</button>`, onSubmit: async (form, dialog) => {
      const reason = new FormData(form).get('reason');
      if (guardian) return openIndependentApproval(operation, form, dialog);
      await submitForm(form, dialog, `/api/operations/${encodeURIComponent(operation.id)}/${action}`, { reason, note: reason }, reject ? 'Request rejected with an attributable reason.' : refund ? 'Escrow-return request created. It requires a new separate approval and guardian quorum.' : execute ? 'Settlement stage submitted. Check the recorded chain and bank status.' : 'Separate user approval recorded.');
    } });
  }
  function handleRotationAction(action) {
    const federation = federationData();
    const rotation = federation.rotation;
    const allowed = rotationActions();
    if (action === 'rotation-record') {
      if (!rotation) return;
      download(JSON.stringify({ document: 'Concord same-chain federation handover', exported_at: new Date().toISOString(),
        viewer: user().id, warning: 'Local sandbox. Bank reserves and payments are simulated.', federation }, null, 2),
        `concord-handover-${String(rotation.id).replace(/[^a-zA-Z0-9_-]/g, '')}.json`, 'application/json');
      return notify('Recorded handover evidence downloaded.');
    }
    const approve = action === 'rotation-approve';
    const prepare = action === 'rotation-prepare';
    const retry = action === 'rotation-retry';
    const permission = prepare ? 'prepare' : retry ? 'retry' : 'advance';
    if (approve ? !allowed.some(value => ['guardian-approve', 'guardian_approve', 'approve'].includes(value)) : !allowed.includes(permission)) return notify('This handover action is not available to your account at the recorded stage.', true);
    if (!prepare && !rotation?.id) return notify('No recorded handover request is available.', true);
    const title = prepare ? 'Prepare the next federation membership' : approve ? 'Review federation authorization' : retry ? 'Retry the recorded handover stage' : 'Advance the federation handover';
    const source = federation.current?.label || federation.current?.id || 'Current membership';
    const incoming = federation.incoming?.label || federation.incoming?.id || 'Prepared incoming membership';
    const explanation = prepare ? 'The coordinator will prepare the incoming membership, collect readiness evidence and inventory reissuance authority and outstanding escrow. New finance requests may be held under the transition policy. Institutions authorize the exact resulting manifest separately.' : approve ? 'Continue in your institution’s separate approval window to inspect the complete source and target policies, audit readiness binding and exact migration templates. This console never receives your institution approval passphrase.' : 'The coordinator will check its durable stage and perform only the next permitted handover action. Retries use the recorded handover and transaction bytes. Review any holds or errors before continuing.';
    openDialog({ title, description: 'Membership changes continue on the existing Elements chain.', formId: 'rotation-review-form',
      content: `<div class="form-context">${esc(explanation)}</div><div class="kv"><span>Source membership</span><strong>${esc(source)}</strong></div><div class="kv section-gap"><span>Incoming membership</span><strong>${esc(incoming)}</strong></div>${rotation?.id ? copyField('Handover request', rotation.id) : ''}${copyField('Existing chain genesis', federation.genesis_hash || state.data.network?.genesis_hash)}${copyField('Prepared manifest binding', rotation?.manifest_hash || rotation?.plan_hash || rotation?.payload_hash)}${rotation?.error ? `<div class="inline-warning">${esc(rotation.error)}</div>` : ''}<label class="rotation-review-confirm"><input type="checkbox" required data-testid="confirm-rotation-review"><span>${prepare ? 'I understand that preparing this handover records a staged change to signing, recovery and treasury membership.' : 'I have reviewed the recorded source, incoming membership, migration scope and current handover stage.'}</span></label>`,
      footer: `<button class="button" type="button" data-close>Cancel</button><button class="button primary" type="submit" data-testid="confirm-rotation-action">${prepare ? 'Prepare handover' : approve ? 'Open institution approval' : retry ? 'Retry recorded stage' : 'Advance handover'}</button>`,
      onSubmit: async (form, dialog) => {
        if (approve) return openRotationApproval(rotation, form, dialog);
        const path = prepare ? '/api/federation/prepare' : `/api/federation/rotations/${encodeURIComponent(rotation.id)}/advance`;
        await submitForm(form, dialog, path, {}, prepare ? 'Handover preparation recorded. Review its durable stage and readiness evidence.' : 'Handover advance requested. Inspect the recorded stage and confirmation evidence.');
      } });
  }
  async function openRotationApproval(rotation, form, dialog) {
    const institution = arr(state.data.guardians).find(guardian => (guardian.institution_id || guardian.id) === user().institution_id);
    const error = dialog.querySelector('#dialog-error');
    let approvalURL;
    try {
      approvalURL = new URL(institution?.approval_url || '');
      if (approvalURL.protocol !== 'http:' || !approvalHostAllowed(approvalURL) || approvalURL.username || approvalURL.password) throw new Error('Invalid institution service address.');
    } catch (_) { error.textContent = 'Your institution’s independent approval service is not configured. No handover certificate was requested.'; error.classList.remove('hidden'); return; }
    const popup = window.open('about:blank', `concord-institution-${user().institution_id}`, 'popup,width=750,height=900');
    if (!popup) { error.textContent = 'Allow the independent institution approval window, then try again.'; error.classList.remove('hidden'); return; }
    const submit = form.querySelector('[type=submit]');
    submit.disabled = true; error.classList.add('hidden');
    try {
      const path = `/api/federation/rotations/${encodeURIComponent(rotation.id)}`;
      const prepared = await api(path + '/prepare-approval', { method: 'POST', body: {} });
      const request = prepared.approval_request;
      if (!request || request.id !== rotation.id || request.kind !== 'federation_rotation') throw new Error('The server did not supply the exact federation authorization.');
      const before = rotation.manifest_hash || rotation.plan_hash || rotation.payload_hash;
      const after = prepared.manifest_hash || prepared.plan_hash || prepared.payload_hash;
      if (before && after && before !== after) throw new Error('The prepared handover changed. Close this review and inspect its updated manifest.');
      pendingApprovals.set(rotation.id, { popup, origin: approvalURL.origin, institution: user().institution_id, certificatePath: path + '/certificates', kind: 'rotation' });
      approvalURL.hash = encodeURIComponent(JSON.stringify({ ...request, return_origin: location.origin }));
      popup.location.href = approvalURL.href;
      dialog.close();
      notify('Review the handover manifest in your institution’s separate approval window. No certificate is recorded yet.');
    } catch (failure) { popup.close(); error.textContent = failure.message; error.classList.remove('hidden'); }
    finally { submit.disabled = false; }
  }
  async function openIndependentApproval(operation, form, dialog) {
    const institution = arr(state.data.guardians).find(guardian => (guardian.institution_id || guardian.id) === user().institution_id);
    const error = dialog.querySelector('#dialog-error');
    let approvalURL;
    try {
      approvalURL = new URL(institution?.approval_url || '');
      if (approvalURL.protocol !== 'http:' || !approvalHostAllowed(approvalURL) || approvalURL.username || approvalURL.password) throw new Error('Invalid institution service address.');
    } catch (_) { error.textContent = 'Your institution’s independent approval service is not configured. No certificate was requested.'; error.classList.remove('hidden'); return; }
    const popup = window.open('about:blank', `concord-institution-${user().institution_id}`, 'popup,width=650,height=820');
    if (!popup) { error.textContent = 'Allow this local site to open the independent institution approval window, then try again.'; error.classList.remove('hidden'); return; }
    const submit = form.querySelector('[type=submit]');
    submit.disabled = true; error.classList.add('hidden');
    try {
      const prepared = await api(`/api/operations/${encodeURIComponent(operation.id)}/prepare-approval`, { method: 'POST', body: {} });
      if (!prepared.approval_request || prepared.id !== operation.id) throw new Error('The server did not provide an exact approval request.');
      const request = prepared.approval_request;
      if (request.amount_minor !== operation.amount_minor || request.currency !== operation.currency || request.asset_id !== operation.asset_id || request.destination_hash !== operation.destination_hash) throw new Error('The request changed. Close this review and inspect the updated operation.');
      pendingApprovals.set(operation.id, { popup, origin: approvalURL.origin, institution: user().institution_id, certificatePath: `/api/operations/${encodeURIComponent(operation.id)}/certificates`, kind: 'settlement' });
      approvalURL.hash = encodeURIComponent(JSON.stringify({ ...request, return_origin: location.origin }));
      popup.location.href = approvalURL.href;
      dialog.close();
      notify('Continue in your institution’s independent approval window. No approval has been recorded yet.');
    } catch (failure) { popup.close(); error.textContent = failure.message; error.classList.remove('hidden'); }
    finally { submit.disabled = false; }
  }
  window.addEventListener('message', async event => {
    const data = event.data;
    if (!data || typeof data !== 'object' || data.type !== 'institution-approval' || typeof data.operation_id !== 'string') return;
    const expected = pendingApprovals.get(data.operation_id);
    if (!expected || event.origin !== expected.origin || event.source !== expected.popup || !data.signature || data.signature.guardian_id !== expected.institution) return;
    pendingApprovals.delete(data.operation_id);
    try {
      await api(expected.certificatePath, { method: 'POST', body: { signature: data.signature } });
      notify(expected.kind === 'rotation' ? 'Independent handover authorization verified and recorded.' : 'Independent institution certificate verified and recorded.');
      await refresh();
    } catch (failure) { notify(`Institution certificate was not recorded: ${failure.message}`, true); }
  });
  async function copyText(value) {
    try { await navigator.clipboard.writeText(value || ''); notify('Copied to clipboard.'); }
    catch (_) { notify('Clipboard access is unavailable. Select and copy the displayed value.', true); }
  }
  function download(content, fileName, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = document.createElement('a'); link.href = url; link.download = fileName; document.body.append(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function csv(rows) {
    return rows.map(row => row.map(value => { let text = String(value ?? ''); if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`; return `"${text.replace(/"/g, '""')}"`; }).join(',')).join('\r\n');
  }
  function exportOperations() {
    download(csv([['Request ID', 'Type', 'Test currency', 'Amount', 'Source account', 'Destination', 'Status', 'Created UTC', 'Elements txid'], ...filteredOperations().map(operation => [operation.id, operation.kind, `Test${operation.currency}`, operation.amount || (operation.amount_minor / 100).toFixed(2), operation.account_id, operation.destination, operation.state, operation.created_at, operation.txid])]), 'concord-settlement-requests.csv', 'text/csv;charset=utf-8');
    notify('Visible settlement requests exported.');
  }
  function exportActivity() {
    download(csv([['Event', 'Actor', 'Request ID', 'Recorded UTC'], ...arr(state.data.activity).map(event => [event.description || event.action || event.event, event.actor_name || event.actor, event.operation_id, event.created_at || event.timestamp])]), 'concord-activity.csv', 'text/csv;charset=utf-8');
    notify('Authorized activity log exported.');
  }
  function downloadReceipt(operation) {
    const receipt = { document: 'Concord local sandbox settlement record', warning: 'Simulated bank reserves. This record is not proof of a real bank payment or a legal redemption promise.', exported_at: new Date().toISOString(), viewer: user().id, issuer: operation.issuer || 'Sandbox issuer (legal entity undecided)', operation };
    download(JSON.stringify(receipt, null, 2), `concord-${String(operation.id).replace(/[^a-zA-Z0-9_-]/g, '')}.json`, 'application/json');
    notify('Sandbox settlement record downloaded.');
  }
  window.addEventListener('hashchange', () => { state.page = location.hash.slice(1) || 'overview'; state.search = ''; state.filter = 'all'; if (state.session?.user) render(); });
  window.setInterval(() => { if (state.session?.user && !dialogs.querySelector('dialog[open]') && !document.activeElement?.matches('input,select,textarea') && document.visibilityState === 'visible') refresh(); }, 30000);
  (async () => {
    try {
      const session = await api('/api/session');
      state.session = session.session || session;
      if (!state.session.user) return renderLogin();
      render(); await refresh();
    } catch (failure) { renderLogin(failure.status === 401 ? '' : `Cannot connect to the local settlement service: ${failure.message}`); }
  })();
})();
