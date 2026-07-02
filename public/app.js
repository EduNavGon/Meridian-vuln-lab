'use strict';

const api = (path, opts = {}) =>
  fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...opts
  }).then(async (r) => {
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data };
  });

const $ = (sel) => document.querySelector(sel);
const money = (n) => (Number(n) || 0).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

let ME = null;

/* ---------------------------- auth ---------------------------- */
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#loginError');
  err.classList.add('hidden');
  const res = await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: $('#email').value, password: $('#password').value })
  });
  if (!res.ok) { err.textContent = res.data.error || 'Login failed'; err.classList.remove('hidden'); return; }
  await boot();
});

$('#logoutBtn').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  location.reload();
});

async function boot() {
  const res = await api('/api/auth/me');
  if (!res.ok) { $('#loginView').classList.remove('hidden'); $('#appView').classList.add('hidden'); return; }
  ME = res.data;
  $('#loginView').classList.add('hidden');
  $('#appView').classList.remove('hidden');
  $('#userName').textContent = ME.name;
  $('#userTitle').textContent = ME.title || ME.role;
  $('#avatar').textContent = (ME.name || 'U').slice(0, 1).toUpperCase();
  render('overview');
}

/* ---------------------------- nav ---------------------------- */
document.querySelectorAll('#nav .nav-item').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#nav .nav-item').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    render(btn.dataset.view);
  });
});

const TITLES = { overview:'Overview', wallet:'Wallet & Transfers', reports:'Invoices & Reports', accounts:'Accounts', billing:'Billing', coupons:'Promotions', integrations:'Integrations', settings:'Settings' };

async function render(view) {
  $('#pageTitle').textContent = TITLES[view] || 'Overview';
  const c = $('#content');
  c.innerHTML = '<div class="text-sm text-ink-500">Loading…</div>';
  try { await VIEWS[view](c); } catch (e) { c.innerHTML = `<div class="text-sm text-red-600">${esc(e.message)}</div>`; }
}

const notify = (msg, ok = true) => {
  const el = document.createElement('div');
  el.className = `fixed bottom-5 right-5 px-4 py-2 rounded-lg text-sm text-white shadow-lg ${ok ? 'bg-emerald-600' : 'bg-red-600'}`;
  el.textContent = msg; document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
};

const card = (title, body, sub = '') =>
  `<div class="card p-5"><div class="flex items-center justify-between mb-3"><h3 class="font-semibold text-ink-900">${title}</h3>${sub}</div>${body}</div>`;

/* ---------------------------- views ---------------------------- */
const VIEWS = {
  async overview(c) {
    const [w, tx] = await Promise.all([api('/api/wallet'), api('/api/transactions?sort=created_at&dir=DESC')]);
    const rows = (tx.data.transactions || []).map((t) => `
      <tr class="border-t border-slate-100">
        <td class="py-2 pr-4 text-ink-700">${esc(t.memo)}</td>
        <td class="py-2 pr-4"><span class="text-xs px-2 py-0.5 rounded-full ${t.kind==='credit'?'bg-emerald-50 text-emerald-700':'bg-slate-100 text-ink-700'}">${esc(t.kind)}</span></td>
        <td class="py-2 pr-4 text-right ${t.kind==='credit'?'text-emerald-700':'text-ink-800'}">${money(t.amount)}</td>
        <td class="py-2 text-right text-xs text-ink-500">${new Date(t.created_at).toLocaleString()}</td>
      </tr>`).join('');
    c.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="card p-5"><div class="text-sm text-ink-500">Available balance</div><div class="text-2xl font-semibold text-ink-900 mt-1">${money(w.data.balance)}</div></div>
        <div class="card p-5"><div class="text-sm text-ink-500">Account credits</div><div class="text-2xl font-semibold text-ink-900 mt-1">${(w.data.credits||0).toLocaleString()}</div></div>
        <div class="card p-5"><div class="text-sm text-ink-500">Role</div><div class="text-2xl font-semibold text-ink-900 mt-1 capitalize">${esc(ME.role)}</div></div>
      </div>
      ${card('Recent activity', `<table class="w-full text-sm"><tbody>${rows || '<tr><td class="py-3 text-ink-500">No activity</td></tr>'}</tbody></table>`)}`;
  },

  async wallet(c) {
    const w = await api('/api/wallet');
    c.innerHTML = `
      <div class="grid md:grid-cols-2 gap-4">
        <div class="card p-5"><div class="text-sm text-ink-500">Available balance</div><div class="text-3xl font-semibold text-ink-900 mt-1">${money(w.data.balance)}</div></div>
        ${card('Send a transfer', `
          <form id="xfer" class="space-y-3">
            <input id="to" placeholder="Recipient email (e.g. bob@meridian.io)" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
            <input id="amt" type="number" step="0.01" placeholder="Amount" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
            <button class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">Send</button>
          </form>`)}
      </div>`;
    $('#xfer').addEventListener('submit', async (e) => {
      e.preventDefault();
      const res = await api('/api/wallet/transfer', { method: 'POST', body: JSON.stringify({ to_email: $('#to').value, amount: $('#amt').value }) });
      notify(res.ok ? `Sent ${money(res.data.sent)} · new balance ${money(res.data.balance)}` : (res.data.error||'Failed'), res.ok);
      if (res.ok) render('wallet');
    });
  },

  async reports(c) {
    const mine = await api('/api/reports/mine');
    const list = (mine.data.documents || []).map((d) => `
      <tr class="border-t border-slate-100">
        <td class="py-2 pr-4 font-mono text-xs text-ink-700">${esc(d.doc_ref)}</td>
        <td class="py-2 pr-4">${esc(d.counterparty)}</td>
        <td class="py-2 pr-4 text-right">${money(d.amount)}</td>
        <td class="py-2 text-right"><span class="text-xs px-2 py-0.5 rounded-full bg-slate-100">${esc(d.status)}</span></td>
      </tr>`).join('');
    c.innerHTML = `
      ${card('My documents', `<table class="w-full text-sm"><tbody>${list||'<tr><td class="py-3 text-ink-500">None</td></tr>'}</tbody></table>`)}
      <div class="mt-4">${card('Report viewer', `
        <p class="text-sm text-ink-500 mb-3">Open a report context, then render the current document.</p>
        <div class="flex gap-2">
          <button id="openCtx" class="bg-slate-100 hover:bg-slate-200 rounded-lg px-4 py-2 text-sm font-medium">1 · Open context</button>
          <button id="renderCtx" class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">2 · Render document</button>
        </div>
        <pre id="renderOut" class="mt-4 bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-auto hidden"></pre>`)}</div>`;
    $('#openCtx').addEventListener('click', async () => { const r = await api('/api/reports/open', { method:'POST', body:'{}' }); notify(r.ok?'Report context opened':'Failed', r.ok); });
    $('#renderCtx').addEventListener('click', async () => {
      const r = await api('/api/reports/render'); const out = $('#renderOut');
      out.classList.remove('hidden'); out.textContent = JSON.stringify(r.data, null, 2);
    });
  },

  async accounts(c) {
    const a = await api('/api/accounts');
    const list = (a.data.accounts || []).map((x) => `
      <tr class="border-t border-slate-100">
        <td class="py-2 pr-4 font-mono text-xs">${esc(x.account_ref)}</td>
        <td class="py-2 pr-4">${esc(x.label)}</td>
        <td class="py-2 text-right">${money(x.balance)}</td>
      </tr>`).join('');
    c.innerHTML = `
      ${card('My accounts', `<table class="w-full text-sm"><tbody>${list}</tbody></table>`)}
      <div class="mt-4">${card('Balance lookup', `
        <form id="lookup" class="flex gap-2">
          <input id="acc" placeholder="Account ref (e.g. ACC-4021)" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          <button class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">Look up</button>
        </form>
        <pre id="accOut" class="mt-4 bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-auto hidden"></pre>`)}</div>`;
    $('#lookup').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await api('/api/accounts/balance?account_id=' + encodeURIComponent($('#acc').value));
      const out = $('#accOut'); out.classList.remove('hidden'); out.textContent = JSON.stringify(r.data, null, 2);
    });
  },

  async billing(c) {
    c.innerHTML = card('Buy account credits', `
      <p class="text-sm text-ink-500 mb-3">Build a cart, pay, then generate your receipt.</p>
      <div id="lines" class="space-y-2"></div>
      <button id="addLine" class="mt-2 text-sm text-brand-700 font-medium">+ Add line</button>
      <div class="flex gap-2 mt-4">
        <button id="setCart" class="bg-slate-100 hover:bg-slate-200 rounded-lg px-4 py-2 text-sm font-medium">Update cart</button>
        <button id="pay" class="bg-slate-100 hover:bg-slate-200 rounded-lg px-4 py-2 text-sm font-medium">Pay</button>
        <button id="receipt" class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">Generate receipt</button>
      </div>
      <pre id="billOut" class="mt-4 bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-auto hidden"></pre>`);
    const lines = $('#lines');
    const addLine = (sku='CREDIT-PACK', qty=1, price=10) => {
      const row = document.createElement('div'); row.className = 'flex gap-2';
      row.innerHTML = `<input class="sku flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-sm" value="${sku}">
        <input class="qty w-24 rounded-lg border border-slate-300 px-3 py-1.5 text-sm" type="number" value="${qty}">
        <input class="price w-28 rounded-lg border border-slate-300 px-3 py-1.5 text-sm" type="number" value="${price}">`;
      lines.appendChild(row);
    };
    addLine();
    $('#addLine').addEventListener('click', () => addLine());
    const readCart = () => Array.from(lines.children).map((r) => ({ sku: r.querySelector('.sku').value, qty: Number(r.querySelector('.qty').value), price: Number(r.querySelector('.price').value) }));
    const show = (d) => { const o = $('#billOut'); o.classList.remove('hidden'); o.textContent = JSON.stringify(d, null, 2); };
    $('#setCart').addEventListener('click', async () => { const r = await api('/api/checkout/cart', { method:'POST', body: JSON.stringify({ items: readCart() }) }); show(r.data); });
    $('#pay').addEventListener('click', async () => { const r = await api('/api/checkout/pay', { method:'POST', body:'{}' }); show(r.data); });
    $('#receipt').addEventListener('click', async () => { const r = await api('/api/checkout/receipt', { method:'POST', body:'{}' }); show(r.data); });
  },

  async coupons(c) {
    const a = await api('/api/coupons');
    const list = (a.data.coupons || []).map((x) => `
      <tr class="border-t border-slate-100">
        <td class="py-2 pr-4 font-mono">${esc(x.code)}</td>
        <td class="py-2 pr-4">${x.discount} credits</td>
        <td class="py-2 text-right">${x.remaining_uses} left</td>
      </tr>`).join('');
    c.innerHTML = `
      ${card('Available promotions', `<table class="w-full text-sm"><tbody>${list}</tbody></table>`)}
      <div class="mt-4">${card('Redeem a code', `
        <form id="redeem" class="flex gap-2">
          <input id="code" placeholder="Code (e.g. WELCOME50)" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          <button class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">Redeem</button>
        </form>`)}</div>`;
    $('#redeem').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await api('/api/coupons/redeem', { method:'POST', body: JSON.stringify({ code: $('#code').value }) });
      notify(r.ok ? `+${r.data.credits_awarded} credits (balance ${r.data.credits_balance})` : (r.data.error||'Failed'), r.ok);
      if (r.ok) render('coupons');
    });
  },

  async integrations(c) {
    const w = await api('/api/webhooks');
    const list = (w.data.webhooks || []).map((x) => `
      <tr class="border-t border-slate-100">
        <td class="py-2 pr-4 font-mono text-xs break-all">${esc(x.target_url)}</td>
        <td class="py-2 text-right"><span class="text-xs px-2 py-0.5 rounded-full bg-slate-100">${esc(x.last_status)}</span></td>
      </tr>`).join('');
    c.innerHTML = `
      ${card('Webhooks', `<table class="w-full text-sm"><tbody>${list||'<tr><td class="py-3 text-ink-500">None yet</td></tr>'}</tbody></table>`)}
      <div class="mt-4">${card('Register webhook', `
        <p class="text-sm text-ink-500 mb-3">We validate the endpoint is reachable before saving it.</p>
        <form id="wh" class="flex gap-2">
          <input id="url" placeholder="https://your-endpoint.example/hook" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          <button class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">Validate & save</button>
        </form>
        <pre id="whOut" class="mt-4 bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-auto hidden"></pre>`)}</div>`;
    $('#wh').addEventListener('submit', async (e) => {
      e.preventDefault();
      const r = await api('/api/webhooks', { method:'POST', body: JSON.stringify({ url: $('#url').value }) });
      const o = $('#whOut'); o.classList.remove('hidden'); o.textContent = JSON.stringify(r.data, null, 2);
      if (r.ok) render('integrations');
    });
  },

  async settings(c) {
    const s = await api('/api/settings');
    c.innerHTML = `
      ${card('Preferences', `<pre class="bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-auto">${esc(JSON.stringify(s.data.settings, null, 2))}</pre>
        <form id="prefs" class="mt-3 flex gap-2">
          <input id="prefJson" placeholder='{"theme":"dark"}' class="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono" />
          <button class="bg-brand-600 hover:bg-brand-700 text-white rounded-lg px-4 py-2 text-sm font-medium">Apply patch</button>
        </form>`)}
      <div class="mt-4">${card('Workspace portability', `
        <p class="text-sm text-ink-500 mb-3">Export your workspace state, or restore it from a blob.</p>
        <div class="flex gap-2">
          <button id="exp" class="bg-slate-100 hover:bg-slate-200 rounded-lg px-4 py-2 text-sm font-medium">Export state</button>
        </div>
        <form id="restoreForm" class="mt-3 flex gap-2">
          <input id="blob" placeholder="Paste base64 state blob" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono" />
          <button class="bg-slate-100 hover:bg-slate-200 rounded-lg px-4 py-2 text-sm font-medium">Restore</button>
        </form>
        <pre id="setOut" class="mt-4 bg-slate-900 text-slate-100 text-xs rounded-lg p-3 overflow-auto hidden"></pre>`)}</div>`;
    const show = (d) => { const o = $('#setOut'); o.classList.remove('hidden'); o.textContent = JSON.stringify(d, null, 2); };
    $('#prefs').addEventListener('submit', async (e) => { e.preventDefault(); let b; try { b = JSON.parse($('#prefJson').value); } catch { notify('Invalid JSON', false); return; } const r = await api('/api/settings', { method:'POST', body: JSON.stringify(b) }); if (r.ok) render('settings'); });
    $('#exp').addEventListener('click', async () => { const r = await api('/api/session/export'); show(r.data); });
    $('#restoreForm').addEventListener('submit', async (e) => { e.preventDefault(); const r = await api('/api/session/restore', { method:'POST', body: JSON.stringify({ state: $('#blob').value }) }); show(r.data); });
  }
};

boot();
