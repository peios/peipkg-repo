/* peios packages — client-side browser over the signed repository index.
   Fetches /index/active.json (current versions) and /index/archive.json
   (full version history). Pure static; no build step. */

'use strict';

const state = {
  active: [],
  archive: [],
  byName: new Map(),   // name -> [archive entries], newest first
  filtered: [],        // current filtered active list
  selected: null,      // selected package name
};

const $ = (sel, root = document) => root.querySelector(sel);

/* ---------- formatting helpers ---------- */

function humanSize(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let n = bytes, u = 0;
  while (n >= 1024 && u < units.length - 1) { n /= 1024; u++; }
  const val = u === 0 ? n : n.toFixed(n < 10 ? 2 : 1);
  return `${val} ${units[u]}`;
}

function fmtDate(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return iso || '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}

function relTime(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return iso || '—';
  const secs = (Date.now() - d.getTime()) / 1000;
  const steps = [
    [60, 'second', 1],
    [3600, 'minute', 60],
    [86400, 'hour', 3600],
    [2592000, 'day', 86400],
    [31536000, 'month', 2592000],
    [Infinity, 'year', 31536000],
  ];
  for (const [limit, label, div] of steps) {
    if (secs < limit) {
      const v = Math.max(1, Math.floor(secs / div));
      return `${v} ${label}${v === 1 ? '' : 's'} ago`;
    }
  }
  return fmtDate(iso);
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function highlight(text, q) {
  const safe = esc(text);
  if (!q) return safe;
  const i = text.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return safe;
  // re-find offset in escaped string by escaping the three slices
  const a = esc(text.slice(0, i));
  const b = esc(text.slice(i, i + q.length));
  const c = esc(text.slice(i + q.length));
  return `${a}<mark>${b}</mark>${c}`;
}

/* ---------- data load ---------- */

async function load() {
  try {
    const [activeRes, archiveRes] = await Promise.all([
      fetch('/index/active.json', { cache: 'no-cache' }),
      fetch('/index/archive.json', { cache: 'no-cache' }),
    ]);
    if (!activeRes.ok) throw new Error(`active.json: ${activeRes.status}`);
    const active = await activeRes.json();
    let archive = { packages: [] };
    if (archiveRes.ok) archive = await archiveRes.json();

    state.meta = active;
    state.active = (active.packages || []).slice()
      .sort((a, b) => a.name.localeCompare(b.name));
    state.archive = archive.packages || [];

    for (const p of state.archive) {
      if (!state.byName.has(p.name)) state.byName.set(p.name, []);
      state.byName.get(p.name).push(p);
    }
    for (const list of state.byName.values()) {
      list.sort((a, b) => new Date(b.build?.timestamp || 0) - new Date(a.build?.timestamp || 0));
    }

    renderMeta();
    applyFilter('');
    if (state.filtered.length) select(state.filtered[0].name, { scroll: false });
  } catch (err) {
    console.error(err);
    const tpl = $('#error-tpl').content.cloneNode(true);
    $('#detail').appendChild(tpl);
    $('#count').textContent = '';
  }
}

/* ---------- render: masthead meta ---------- */

function renderMeta() {
  const m = state.meta;
  $('#repo-meta').innerHTML = `
    <div><dt>repository</dt><dd class="accent">${esc(m.repo || 'peios')}</dd></div>
    <div><dt>packages</dt><dd>${state.active.length}</dd></div>
    <div><dt>index</dt><dd>v${esc(m.index_version)}</dd></div>
    <div><dt>updated</dt><dd title="${esc(m.generated_at)}">${esc(relTime(m.generated_at))}</dd></div>
    <div><dt>integrity</dt><dd><span class="signed" title="Repository indexes are Ed25519-signed">signed</span></dd></div>
  `;
}

/* ---------- render: list ---------- */

function applyFilter(q) {
  q = q.trim();
  const lq = q.toLowerCase();
  state.filtered = state.active.filter(p =>
    !lq ||
    p.name.toLowerCase().includes(lq) ||
    (p.description || '').toLowerCase().includes(lq)
  );
  renderList(q);
  renderCount(q);
}

function renderCount(q) {
  const total = state.active.length;
  const n = state.filtered.length;
  $('#count').textContent = q
    ? `${n} of ${total} package${total === 1 ? '' : 's'}`
    : `${total} package${total === 1 ? '' : 's'} · active`;
}

function renderList(q) {
  const list = $('#list');
  const empty = $('#empty');
  if (!state.filtered.length) {
    list.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  list.innerHTML = state.filtered.map((p, i) => `
    <li role="presentation">
      <button class="pkg-row" role="option" data-name="${esc(p.name)}"
              aria-selected="${p.name === state.selected}" style="--i:${i}">
        <span class="pkg-row-top">
          <span class="pkg-name">${highlight(p.name, q)}</span>
          <span class="pkg-ver">${esc(p.version)}</span>
        </span>
        <span class="pkg-desc">${highlight(p.description || '', q)}</span>
      </button>
    </li>`).join('');

  for (const btn of list.querySelectorAll('.pkg-row')) {
    btn.addEventListener('click', () => select(btn.dataset.name, { scroll: true }));
  }
}

/* ---------- render: detail ---------- */

function relationsHTML(p) {
  const rels = [
    ['dependencies', p.dependencies, ''],
    ['optional', p.optional_dependencies, ''],
    ['provides', p.provides, ''],
    ['replaces', p.replaces, ''],
    ['conflicts', p.conflicts, 'is-conflict'],
    ['side effects', p.side_effects, ''],
  ].filter(([, vals]) => Array.isArray(vals) && vals.length);

  if (!rels.length) {
    return `<p class="rel-none">No declared dependencies, conflicts, or provides.</p>`;
  }
  return `<div class="rel-grid">${rels.map(([key, vals, mod]) => `
    <div class="rel">
      <span class="rel-key">${esc(key)}</span>
      <span class="rel-vals">${vals.map(v => `<span class="rel-tag ${mod}">${esc(v)}</span>`).join('')}</span>
    </div>`).join('')}</div>`;
}

function versionsHTML(p) {
  const all = state.byName.get(p.name) || [];
  if (all.length <= 1) return '';
  const rows = all.map(v => {
    const current = v.version === p.version;
    return `<a class="vrow ${current ? 'is-current' : ''}" href="${esc(v.url)}" download>
        <span class="vrow-ver">${esc(v.version)}</span>
        <span class="vrow-date">${esc(fmtDate(v.build?.timestamp))}</span>
        <span class="vrow-size">${esc(humanSize(v.size_compressed))}</span>
        ${current ? '<span class="vrow-cur">current</span>' : ''}
      </a>`;
  }).join('');
  return `<section class="section">
      <h3 class="section-label">version history · ${all.length}</h3>
      <div class="versions">${rows}</div>
    </section>`;
}

function select(name, { scroll = false } = {}) {
  const p = state.active.find(x => x.name === name);
  if (!p) return;
  state.selected = name;

  for (const btn of document.querySelectorAll('.pkg-row')) {
    btn.setAttribute('aria-selected', String(btn.dataset.name === name));
  }

  const installCmd = `peipkg install ${p.name}`;
  const base = p.url.replace(/\/[^/]+$/, '');  // dir holding the sidecars
  const detail = $('#detail');
  detail.classList.remove('is-empty');
  detail.innerHTML = `
    <div class="detail-inner">
      <div class="detail-head">
        <h2 class="detail-title">
          <span class="detail-name">${esc(p.name)}</span>
          <span class="detail-ver">${esc(p.version)}</span>
        </h2>
        <div class="chips">
          <span class="chip chip-arch">${esc(p.architecture)}</span>
          <span class="chip chip-license">${esc(p.license || 'unlicensed')}</span>
          <span class="chip chip-signed">signed</span>
        </div>
        <p class="detail-desc">${esc(p.description || '')}</p>
        ${p.homepage ? `<a class="detail-home" href="${esc(p.homepage)}" target="_blank" rel="noopener noreferrer">${esc(p.homepage)} ↗</a>` : ''}
        <div class="provenance" id="prov-slot"></div>
      </div>

      <div class="detail-body">
        <div class="install">
          <code><span class="tok-cmd">peipkg</span> <span class="tok-sub">install</span> ${esc(p.name)}</code>
          <button class="copy-btn" data-copy="${esc(installCmd)}" data-label="copy">copy</button>
        </div>

        <section class="section">
          <h3 class="section-label">package</h3>
          <dl class="facts">
            <div class="fact"><dt>download</dt><dd>${esc(humanSize(p.size_compressed))}</dd></div>
            <div class="fact"><dt>installed</dt><dd>${esc(humanSize(p.size_installed))}</dd></div>
            <div class="fact"><dt>architecture</dt><dd>${esc(p.architecture)}</dd></div>
            <div class="fact"><dt>built</dt><dd>${esc(fmtDate(p.build?.timestamp))}<br><small>${esc(p.build?.farm_id || '')}</small></dd></div>
          </dl>
          <a class="download" href="${esc(p.url)}" download>
            download .peipkg <span class="size">${esc(humanSize(p.size_compressed))}</span>
          </a>
        </section>

        <section class="section" id="contents-slot">
          <h3 class="section-label">contents</h3>
          <p class="rel-none">loading file list&hellip;</p>
        </section>

        <section class="section">
          <h3 class="section-label">relations</h3>
          ${relationsHTML(p)}
        </section>

        <section class="section">
          <h3 class="section-label">${esc(p.hash?.algorithm || 'checksum')}</h3>
          <div class="hash">
            <span class="hash-algo">${esc(p.hash?.algorithm || 'hash')}</span>
            <span class="hash-val">${esc(p.hash?.value || '—')}</span>
            <button class="copy-btn" data-copy="${esc(p.hash?.value || '')}" data-label="copy">copy</button>
          </div>
        </section>

        <section class="section" id="sec-slot"></section>

        ${versionsHTML(p)}
      </div>
    </div>`;

  for (const btn of detail.querySelectorAll('.copy-btn')) {
    btn.addEventListener('click', () => copy(btn));
  }

  fillSidecars(name, base);

  if (scroll && window.matchMedia('(max-width: 820px)').matches) {
    detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

/* ---------- inspect: sidecar metadata (manifest.json + files.json) ---------- */

const sidecarCache = new Map();

async function fetchSidecars(base) {
  if (sidecarCache.has(base)) return sidecarCache.get(base);
  const out = { manifest: null, files: null };
  try {
    const [mr, fr] = await Promise.all([
      fetch(`${base}/manifest.json`, { cache: 'no-cache' }),
      fetch(`${base}/files.json`, { cache: 'no-cache' }),
    ]);
    if (mr.ok) out.manifest = await mr.json();
    if (fr.ok) out.files = await fr.json();
  } catch (e) {
    console.warn('sidecar fetch failed', e);
  }
  sidecarCache.set(base, out);
  return out;
}

function parseSource(ref) {
  if (!ref) return null;
  const s = String(ref).replace(/^git\+/, '');
  const h = s.indexOf('#');
  const url = h >= 0 ? s.slice(0, h) : s;
  const frag = h >= 0 ? s.slice(h + 1) : '';
  const href = url.replace(/\.git$/, '');
  return {
    href,
    display: href.replace(/^https?:\/\//, ''),
    ref: frag.replace(/^refs\/(tags|heads)\//, ''),
  };
}

function buildTree(entries) {
  const root = { name: '', dirs: new Map(), files: [], count: 0, size: 0 };
  for (const e of entries) {
    const parts = (e.path || '').split('/');
    const fname = parts.pop();
    let node = root;
    root.count++; root.size += e.size || 0;
    for (const part of parts) {
      if (!node.dirs.has(part)) {
        node.dirs.set(part, { name: part, dirs: new Map(), files: [], count: 0, size: 0 });
      }
      node = node.dirs.get(part);
      node.count++; node.size += e.size || 0;
    }
    node.files.push({ name: fname, size: e.size, hash: e.hash });
  }
  return root;
}

function renderTree(node) {
  let html = '';
  const dirs = [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name));
  for (const d of dirs) {
    const open = (d.dirs.size + d.files.length) <= 20 ? ' open' : '';
    html += `<details class="tnode"${open}>
        <summary class="tdir"><span class="tname">${esc(d.name)}/</span><span class="tmeta">${d.count} · ${esc(humanSize(d.size))}</span></summary>
        <div class="tchildren">${renderTree(d)}</div>
      </details>`;
  }
  const files = node.files.slice().sort((a, b) => a.name.localeCompare(b.name));
  for (const f of files) {
    html += `<div class="tfile" title="${esc(f.hash || '')}">
        <span class="tname">${esc(f.name)}</span>
        <span class="tsize">${esc(humanSize(f.size))}</span>
      </div>`;
  }
  return html;
}

async function fillSidecars(name, base) {
  const { manifest, files } = await fetchSidecars(base);
  if (state.selected !== name) return;  // selection moved on; drop stale render

  const prov = document.getElementById('prov-slot');
  if (prov) {
    const src = parseSource(manifest?.build?.source_ref);
    prov.innerHTML = src
      ? `<span class="prov-key">source</span>
         <a class="prov-url" href="${esc(src.href)}" target="_blank" rel="noopener noreferrer">${esc(src.display)}</a>
         ${src.ref ? `<span class="prov-ref">${esc(src.ref)}</span>` : ''}`
      : '';
  }

  const contents = document.getElementById('contents-slot');
  if (contents) {
    if (files && Array.isArray(files.entries) && files.entries.length) {
      const tree = buildTree(files.entries);
      contents.innerHTML = `
        <h3 class="section-label">contents · ${tree.count} file${tree.count === 1 ? '' : 's'} · ${esc(humanSize(tree.size))}</h3>
        <div class="tree">${renderTree(tree)}</div>`;
    } else {
      contents.innerHTML = `<h3 class="section-label">contents</h3><p class="rel-none">File listing unavailable.</p>`;
    }
  }

  const sec = document.getElementById('sec-slot');
  if (sec) {
    const ov = Array.isArray(manifest?.sd_overrides) ? manifest.sd_overrides : [];
    if (ov.length) {
      sec.innerHTML = `<h3 class="section-label">security descriptors · ${ov.length}</h3>
        <div class="rel-grid">${ov.map(o => `
          <div class="rel">
            <span class="rel-key">${esc(o.path || '')}</span>
            <span class="rel-vals"><span class="rel-tag">${esc(typeof o === 'string' ? o : (o.sddl || o.sd || JSON.stringify(o)))}</span></span>
          </div>`).join('')}</div>`;
    } else {
      sec.innerHTML = `<h3 class="section-label">security descriptors</h3>
        <p class="rel-none">All files use inherited / default security descriptors.</p>`;
    }
  }
}

/* ---------- copy ---------- */

async function copy(btn) {
  const text = btn.dataset.copy || '';
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch {}
    ta.remove();
  }
  const label = btn.dataset.label || 'copy';
  btn.textContent = 'copied ✓';
  btn.classList.add('copied');
  clearTimeout(btn._t);
  btn._t = setTimeout(() => { btn.textContent = label; btn.classList.remove('copied'); }, 1400);
}

/* ---------- keyboard ---------- */

function currentIndex() {
  return state.filtered.findIndex(p => p.name === state.selected);
}

function move(delta) {
  if (!state.filtered.length) return;
  let i = currentIndex();
  i = i < 0 ? 0 : Math.min(state.filtered.length - 1, Math.max(0, i + delta));
  const name = state.filtered[i].name;
  select(name, { scroll: false });
  const btn = document.querySelector(`.pkg-row[data-name="${CSS.escape(name)}"]`);
  if (btn) btn.scrollIntoView({ block: 'nearest' });
}

document.addEventListener('keydown', (e) => {
  const q = $('#q');
  const typing = document.activeElement === q;

  if (e.key === '/' && !typing) {
    e.preventDefault(); q.focus(); q.select();
    return;
  }
  if (e.key === 'Escape' && typing) {
    if (q.value) { q.value = ''; applyFilter(''); }
    else q.blur();
    return;
  }
  if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
});

$('#q').addEventListener('input', (e) => applyFilter(e.target.value));

/* ---------- go ---------- */
load();
