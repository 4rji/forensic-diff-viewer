/* forensic_compare report UI (MVP).
 * Data comes from the inert JSON block #data and is rendered with textContent / attribute
 * setters only. No network access, no HTML injection sinks, no data-derived links. */
(function () {
  'use strict';

  var DATA = JSON.parse(document.getElementById('data').textContent);
  var root = document.getElementById('app');
  // optional build-time banner (not part of the data); render() moves it into the top bar
  var LOGO = document.getElementById('logo');
  if (LOGO) LOGO.hidden = false;

  // ---- storage (per-viewer conveniences only; failures fall back to defaults) -------------
  function load(key, dflt) {
    try {
      var v = window.localStorage.getItem('fc.' + key);
      return v === null ? dflt : JSON.parse(v);
    } catch (e) { return dflt; }
  }
  function save(key, value) {
    try { window.localStorage.setItem('fc.' + key, JSON.stringify(value)); } catch (e) { /* ignore */ }
  }

  // ---- DOM helper ----------------------------------------------------------------------
  function el(tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = String(v);
        else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? '' : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) append(e, arguments[i]);
    return e;
  }
  function append(parent, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(parent, c); }); return; }
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // ---- formatting ------------------------------------------------------------------------
  var STATUS = {
    modified: { label: 'Modified', icon: '✎' },
    added: { label: 'Added', icon: '＋' },
    deleted: { label: 'Deleted', icon: '−' },
    metadata: { label: 'Metadata changed', icon: '≈' },
    unchanged: { label: 'Unchanged', icon: '✓' },
    incomplete: { label: 'Incomplete', icon: '?' }
  };
  var PRIORITY = { 1: 'P1 Critical', 2: 'P2 High', 3: 'P3 Medium', 4: 'P4 Expected', 5: 'P5 None' };

  function statusChip(status) {
    var s = STATUS[status] || { label: status, icon: '' };
    return el('span', { class: 'chip st-' + status }, s.icon + ' ' + s.label);
  }
  function fmtSize(n) {
    if (n === null || n === undefined) return '';
    if (n < 1024) return n + ' B';
    var units = ['KiB', 'MiB', 'GiB', 'TiB'];
    var v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(v < 10 ? 1 : 0) + ' ' + units[i] + ' (' + n + ')';
  }
  function fmtTime(sec) {
    if (sec === null || sec === undefined) return '';
    var d = new Date(sec * 1000);
    if (isNaN(d.getTime())) return String(sec);
    return d.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  }
  var TYPE_CHAR = { file: '-', dir: 'd', symlink: 'l', chr: 'c', blk: 'b', fifo: 'p', socket: 's' };
  function modeString(type, mode) {
    if (mode === null || mode === undefined) return '';
    var s = TYPE_CHAR[type] || '?';
    var spec = [[0o4000, 's', 'S'], [0o2000, 's', 'S'], [0o1000, 't', 'T']];
    for (var i = 0; i < 3; i++) {
      var shift = 6 - 3 * i;
      s += (mode >> shift & 4) ? 'r' : '-';
      s += (mode >> shift & 2) ? 'w' : '-';
      var x = mode >> shift & 1, sp = mode & spec[i][0];
      s += sp ? (x ? spec[i][1] : spec[i][2]) : (x ? 'x' : '-');
    }
    return s;
  }
  function octal(mode) { return mode === null || mode === undefined ? '' : ('0000' + mode.toString(8)).slice(-4); }
  function val(assessed) { return assessed && assessed.state === 'ok' ? assessed.value : null; }
  function sha(entry) { var c = entry && val(entry.content); return c ? c.sha256 : null; }
  function shortHash(h) { return h ? h.slice(0, 12) + '…' : ''; }

  // ---- state -----------------------------------------------------------------------------
  var DEFAULT_FILTERS = {
    status: 'all', hideUnchanged: true, hideExpected: false, sensitiveOnly: false, search: '',
    sortKey: 'priority', sortDir: 1, page: 1
  };
  // The report opens on the file table of the first filesystem section (files are what an
  // analyst reviews first); the overview stays one click away.
  function defaultView() {
    var srcs = DATA.sources || [];
    var fsec = srcs.filter(function (s) { return s.kind === 'filesystem'; })[0] || srcs[0];
    return fsec ? { type: 'source', id: fsec.id } : { type: 'overview' };
  }
  var state = {
    view: defaultView(),
    filters: Object.assign({}, DEFAULT_FILTERS),
    pageSize: load('pageSize', 200),
    selected: null,
    bannersCollapsed: load('bannersCollapsed', false),
    sidebarCollapsed: load('sidebarCollapsed', false)
  };
  var sectionsById = {};
  (DATA.sources || []).forEach(function (s) { sectionsById[s.id] = s; });

  // ---- theme ------------------------------------------------------------------------------
  function preferredTheme() {
    var t = load('theme', null);
    if (t === 'light' || t === 'dark') return t;
    try { return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; } catch (e) { return 'light'; }
  }
  function applyTheme(t) { document.documentElement.setAttribute('data-theme', t); }
  applyTheme(preferredTheme());

  // ---- notices / banners --------------------------------------------------------------------
  var NOTICE_META = {
    'integrity-failed': { cls: 'danger', icon: '⛔', label: 'Integrity FAILED' },
    'reference-mismatch': { cls: 'danger', icon: '⚠', label: 'Reference mismatch' },
    'reference-unverified': { cls: 'warn', icon: '⚠', label: 'Reference unverified' },
    'incomplete': { cls: 'info', icon: '?', label: 'Incomplete analysis' },
    'contents': { cls: 'warn', icon: 'ℹ', label: 'This report contains file contents' }
  };
  function renderBanners() {
    var notices = DATA.notices || [];
    var box = el('div', { class: 'banners', role: 'region', 'aria-label': 'Report notices' });
    if (!notices.length) return box;
    var counts = {};
    notices.forEach(function (n) { counts[n.type] = (counts[n.type] || 0) + 1; });
    var summary = el('div', { class: 'banner-summary' });
    Object.keys(NOTICE_META).forEach(function (t) {
      if (counts[t]) {
        var m = NOTICE_META[t];
        summary.appendChild(el('span', { class: m.cls, 'data-notice': t }, m.icon + ' ' + m.label + ' (' + counts[t] + ')'));
      }
    });
    var toggle = el('button', {
      'aria-expanded': String(!state.bannersCollapsed),
      onclick: function () { state.bannersCollapsed = !state.bannersCollapsed; save('bannersCollapsed', state.bannersCollapsed); render(); }
    }, state.bannersCollapsed ? 'Show details' : 'Collapse');
    box.appendChild(el('div', { class: 'banner banner-bar' }, summary, toggle));
    if (!state.bannersCollapsed) {
      Object.keys(NOTICE_META).forEach(function (t) {
        var items = notices.filter(function (n) { return n.type === t; });
        if (!items.length) return;
        var m = NOTICE_META[t];
        box.appendChild(el('div', { class: 'banner ' + m.cls, 'data-notice': t },
          el('b', null, m.icon + ' ' + m.label + ' (' + items.length + ')'),
          el('ul', { class: 'list' }, items.map(function (n) {
            return el('li', null, n.source ? el('span', { class: 'mono' }, '[' + n.source + '] ') : null, n.message);
          }))));
      });
    }
    return box;
  }

  // ---- top bar ----------------------------------------------------------------------------
  function capField(side, name) {
    var c = DATA.capture && DATA.capture[side];
    var f = c && c.fields && c.fields[name];
    if (!f) return 'not recorded';
    if (f.state === 'conflict') return 'CONFLICT';
    return f.value === null || f.value === undefined ? 'not recorded' : String(f.value);
  }
  function renderTopbar() {
    var integ = DATA.integrity || {};
    var cls = integrityClass(integ.overall);
    var label = integ.overall === 'verified' ? 'Integrity verified' :
      integ.overall === 'failed' ? 'Integrity FAILED' :
      integ.overall === 'not-checked' ? 'Integrity: not checked by this run' : 'Integrity: stable, unverified';
    return el('header', { class: 'topbar' },
      LOGO,
      el('button', {
        'aria-label': 'Toggle sidebar', title: 'Toggle sidebar',
        onclick: function () { state.sidebarCollapsed = !state.sidebarCollapsed; save('sidebarCollapsed', state.sidebarCollapsed); render(); }
      }, '☰'),
      el('div', { class: 'brand' }, 'forensic_compare', el('small', null, 'golden vs current')),
      el('div', { class: 'case' },
        el('span', null, 'Model ', el('b', null, capField('golden', 'device_model')), ' / ', el('b', null, capField('current', 'device_model'))),
        el('span', null, 'Golden captured ', el('b', null, capField('golden', 'captured_at'))),
        el('span', null, 'Current captured ', el('b', null, capField('current', 'captured_at')))),
      el('span', { class: 'chip ' + cls, id: 'integrity-badge', title: integ.disclaimer || '' }, label),
      el('button', {
        id: 'theme-toggle', 'aria-label': 'Toggle light/dark theme',
        onclick: function () {
          var t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
          applyTheme(t); save('theme', t);
        }
      }, 'Light / dark'));
  }

  // ---- sidebar ------------------------------------------------------------------------------
  function navItem(view, label, extra) {
    var current = JSON.stringify(state.view) === JSON.stringify(view);
    return el('button', {
      class: 'nav-item', 'aria-current': current ? 'true' : 'false',
      onclick: function () { go(view); }
    }, el('span', { class: 'label', title: label }, label), extra);
  }
  function sectionChip(s) {
    if (s.kind === 'filesystem') {
      var n = (s.summary && (s.summary.total - s.summary.unchanged)) || 0;
      return el('span', { class: 'chip ' + (s.status === 'compared' ? '' : 'st-incomplete') }, s.status === 'compared' ? n + ' changes' : 'incomplete');
    }
    return el('span', { class: 'chip ' + (s.status === 'incomplete' ? 'st-incomplete' : 'warn') }, s.status);
  }
  function renderSidebar() {
    var top = (DATA.sources || []).filter(function (s) { return !s.parent; });
    var nav = el('nav', { class: 'sidebar', 'aria-label': 'Sections' });
    nav.appendChild(el('div', { class: 'nav-group' }, navItem({ type: 'overview' }, 'Overview')));
    var g = el('div', { class: 'nav-group' }, el('h3', null, 'Sources'));
    top.forEach(function (s) {
      g.appendChild(navItem({ type: 'source', id: s.id }, s.id, sectionChip(s)));
      var children = (DATA.sources || []).filter(function (c) { return c.parent === s.id; });
      if (children.length) {
        var sub = el('div', { class: 'nav-sub' });
        children.forEach(function (c) { sub.appendChild(navItem({ type: 'source', id: c.id }, c.title || c.id, sectionChip(c))); });
        g.appendChild(sub);
      }
    });
    (DATA.unmatched || []).forEach(function (u) {
      g.appendChild(navItem({ type: 'unmatched' }, u.name + ' (' + u.side + ' only)', el('span', { class: 'chip warn' }, 'unmatched')));
    });
    nav.appendChild(g);
    nav.appendChild(el('div', { class: 'nav-group' }, el('h3', null, 'Case'),
      navItem({ type: 'integrity' }, 'Integrity'),
      navItem({ type: 'capture' }, 'Capture metadata'),
      navItem({ type: 'rules' }, 'Expected-change rules'),
      navItem({ type: 'files' }, 'Files not used'),
      navItem({ type: 'tools' }, 'Tools & run')));
    return nav;
  }
  function go(view) {
    state.view = view; state.selected = null; state.filters.page = 1;
    render(); window.scrollTo(0, 0);
  }

  // ---- generic tables -------------------------------------------------------------------------
  function kvTable(rows) {
    var t = el('table', { class: 'kv' });
    var tb = el('tbody');
    rows.forEach(function (r) { if (r) tb.appendChild(el('tr', null, el('th', null, r[0]), el('td', null, r[1]))); });
    t.appendChild(tb);
    return t;
  }
  function simpleTable(headers, rows) {
    var t = el('table');
    t.appendChild(el('thead', null, el('tr', null, headers.map(function (h) { return el('th', null, h); }))));
    var tb = el('tbody');
    rows.forEach(function (r) { tb.appendChild(el('tr', null, r.map(function (c) { return el('td', null, c); }))); });
    t.appendChild(tb);
    return el('div', { class: 'table-wrap' }, t);
  }
  function list(items) {
    if (!items || !items.length) return null;
    return el('ul', { class: 'list' }, items.map(function (i) { return el('li', null, i); }));
  }

  // ---- overview ----------------------------------------------------------------------------
  function renderOverview() {
    var box = el('div');
    box.appendChild(el('div', { class: 'section-head' }, el('h2', null, 'Overview')));
    var comp = DATA.completeness || {};
    box.appendChild(el('div', { class: 'panel' },
      el('h3', null, comp.complete ? 'Analysis complete' : 'Analysis incomplete or limited'),
      list(comp.reasons)));
    var rows = (DATA.sources || []).map(function (s) {
      var sum = s.summary || {};
      return [
        el('button', { class: 'nav-item', onclick: function () { go({ type: 'source', id: s.id }); } }, s.id),
        s.kind, sectionChip(s),
        s.kind === 'filesystem' ? String(sum.modified || 0) : '',
        s.kind === 'filesystem' ? String(sum.added || 0) : '',
        s.kind === 'filesystem' ? String(sum.deleted || 0) : '',
        s.kind === 'filesystem' ? String(sum.metadata || 0) : '',
        s.kind === 'filesystem' ? String(sum.incomplete_any || 0) : '',
        (s.reference && s.reference.notices || []).join(', ')
      ];
    });
    box.appendChild(simpleTable(['Section', 'Kind', 'Status', 'Modified', 'Added', 'Deleted', 'Metadata', 'Incomplete', 'Reference'], rows));
    return box;
  }

  // ---- filesystem section -----------------------------------------------------------------
  function entryMatches(e, f) {
    if (f.status === 'incomplete') { if (!(e.status === 'incomplete' || e.incomplete)) return false; }
    else if (f.status !== 'all' && e.status !== f.status) return false;
    if (f.status === 'all' && f.hideUnchanged && e.status === 'unchanged') return false;
    if (f.hideExpected && e.expectation === 'full' && !e.incomplete) return false;
    if (f.sensitiveOnly && !e.diffs.some(function (d) { return d.sensitive; })) return false;
    if (f.search) {
      var q = f.search.toLowerCase();
      var hay = [e.path, sha(e.golden) || '', sha(e.current) || ''].join('\n').toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  }
  var SORTERS = {
    priority: function (e) { return [e.priority || 9, e.path]; },
    status: function (e) { return [e.status, e.path]; },
    path: function (e) { return [e.path]; },
    size: function (e) { var s = val((e.current || e.golden || {}).size); return [s === null ? -1 : s, e.path]; },
    change: function (e) { return [-e.diffs.length, e.path]; },
    expected: function (e) { return [e.expectation, e.path]; }
  };
  function cmpArr(a, b) {
    for (var i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  }
  function filtered(section) {
    var f = state.filters;
    var key = SORTERS[f.sortKey] || SORTERS.priority;
    return section.entries.filter(function (e) { return entryMatches(e, f); })
      .sort(function (a, b) { return f.sortDir * cmpArr(key(a), key(b)); });
  }
  function changedPair(g, c, fmt) {
    fmt = fmt || String;
    if (g === null || g === undefined) return c === null || c === undefined ? '' : fmt(c);
    if (c === null || c === undefined || g === c) return fmt(g);
    return el('span', { class: 'changed' }, fmt(g), el('span', { class: 'arrow' }, '→'), fmt(c));
  }
  function permsOf(e) { return e ? modeString(val(e.type), val(e.mode)) : null; }
  function ownerOf(e) {
    if (!e) return null;
    var u = val(e.uid), g = val(e.gid);
    return u === null || g === null ? 'not assessed' : u + ':' + g;
  }

  function renderCards(section) {
    var s = section.summary || {};
    var f = state.filters;
    function card(key, label, n, cls, annotation) {
      var pressed = !annotation && f.status === key;
      return el('button', {
        class: 'card ' + (cls || '') + (annotation ? ' annotation' : ''), 'aria-pressed': String(pressed), 'data-card': key,
        onclick: function () {
          if (annotation) return;
          f.status = key; f.page = 1; state.selected = null; render();
        }
      }, el('span', { class: 'n' }, String(n || 0)), el('span', { class: 't' }, label));
    }
    return el('div', { class: 'cards', 'aria-label': 'Summary for this section (before filters)' },
      card('all', 'Total', s.total),
      card('unchanged', 'Unchanged', s.unchanged, 'st-unchanged'),
      card('modified', 'Modified', s.modified, 'st-modified'),
      card('added', 'Added', s.added, 'st-added'),
      card('deleted', 'Deleted', s.deleted, 'st-deleted'),
      card('metadata', 'Metadata changed', s.metadata, 'st-metadata'),
      card('incomplete', 'Incomplete', s.incomplete_any, 'st-incomplete'),
      card('x-expected', 'Expected (annotation)', s.expected_full, '', true),
      card('x-partial', 'Partially expected (annotation)', s.expected_partial, '', true),
      card('x-sensitive', 'Sensitive changes', s.sensitive, '', true));
  }

  function renderFilters(section, shown) {
    var f = state.filters;
    var statuses = [['all', 'All'], ['modified', 'Modified'], ['added', 'Added'], ['deleted', 'Deleted'],
      ['metadata', 'Metadata Changed'], ['unchanged', 'Unchanged'], ['incomplete', 'Incomplete']];
    var group = el('div', { class: 'group', role: 'group', 'aria-label': 'Status filter' });
    statuses.forEach(function (s) {
      group.appendChild(el('button', {
        'aria-pressed': String(f.status === s[0]), 'data-filter': s[0],
        onclick: function () { f.status = s[0]; f.page = 1; state.selected = null; render(); }
      }, s[1]));
    });
    function toggle(key, label, id) {
      var input = el('input', {
        type: 'checkbox', id: id,
        onchange: function (ev) { f[key] = ev.target.checked; f.page = 1; render(); }
      });
      input.checked = !!f[key];
      return el('label', { for: id }, input, label);
    }
    var search = el('input', {
      type: 'search', id: 'search', placeholder: 'Search path, name or hash  ( / )', 'aria-label': 'Search path, name or hash',
      oninput: function (ev) { f.search = ev.target.value; f.page = 1; renderSectionBody(); }
    });
    search.value = f.search;
    return el('div', { class: 'filters' }, group,
      toggle('hideUnchanged', 'Hide unchanged', 'f-hide-unchanged'),
      toggle('hideExpected', 'Hide fully expected', 'f-hide-expected'),
      toggle('sensitiveOnly', 'Sensitive only', 'f-sensitive'),
      search);
  }

  var COLUMNS = [
    ['priority', 'Priority'], ['status', 'Status'], ['path', 'Path'], [null, 'Golden Hash'],
    [null, 'Current Hash'], ['size', 'Size'], [null, 'Permissions'], [null, 'Owner'],
    ['change', 'Change'], ['expected', 'Expected']
  ];
  function renderTable(section, rows) {
    var f = state.filters;
    var thead = el('tr');
    COLUMNS.forEach(function (c) {
      var sorted = c[0] && f.sortKey === c[0];
      thead.appendChild(el('th', { 'aria-sort': sorted ? (f.sortDir > 0 ? 'ascending' : 'descending') : null, scope: 'col' },
        c[0] ? el('button', {
          onclick: function () {
            if (f.sortKey === c[0]) f.sortDir = -f.sortDir; else { f.sortKey = c[0]; f.sortDir = 1; }
            renderSectionBody();
          }
        }, c[1]) : c[1]));
    });
    var tbody = el('tbody');
    rows.forEach(function (e) {
      var g = e.golden, c = e.current;
      var exp = e.expectation === 'full' ? el('span', { class: 'chip ok' }, 'Expected') :
        e.expectation === 'partial' ? el('span', { class: 'chip warn' }, 'Partially expected') : '';
      var tr = el('tr', {
        tabindex: '0', 'aria-selected': String(state.selected === e),
        onclick: function () { state.selected = e; renderSectionBody(); },
        onkeydown: function (ev) { if (ev.key === 'Enter') { state.selected = e; renderSectionBody(); } }
      },
        el('td', null, el('span', { class: 'chip p' + e.priority }, PRIORITY[e.priority] || '')),
        el('td', null, statusChip(e.status), e.incomplete && e.status !== 'incomplete' ? el('span', { class: 'chip st-incomplete', title: e.incomplete_reasons.join('\n') }, 'incomplete') : null),
        el('td', { class: 'path' }, e.path),
        el('td', { class: 'hash', title: sha(g) || '' }, shortHash(sha(g))),
        el('td', { class: 'hash', title: sha(c) || '' }, shortHash(sha(c))),
        el('td', { class: 'num' }, changedPair(g && val(g.size), c && val(c.size))),
        el('td', { class: 'mono' }, changedPair(permsOf(g), permsOf(c))),
        el('td', { class: 'mono' }, changedPair(ownerOf(g), ownerOf(c))),
        el('td', null, e.diffs.map(function (d) { return d.field; }).join(', ')),
        el('td', null, exp));
      tbody.appendChild(tr);
    });
    return el('div', { class: 'table-wrap' }, el('table', { id: 'entries' }, el('thead', null, thead), tbody));
  }

  function renderPager(total) {
    var f = state.filters;
    var pages = Math.max(1, Math.ceil(total / state.pageSize));
    if (f.page > pages) f.page = pages;
    var size = el('select', {
      'aria-label': 'Rows per page',
      onchange: function (ev) { state.pageSize = parseInt(ev.target.value, 10); save('pageSize', state.pageSize); f.page = 1; renderSectionBody(); }
    });
    [25, 50, 100, 200, 500, 1000].forEach(function (n) {
      var o = el('option', { value: String(n) }, String(n));
      if (n === state.pageSize) o.selected = true;
      size.appendChild(o);
    });
    return el('div', { class: 'pager' },
      el('button', { disabled: f.page <= 1, onclick: function () { f.page--; renderSectionBody(); } }, '‹ Prev'),
      el('span', { id: 'page-info' }, 'Page ' + f.page + ' of ' + pages),
      el('button', { disabled: f.page >= pages, onclick: function () { f.page++; renderSectionBody(); } }, 'Next ›'),
      el('label', null, 'Rows per page ', size));
  }

  // ---- detail panel ---------------------------------------------------------------------------
  function assessedCell(a, fmt) {
    if (!a) return el('span', { class: 'muted' }, '—');
    if (a.state === 'error') {
      return el('span', { class: 'na' }, 'not assessed: ' + (a.reason || 'unknown') + (a.log_id ? ' (tool log #' + a.log_id + ')' : ''));
    }
    if (a.state === 'absent') return el('span', { class: 'muted' }, 'none');
    if (a.state === 'n/a') return el('span', { class: 'muted' }, 'n/a');
    return fmt ? fmt(a.value) : String(a.value);
  }
  function fmtContent(v) {
    return el('span', null, v.sha256, el('br'), el('span', { class: 'muted' }, v.kind + ', ' + v.bytes_read + ' bytes read'));
  }
  function fmtSymlink(v) { return el('span', null, v.target, el('div', { class: 'hex' }, 'hex ' + v.target_hex)); }
  function fmtCap(v) { return el('span', null, v.text || '(empty)', el('div', { class: 'hex' }, 'v' + v.version + (v.rootid !== null && v.rootid !== undefined ? ' rootid=' + v.rootid : '') + ' hex ' + v.hex)); }
  function fmtXattrs(v) {
    return el('div', null, Object.keys(v).sort().map(function (k) {
      return el('div', null, el('b', null, k), ' (' + v[k].size + ' B)', el('div', { class: 'hex' }, v[k].hex));
    }));
  }
  var DETAIL_FIELDS = [
    ['type', 'Type', null, ['type']],
    ['mode', 'Mode', function (v, e) { return octal(v) + '  ' + modeString(val(e.type), v); }, ['mode', 'suid', 'sgid']],
    ['uid', 'UID', null, ['uid']],
    ['gid', 'GID', null, ['gid']],
    ['size', 'Size', function (v) { return fmtSize(v); }, ['size']],
    ['mtime', 'mtime', function (v) { return fmtTime(v) + '  (' + v + ')'; }, ['mtime']],
    ['content', 'Content (SHA-256)', fmtContent, ['content']],
    ['symlink', 'Symlink target', fmtSymlink, ['symlink_target']],
    ['capability', 'Capabilities', fmtCap, ['capability']],
    ['xattrs', 'Extended attributes', fmtXattrs, ['xattr:']]
  ];
  // File pages written next to the report: diffs/NNNN.html (line diffs of modified text files)
  // and, with --allfiles, files/NNNN.html (content of every other text file). Only these
  // relative paths are ever used as link targets.
  var PAGE_FILE = /^(diffs|files)\/\d{4,}\.html$/;
  function pageLink(file, label) {
    if (!PAGE_FILE.test(file)) return null;
    return el('a', { class: 'btn', href: file, target: '_blank', rel: 'noopener noreferrer' }, label);
  }
  function filePages(e) {
    var opts = DATA.options || {};
    var d = e.text_diff, v = e.text_view, out = [];
    if (d && d.file) {
      out.push(el('p', { class: 'textdiff' }, pageLink(d.file, 'Open line diff in a new tab ↗'),
        ' ', el('span', { class: 'chip ok' }, '+' + d.added), ' ', el('span', { class: 'chip danger' }, '−' + d.removed)));
    } else if (d && d.reason) {
      out.push(el('p', { class: 'muted' }, 'Line diff not available: ' + d.reason + '.'));
    } else if (e.status === 'modified' && !opts.text_diffs && sha(e.golden) && sha(e.current) && sha(e.golden) !== sha(e.current)) {
      out.push(el('p', { class: 'muted' }, 'Line diffs were turned off for this report (--no-text-diffs).'));
    }
    if (v && v.file) {
      out.push(el('p', { class: 'textdiff' }, pageLink(v.file, 'Open file (' + v.side + ') in a new tab ↗'),
        ' ', el('span', { class: 'chip' }, v.lines + ' lines')));
    } else if (v && v.reason) {
      out.push(el('p', { class: 'muted' }, 'File view not available (' + v.side + '): ' + v.reason + '.'));
    } else if (!opts.all_files && !(d && d.file) && (sha(e.golden) || sha(e.current))) {
      out.push(el('p', { class: 'muted' }, 'File contents are only included for modified text files; run with --allfiles to view every text file.'));
    }
    return out.length ? el('div', null, out) : null;
  }
  function renderDetail(e) {
    var box = el('aside', { class: 'detail', id: 'detail', 'aria-label': 'Entry details' });
    box.appendChild(el('button', { class: 'close', 'aria-label': 'Close details', onclick: function () { state.selected = null; renderSectionBody(); } }, '✕'));
    box.appendChild(el('h3', null, e.path));
    box.appendChild(el('div', { class: 'chips' }, statusChip(e.status), el('span', { class: 'chip p' + e.priority }, PRIORITY[e.priority] || ''),
      e.kind ? el('span', { class: 'chip' }, e.kind) : null,
      e.boot ? el('span', { class: 'chip warn' }, 'boot partition') : null,
      e.expectation !== 'none' ? el('span', { class: 'chip ' + (e.expectation === 'full' ? 'ok' : 'warn') }, e.expectation === 'full' ? 'Expected' : 'Partially expected') : null));
    var pages = filePages(e);
    if (pages) box.appendChild(pages);
    if (e.incomplete_reasons.length) {
      box.appendChild(el('div', { class: 'panel' }, el('b', { class: 'na' }, 'Not fully assessed'), list(e.incomplete_reasons)));
    }
    var diffFields = e.diffs.map(function (d) { return d.field; });
    var t = el('table', { class: 'kv' });
    t.appendChild(el('thead', null, el('tr', null, el('th', null, 'Field'), el('th', null, 'Golden'), el('th', null, 'Current'))));
    var tb = el('tbody');
    DETAIL_FIELDS.forEach(function (fd) {
      var name = fd[0];
      var differs = diffFields.some(function (df) {
        return fd[3].some(function (p) { return p === 'xattr:' ? df.indexOf('xattr:') === 0 : df === p; });
      });
      function cell(entry) {
        if (!entry) return el('span', { class: 'muted' }, 'absent');
        return assessedCell(entry[name], fd[2] ? function (v) { return fd[2](v, entry); } : null);
      }
      tb.appendChild(el('tr', { class: differs ? 'diff' : null }, el('th', null, fd[1]),
        el('td', { class: 'v' }, cell(e.golden)), el('td', { class: 'v' }, cell(e.current))));
    });
    tb.appendChild(el('tr', null, el('th', null, 'Inode'), el('td', { class: 'v' }, e.golden ? String(e.golden.inode) : '—'), el('td', { class: 'v' }, e.current ? String(e.current.inode) : '—')));
    tb.appendChild(el('tr', null, el('th', null, 'atime / ctime / crtime (context)'),
      el('td', { class: 'v' }, e.golden ? ['atime', 'ctime', 'crtime'].map(function (k) { return fmtTime(e.golden.times[k]); }).join('\n') : '—'),
      el('td', { class: 'v' }, e.current ? ['atime', 'ctime', 'crtime'].map(function (k) { return fmtTime(e.current.times[k]); }).join('\n') : '—')));
    t.appendChild(tb);
    box.appendChild(t);
    box.appendChild(el('p', { class: 'muted' }, 'Path bytes (hex): ', el('span', { class: 'hex' }, e.path_hex)));

    if (e.diffs.length) {
      var rows = e.diffs.map(function (d) {
        var cov = d.covered_by ? (d.explicit_sensitive ? el('span', { class: 'chip danger' }, '⚠ sensitive field explicitly allowed by rule ' + d.covered_by) :
          el('span', { class: 'chip ok' }, 'expected by rule ' + d.covered_by)) : el('span', { class: 'chip' }, 'uncovered');
        return [d.field, d.golden === null ? '—' : String(d.golden), d.current === null ? '—' : String(d.current),
          d.sensitive ? el('span', { class: 'chip danger' }, 'sensitive') : '', cov];
      });
      box.appendChild(el('h4', null, 'Differences'));
      box.appendChild(simpleTable(['Field', 'Golden', 'Current', '', 'Coverage'], rows));
    }
    return box;
  }

  // ---- section rendering -----------------------------------------------------------------------
  var sectionBody = null;
  function renderSectionBody() {
    if (!sectionBody) return;
    var section = sectionsById[state.view.id];
    var rows = filtered(section);
    var f = state.filters;
    var start = (f.page - 1) * state.pageSize;
    clear(sectionBody);
    sectionBody.appendChild(el('div', { class: 'countline' },
      el('span', { id: 'displaying' }, 'Displaying ' + rows.length + ' of ' + section.entries.length + ' entries'),
      el('button', { id: 'reset-filters', onclick: function () { state.filters = Object.assign({}, DEFAULT_FILTERS); state.selected = null; render(); } }, 'Reset filters')));
    sectionBody.appendChild(renderPager(rows.length));
    var page = rows.slice(start, start + state.pageSize);
    var split = el('div', { class: 'split' }, renderTable(section, page));
    if (state.selected) split.appendChild(renderDetail(state.selected));
    sectionBody.appendChild(split);
  }
  function fsFacts(section) {
    var rows = [];
    ['golden', 'current'].forEach(function (side) {
      var fs = section.filesystem && section.filesystem[side];
      var inv = section.inventory && section.inventory[side];
      if (!fs) return;
      rows.push([side,
        [fs.fs_type || 'unknown', 'offset ' + fs.offset_bytes + ' B', 'sector ' + fs.sector_size,
          'last mounted: ' + (fs.last_mounted && fs.last_mounted.state === 'ok' ? (fs.last_mounted.value || 'empty') : 'not assessed'),
          'inventory: ' + (inv ? inv.state : 'n/a'),
          fs.needs_recovery ? 'needs_recovery' : null].filter(Boolean).join(' · ')]);
    });
    return kvTable(rows);
  }
  function referencePanel(ref) {
    if (!ref) return null;
    var rows = (ref.items || []).map(function (i) {
      return [i.field, refVal(i.golden), refVal(i.current), el('span', { class: 'chip ' + (i.state === 'ok' ? 'ok' : i.state === 'mismatch' ? 'danger' : 'warn') }, i.state)];
    });
    (ref.context || []).forEach(function (i) { rows.push([i.field + ' (context)', refVal(i.golden), refVal(i.current), '']); });
    return el('div', { class: 'panel' }, el('h3', null, 'Reference (role: ' + (ref.role || 'not declared') + ')'),
      simpleTable(['Field', 'Golden', 'Current', 'State'], rows), list(ref.notes));
  }
  function refVal(r) {
    if (!r) return '';
    if (r.state === 'not-recorded') return el('span', { class: 'muted' }, 'not recorded');
    if (r.state === 'conflict') return el('span', { class: 'chip danger' }, 'Conflict: ' + r.values.map(function (v) { return v.value + ' (' + v.provenance + ')'; }).join(' vs '));
    return el('span', null, String(r.value), ' ', el('span', { class: 'muted' }, '(' + r.values.map(function (v) { return v.provenance; }).join(', ') + ')'));
  }
  function sectionHeader(section) {
    return el('div', null,
      el('div', { class: 'section-head' }, el('h2', null, section.title || section.id),
        el('span', { class: 'chip' }, section.kind), sectionChip(section),
        section.role ? el('span', { class: 'chip' }, 'role: ' + section.role) : null,
        section.boot && section.boot.is_boot ? el('span', { class: 'chip warn' }, 'boot (' + section.boot.sources.join('; ') + ')') : null),
      section.incomplete_reasons && section.incomplete_reasons.length ? el('div', { class: 'panel' }, el('b', { class: 'na' }, 'Incomplete'), list(section.incomplete_reasons)) : null,
      section.warnings && section.warnings.length ? el('div', { class: 'panel' }, el('b', null, 'Warnings'), list(section.warnings)) : null);
  }
  function renderFilesystem(section) {
    var box = el('div');
    box.appendChild(sectionHeader(section));
    box.appendChild(fsFacts(section));
    box.appendChild(referencePanel(section.reference));
    box.appendChild(renderCards(section));
    box.appendChild(renderFilters(section));
    sectionBody = el('div', { id: 'section-body' });
    box.appendChild(sectionBody);
    return box;
  }
  function partSide(p) {
    if (!p) return el('span', { class: 'muted' }, 'absent');
    return el('div', null,
      el('div', { class: 'mono' }, 'start ' + p.start + ' · length ' + p.length + ' · offset ' + p.offset_bytes + ' B'),
      el('div', null, 'signature: ' + (p.signatures.length ? p.signatures.join(', ') : 'none recognized')),
      el('div', { class: 'muted' }, p.status + (p.reason ? ' — ' + p.reason : '')));
  }
  function renderDisk(section) {
    var box = el('div');
    box.appendChild(sectionHeader(section));
    box.appendChild(referencePanel(section.reference));
    var lg = section.layout || {};
    box.appendChild(kvTable([
      ['Golden table', lg.golden ? lg.golden.table_type + ' · ' + lg.golden.sector_size + '-byte sectors' : 'none'],
      ['Current table', lg.current ? lg.current.table_type + ' · ' + lg.current.sector_size + '-byte sectors' : 'none']]));
    if (section.layout_differences && section.layout_differences.length) {
      box.appendChild(el('div', { class: 'panel' }, el('b', null, 'Layout differences'), list(section.layout_differences)));
    }
    var rows = (section.partitions || []).map(function (p) {
      var declared = Object.keys(p.declared || {}).map(function (k) {
        var r = p.declared[k];
        return el('div', null, k + ': ', refVal(r));
      });
      var go1 = p.section_id ? el('button', { onclick: function () { go({ type: 'source', id: p.section_id }); } }, 'Open comparison') : null;
      var go2 = p.mapper_section ? el('button', { onclick: function () { go({ type: 'source', id: p.mapper_section }); } }, 'Open mapper image ' + p.mapper_section) : null;
      return ['p' + p.number, el('span', { class: 'chip ' + (p.status === 'compared' ? 'ok' : p.status === 'encrypted' ? 'warn' : 'st-incomplete') }, p.status),
        partSide(p.golden), partSide(p.current), el('div', null, declared.length ? declared : el('span', { class: 'muted' }, 'none declared')), el('div', null, go1, go2)];
    });
    box.appendChild(el('h3', null, 'Partitions'));
    box.appendChild(simpleTable(['#', 'Analysis', 'Golden', 'Current', 'Declared (capture.yaml)', ''], rows));
    return box;
  }
  function renderImageLevel(section) {
    var box = el('div');
    box.appendChild(sectionHeader(section));
    box.appendChild(el('div', { class: 'panel' }, el('b', null, section.reason || 'Structural analysis not supported: image-level hash comparison only')));
    function side(s) { return s ? [fmtSize(s.size), s.signatures && s.signatures.length ? s.signatures.join(', ') : 'none recognized', el('span', { class: 'mono' }, s.sha256 || 'not hashed')] : ['', '', '']; }
    box.appendChild(simpleTable(['Side', 'Size', 'Signature', 'SHA-256 (pre-analysis)'], [
      ['Golden'].concat(side(section.golden)), ['Current'].concat(side(section.current))]));
    box.appendChild(el('p', null, 'Image hashes: ', el('b', null, section.identical === true ? 'identical' : section.identical === false ? 'different' : 'unknown'),
      el('span', { class: 'muted' }, ' — this is not a file-level comparison.')));
    box.appendChild(referencePanel(section.reference));
    return box;
  }
  function renderUnavailable(section) {
    var box = el('div');
    box.appendChild(sectionHeader(section));
    box.appendChild(el('div', { class: 'panel' }, el('b', { class: 'na' }, section.reason || 'Comparison not possible')));
    function side(s) { return s ? [s.kind, s.signatures && s.signatures.length ? s.signatures.join(', ') : 'none recognized', s.reason || ''] : ['', '', '']; }
    box.appendChild(simpleTable(['Side', 'Detected kind', 'Signature', 'Reason'], [['Golden'].concat(side(section.golden)), ['Current'].concat(side(section.current))]));
    return box;
  }

  // ---- case views -------------------------------------------------------------------------------
  function integrityClass(status) {
    return status === 'verified' ? 'ok' : status === 'failed' ? 'danger' : status === 'not-checked' ? '' : 'warn';
  }
  function verdictChip(v) {
    var label = v.status === 'verified' ? 'verified' : v.status === 'failed' ? 'FAILED — integrity not established' :
      v.status === 'not-checked' ? 'not checked' : 'stable, unverified';
    return el('span', { class: 'chip ' + integrityClass(v.status) }, label);
  }
  function renderIntegrity() {
    var i = DATA.integrity || {};
    var rows = (i.images || []).map(function (v) {
      return [v.side, el('span', { class: 'mono' }, v.name), verdictChip(v), v.reason || '',
        el('div', { class: 'hex' }, (v.expected || []).map(function (x) { return x.sha256 + ' (' + x.file + ')'; }).join('\n') || 'none supplied'),
        el('div', { class: 'hex' }, 'pre  ' + (v.pre || '—')), el('div', { class: 'hex' }, 'post ' + (v.post || '—'))];
    });
    var files = [];
    ['golden', 'current'].forEach(function (side) {
      var r = (i.checksum_files || {})[side] || {};
      Object.keys(r).forEach(function (f) {
        files.push([side, f, (r[f].used || []).join(', '), (r[f].malformed || []).length + ' malformed, ' + (r[f].ignored || []).length + ' ignored']);
      });
    });
    return el('div', null, el('div', { class: 'section-head' }, el('h2', null, 'Integrity'), verdictChip({ status: i.overall })),
      el('p', { class: 'muted' }, i.disclaimer || ''),
      simpleTable(['Side', 'Image', 'Verdict', 'Reason', 'Supplied checksum', 'Pre-analysis', 'Post-analysis'], rows),
      el('h3', null, 'Checksum manifests'),
      files.length ? simpleTable(['Side', 'File', 'Entries used', 'Other'], files) : el('p', { class: 'muted' }, 'No checksum manifests supplied.'));
  }
  function renderCapture() {
    var box = el('div', null, el('div', { class: 'section-head' }, el('h2', null, 'Capture metadata')));
    ['golden', 'current'].forEach(function (side) {
      var c = (DATA.capture || {})[side] || {};
      var rows = Object.keys(c.fields || {}).map(function (k) { return [el('span', { class: 'mono' }, k), refVal(c.fields[k])]; });
      box.appendChild(el('div', { class: 'panel' }, el('h3', null, side === 'golden' ? 'Golden' : 'Current'),
        c.present ? el('p', { class: 'muted mono' }, 'Read from ' + (c.path || 'capture.yaml')) : el('p', { class: 'muted' }, 'No capture file (capture.yaml or <image>.capture.yaml): every value is not recorded.'),
        list(c.errors),
        rows.length ? simpleTable(['Field', 'Value (provenance)'], rows) : null,
        el('h4', null, 'Supporting files (copied verbatim to supporting/' + side + '/; device-info.txt is never parsed)'),
        simpleTable(['File', 'SHA-256', 'Size'], (c.supporting || []).map(function (s) { return [s.name, el('span', { class: 'hex' }, s.sha256), String(s.size)]; }))));
    });
    return box;
  }
  function renderRules() {
    var r = DATA.rules || {};
    var rows = (r.rules || []).map(function (x) {
      return [x.id, x.label, (x.sources || []).join(', '), (x.paths || []).join(', '), (x.statuses || []).join(', '), (x.fields || []).join(', '),
        x.matches ? String(x.matches) : el('span', { class: 'chip warn' }, 'No matches')];
    });
    return el('div', null, el('div', { class: 'section-head' }, el('h2', null, 'Expected-change rules')),
      el('p', null, r.file ? 'Rules file: ' + r.file + ' (sha256 ' + r.sha256 + ')' : 'No rules file loaded.'),
      el('p', { class: 'muted' }, '"Expected" is an analyst annotation, not a verdict that a file is safe. Rules never change a status or hide an entry by default.'),
      rows.length ? simpleTable(['Id', 'Label', 'Sources', 'Paths', 'Statuses', 'Fields', 'Matches'], rows) : null,
      (r.elevate || []).length ? simpleTable(['Elevate sources', 'Paths', 'Reason'], r.elevate.map(function (e) { return [e.sources.join(', '), e.paths.join(', '), e.reason]; })) : null);
  }
  function renderFiles() {
    var box = el('div', null, el('div', { class: 'section-head' }, el('h2', null, 'Files not used')));
    ['golden', 'current'].forEach(function (side) {
      var items = (DATA.not_used || {})[side] || [];
      box.appendChild(el('h3', null, side));
      box.appendChild(items.length ? simpleTable(['File', 'Reason'], items.map(function (x) { return [el('span', { class: 'mono' }, x[0]), x[1]]; })) : el('p', { class: 'muted' }, 'none'));
    });
    return box;
  }
  function renderUnmatched() {
    var rows = (DATA.unmatched || []).map(function (u) {
      return [u.side, el('span', { class: 'mono' }, u.name), u.integrity ? verdictChip(u.integrity) : ''];
    });
    return el('div', null, el('div', { class: 'section-head' }, el('h2', null, 'Unmatched sources')),
      el('p', { class: 'muted' }, 'These images exist on one side only. They are not compared, and their contents are not reported as added or deleted.'),
      simpleTable(['Side', 'Image', 'Integrity'], rows));
  }
  function renderTools() {
    var v = DATA.tool_versions || {};
    return el('div', null, el('div', { class: 'section-head' }, el('h2', null, 'Tools & run')),
      kvTable([['Generated at', DATA.generated_at], ['Command', el('span', { class: 'mono' }, (DATA.command || []).join(' '))],
        ['Mode', DATA.mode], ['Golden input', DATA.inputs && DATA.inputs.golden], ['Current input', DATA.inputs && DATA.inputs.current],
        ['forensic_compare', DATA.tool && DATA.tool.version]]),
      el('h3', null, 'External tool versions (tools actually used)'),
      simpleTable(['Tool', 'Version'], Object.keys(v).sort().map(function (k) { return [k, v[k]]; })),
      el('p', { class: 'muted' }, 'Every external command is recorded in tool_log.jsonl next to this report.'));
  }

  // ---- main render ------------------------------------------------------------------------------
  function render() {
    clear(root);
    sectionBody = null;
    root.className = 'app' + (LOGO ? ' has-logo' : '') + (state.sidebarCollapsed ? ' sidebar-collapsed' : '');
    root.appendChild(renderTopbar());
    root.appendChild(renderBanners());
    var content = el('main', { class: 'content', id: 'content' });
    var v = state.view;
    if (v.type === 'source') {
      var s = sectionsById[v.id];
      content.appendChild(s.kind === 'filesystem' ? renderFilesystem(s) : s.kind === 'disk' ? renderDisk(s) :
        s.kind === 'image-level' ? renderImageLevel(s) : renderUnavailable(s));
    } else if (v.type === 'integrity') content.appendChild(renderIntegrity());
    else if (v.type === 'capture') content.appendChild(renderCapture());
    else if (v.type === 'rules') content.appendChild(renderRules());
    else if (v.type === 'files') content.appendChild(renderFiles());
    else if (v.type === 'tools') content.appendChild(renderTools());
    else if (v.type === 'unmatched') content.appendChild(renderUnmatched());
    else content.appendChild(renderOverview());
    root.appendChild(el('div', { class: 'main' }, renderSidebar(), content));
    if (sectionBody) renderSectionBody();
  }

  document.addEventListener('keydown', function (ev) {
    var tag = (ev.target && ev.target.tagName) || '';
    if (ev.key === '/' && tag !== 'INPUT' && tag !== 'SELECT' && tag !== 'TEXTAREA') {
      var s = document.getElementById('search');
      if (s) { ev.preventDefault(); s.focus(); }
    }
  });

  render();
})();
