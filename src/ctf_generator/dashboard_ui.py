"""Self-contained HTML pages for the CTFGenerator dashboard.

Pure functions that return COMPLETE, standalone HTML documents (inline
``<style>`` + ``<script>``, no external CDN/font/script/stylesheet
references) so they can be served directly by the stdlib ``http.server``
adapter in :mod:`ctf_generator.dashboard_server` under a strict CSP without
tripping any external-resource rule.

Security model
--------------
The pages are progressive-enhancement *shells*: the browser JS polls the
existing JSON API routes (``/api/leaderboard``, ``/api/progress``,
``/api/feed``, ``/public/scoreboard``) and renders every server-supplied
value with ``textContent`` -- never ``innerHTML`` -- so a malicious team
display name or challenge id cannot inject markup on the client.

For the small amount of data rendered *server-side* (an initial leaderboard
snapshot painted before JS runs) every dynamic value is routed through
:func:`escape`, so a stored ``<script>`` in a team name is emitted as inert
``&lt;script&gt;`` text. All dynamic/user-controlled values -- team display
names, challenge ids, scores -- go through :func:`escape` on the server and
``textContent`` on the client.
"""

from __future__ import annotations

import html
from typing import Iterable, Mapping


def escape(value: object) -> str:
    """HTML-escape an arbitrary value for safe interpolation into markup.

    Coerces to ``str`` first (so ints/None render safely) and escapes
    ``& < > " '`` -- the full set needed for both element text and quoted
    attribute values. This is the single server-side escaping helper every
    dynamic value in this module passes through.
    """
    return html.escape("" if value is None else str(value), quote=True)


_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem;
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
    Helvetica, Arial, sans-serif;
  background: #0f1117; color: #e6e8ee; line-height: 1.5;
}
h1, h2 { font-weight: 650; letter-spacing: -0.01em; }
h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
h2 { font-size: 1.05rem; margin: 0 0 0.75rem; color: #aab0c0; }
.muted { color: #8b91a3; font-size: 0.85rem; }
main { max-width: 960px; margin: 0 auto; }
.grid { display: grid; gap: 1.5rem; grid-template-columns: 1fr; }
@media (min-width: 720px) { .grid { grid-template-columns: 1fr 1fr; } }
.card {
  background: #171a23; border: 1px solid #262a36; border-radius: 12px;
  padding: 1.25rem; overflow-x: auto;
}
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #262a36; }
th { color: #8b91a3; font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
tr:last-child td { border-bottom: none; }
form { display: grid; gap: 0.75rem; }
label { display: grid; gap: 0.25rem; font-size: 0.85rem; color: #aab0c0; }
input, select, button {
  font: inherit; padding: 0.55rem 0.7rem; border-radius: 8px;
  border: 1px solid #333a4a; background: #0f1117; color: #e6e8ee;
}
button {
  background: #3b6ef5; border-color: #3b6ef5; color: #fff; font-weight: 600;
  cursor: pointer;
}
button:hover { background: #305ad6; }
.err { color: #ff7676; font-size: 0.85rem; min-height: 1.2em; }
.ok { color: #4ade80; font-size: 0.85rem; min-height: 1.2em; }
.center { max-width: 360px; margin: 8vh auto 0; }
"""


def _leaderboard_rows_html(rows: Iterable[Mapping[str, object]] | None) -> str:
    """Server-render escaped ``<tr>`` rows for an initial leaderboard paint.

    Every cell is passed through :func:`escape`; a ``<script>`` in a display
    name becomes inert text rather than executable markup.
    """
    if not rows:
        return ""
    out = []
    for row in rows:
        out.append(
            "<tr><td>{rank}</td><td>{name}</td><td>{score}</td><td>{solves}</td></tr>".format(
                rank=escape(row.get("rank", "")),
                name=escape(row.get("display_name", "")),
                score=escape(row.get("score", "")),
                solves=escape(row.get("solve_count", "")),
            )
        )
    return "".join(out)


def login_page(csrf: str | None = None) -> str:
    """The admin login page: a username/password form that POSTs JSON to
    ``/login``, stashes the returned CSRF token in ``sessionStorage``, and
    redirects to ``/`` on success. Fully self-contained."""
    csrf_field = ""
    if csrf:
        csrf_field = '<input type="hidden" name="csrf" value="' + escape(csrf) + '">'
    return (
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTFGenerator — Admin Login</title>
<style>"""
        + _STYLE
        + """</style>
</head>
<body>
<main class="center">
  <div class="card">
    <h1>CTFGenerator</h1>
    <p class="muted">Sign in to the admin dashboard.</p>
    <form id="login-form" autocomplete="off">
      __CSRF_FIELD__
      <label>Username
        <input type="text" id="username" name="username" required autofocus>
      </label>
      <label>Password
        <input type="password" id="password" name="password" required>
      </label>
      <button type="submit">Sign in</button>
      <div class="err" id="error" role="alert"></div>
    </form>
  </div>
</main>
<script>
(function () {
  var form = document.getElementById('login-form');
  var errEl = document.getElementById('error');
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    errEl.textContent = '';
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    }).then(function (resp) {
      return resp.json().then(function (data) { return { ok: resp.ok, data: data }; });
    }).then(function (result) {
      if (result.ok && result.data && result.data.csrf_token) {
        try { sessionStorage.setItem('ctfgen_csrf', result.data.csrf_token); } catch (e) {}
        window.location.href = '/';
      } else {
        errEl.textContent = (result.data && result.data.error) || 'Login failed';
      }
    }).catch(function () { errEl.textContent = 'Network error'; });
  });
})();
</script>
</body>
</html>
"""
    ).replace("__CSRF_FIELD__", csrf_field)


def admin_dashboard_page(initial_rows: Iterable[Mapping[str, object]] | None = None) -> str:
    """The authenticated admin dashboard shell.

    JS polls ``/api/leaderboard``, ``/api/progress`` and ``/api/feed`` and
    renders a live leaderboard, progress table and event feed (all via
    ``textContent``), plus a CSRF-protected form that records a
    solve/attempt event via ``POST /api/event`` using the CSRF token stashed
    at login. ``initial_rows`` (optional) is a server-rendered, HTML-escaped
    first paint of the leaderboard.
    """
    rows_html = _leaderboard_rows_html(initial_rows)
    return (
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTFGenerator — Admin Dashboard</title>
<style>"""
        + _STYLE
        + """</style>
</head>
<body>
<main>
  <header>
    <h1>CTFGenerator — Admin Dashboard</h1>
    <p class="muted">Live competition state. <a href="#" id="logout">Sign out</a></p>
  </header>
  <div class="grid">
    <section class="card">
      <h2>Leaderboard</h2>
      <table>
        <thead><tr><th>#</th><th>Team</th><th>Score</th><th>Solves</th></tr></thead>
        <tbody id="lb-body">__ROWS__</tbody>
      </table>
    </section>
    <section class="card">
      <h2>Record event</h2>
      <form id="event-form">
        <label>Type
          <select id="ev-type">
            <option value="solve">solve</option>
            <option value="attempt">attempt</option>
          </select>
        </label>
        <label>Team id <input type="text" id="ev-team" required></label>
        <label>Challenge id <input type="text" id="ev-chal" required></label>
        <button type="submit">Record</button>
        <div class="ok" id="ev-status" role="status"></div>
      </form>
    </section>
    <section class="card">
      <h2>Team progress</h2>
      <table>
        <thead><tr><th>Team</th><th>Solved</th><th>Attempts</th></tr></thead>
        <tbody id="pg-body"></tbody>
      </table>
    </section>
    <section class="card">
      <h2>Live feed</h2>
      <table>
        <thead><tr><th>Seq</th><th>Type</th><th>Team</th><th>Challenge</th></tr></thead>
        <tbody id="feed-body"></tbody>
      </table>
    </section>
  </div>
</main>
<script>
(function () {
  function csrf() { try { return sessionStorage.getItem('ctfgen_csrf') || ''; } catch (e) { return ''; } }
  function cell(row, value) {
    var td = document.createElement('td');
    td.textContent = (value === null || value === undefined) ? '' : String(value);
    row.appendChild(td);
  }
  function getJSON(url) {
    return fetch(url, { headers: { 'Accept': 'application/json' } }).then(function (r) {
      if (r.status === 401) { window.location.href = '/login'; return null; }
      return r.ok ? r.json() : null;
    });
  }
  function renderLeaderboard(data) {
    if (!data || !data.leaderboard) return;
    var entries = data.leaderboard.entries || [];
    var tb = document.getElementById('lb-body');
    tb.textContent = '';
    entries.forEach(function (e) {
      var tr = document.createElement('tr');
      cell(tr, e.rank);
      cell(tr, e.display_name != null ? e.display_name : e.team_id);
      cell(tr, e.score);
      cell(tr, e.solve_count);
      tb.appendChild(tr);
    });
  }
  function renderProgress(data) {
    if (!data || !data.progress) return;
    var tb = document.getElementById('pg-body');
    tb.textContent = '';
    Object.keys(data.progress).sort().forEach(function (k) {
      var p = data.progress[k];
      var tr = document.createElement('tr');
      cell(tr, p.display_name != null ? p.display_name : p.team_id);
      cell(tr, (p.solved || []).join(', '));
      cell(tr, p.attempts);
      tb.appendChild(tr);
    });
  }
  var lastSeq = 0;
  function renderFeed(data) {
    if (!data || !data.feed) return;
    var tb = document.getElementById('feed-body');
    data.feed.forEach(function (ev) {
      if (ev.seq > lastSeq) lastSeq = ev.seq;
      var tr = document.createElement('tr');
      cell(tr, ev.seq);
      cell(tr, ev.type);
      cell(tr, ev.team_id);
      cell(tr, ev.challenge_id);
      tb.insertBefore(tr, tb.firstChild);
    });
  }
  function refresh() {
    getJSON('/api/leaderboard').then(renderLeaderboard);
    getJSON('/api/progress').then(renderProgress);
    getJSON('/api/feed?since=' + encodeURIComponent(lastSeq)).then(renderFeed);
  }
  document.getElementById('event-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var status = document.getElementById('ev-status');
    status.textContent = '';
    var body = {
      type: document.getElementById('ev-type').value,
      team_id: document.getElementById('ev-team').value,
      challenge_id: document.getElementById('ev-chal').value
    };
    fetch('/api/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (r.status === 401) { window.location.href = '/login'; return; }
      status.className = r.ok ? 'ok' : 'err';
      status.textContent = r.ok ? 'Recorded.' : 'Failed (status ' + r.status + ').';
      if (r.ok) refresh();
    }).catch(function () { status.className = 'err'; status.textContent = 'Network error'; });
  });
  document.getElementById('logout').addEventListener('click', function (ev) {
    ev.preventDefault();
    fetch('/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf() } })
      .then(function () { window.location.href = '/login'; });
  });
  refresh();
  setInterval(refresh, 4000);
})();
</script>
</body>
</html>
"""
    ).replace("__ROWS__", rows_html)


def public_scoreboard_page(initial_rows: Iterable[Mapping[str, object]] | None = None) -> str:
    """The public, read-only scoreboard shell.

    JS reads the public token from ``?token=`` in the URL, polls
    ``/public/scoreboard`` every few seconds, and renders the redacted
    leaderboard via ``textContent``. ``initial_rows`` (optional) is a
    server-rendered, HTML-escaped first paint.
    """
    rows_html = _leaderboard_rows_html(initial_rows)
    return (
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTFGenerator — Scoreboard</title>
<style>"""
        + _STYLE
        + """</style>
</head>
<body>
<main class="center" style="max-width:640px">
  <div class="card">
    <h1>Scoreboard</h1>
    <p class="muted" id="status">Live standings — auto-refreshing.</p>
    <table>
      <thead><tr><th>#</th><th>Team</th><th>Score</th><th>Solves</th></tr></thead>
      <tbody id="sb-body">__ROWS__</tbody>
    </table>
  </div>
</main>
<script>
(function () {
  var token = new URLSearchParams(window.location.search).get('token') || '';
  function cell(row, value) {
    var td = document.createElement('td');
    td.textContent = (value === null || value === undefined) ? '' : String(value);
    row.appendChild(td);
  }
  function render(rows) {
    var tb = document.getElementById('sb-body');
    tb.textContent = '';
    (rows || []).forEach(function (e) {
      var tr = document.createElement('tr');
      cell(tr, e.rank);
      cell(tr, e.display_name);
      cell(tr, e.score);
      cell(tr, e.solve_count);
      tb.appendChild(tr);
    });
  }
  function refresh() {
    fetch('/public/scoreboard?token=' + encodeURIComponent(token), {
      headers: { 'Accept': 'application/json' }
    }).then(function (r) {
      var status = document.getElementById('status');
      if (!r.ok) { status.textContent = 'Unable to load scoreboard (status ' + r.status + ').'; return null; }
      status.textContent = 'Live standings — auto-refreshing.';
      return r.json();
    }).then(function (data) { if (data) render(data.scoreboard); })
      .catch(function () {});
  }
  refresh();
  setInterval(refresh, 5000);
})();
</script>
</body>
</html>
"""
    ).replace("__ROWS__", rows_html)
