"""Self-contained HTML report: inline CSS/JS, single file, no build step."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment

from argos import __version__
from argos.engine.scanner import ScanResult

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>argos report — {{ result.target }}</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#c9d1d9;--dim:#8b949e;
 --critical:#f85149;--high:#f0883e;--medium:#d29922;--low:#58a6ff;--info:#8b949e;--accent:#238636}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
 font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header{border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:20px}
h1{margin:0;font-size:20px}
h1 span{color:var(--dim);font-weight:normal;font-size:14px}
.meta{color:var(--dim);margin-top:6px;font-size:13px}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.badge{padding:4px 12px;border-radius:20px;font-weight:bold;font-size:13px;
 border:1px solid var(--border);color:#0d1117}
.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}
.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}
.badge.info{background:var(--info)}
.filters{display:flex;gap:6px;margin:10px 0 18px}
.filters button{background:var(--panel);color:var(--text);border:1px solid var(--border);
 border-radius:6px;padding:5px 14px;cursor:pointer;font:inherit;font-size:13px}
.filters button.on{border-color:var(--accent);color:#fff;background:var(--accent)}
.card{background:var(--panel);border:1px solid var(--border);border-left:5px solid var(--info);
 border-radius:6px;padding:14px 16px;margin-bottom:12px}
.card.critical{border-left-color:var(--critical)}
.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}
.card.low{border-left-color:var(--low)}
.card h2{margin:0 0 6px;font-size:15px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{font-size:11px;padding:2px 8px;border-radius:10px;color:#0d1117;font-weight:bold}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}
.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}
.sev.info{background:var(--info)}
.metaline{color:var(--dim);font-size:12px;margin:4px 0 8px;word-break:break-all}
.k{color:var(--low)} .v{color:var(--text)}
.desc{margin:6px 0}
.fix{border-left:3px solid var(--accent);padding:6px 10px;background:#12261a;
 margin:8px 0;border-radius:0 4px 4px 0}
.fix b{color:#3fb950}
pre{background:#010409;border:1px solid var(--border);border-radius:6px;
 padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:6px 0}
h3{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin:14px 0 4px}
.warn{background:#3d2e00;border:1px solid var(--high);border-radius:6px;padding:8px 12px;
 margin-bottom:8px;color:var(--high);font-size:13px}
.footer{color:var(--dim);font-size:12px;margin-top:26px;border-top:1px solid var(--border);
 padding-top:12px}
.section-title{font-size:16px;margin:24px 0 10px;
 border-bottom:1px solid var(--border);padding-bottom:6px}
</style>
</head>
<body><div class="wrap">
<header>
  <h1>argos <span>v{{ version }} — security scan report</span></h1>
  <div class="meta">
    target: <b>{{ result.target }}</b> · profile: {{ result.profile }} ·
    mode: {{ "active" if result.active else "passive" }} ·
    started: {{ started }} · duration: {{ "%.1f"|format(result.duration) }}s ·
    pages: {{ result.pages|length }} · requests: {{ result.requests }}
  </div>
  <div class="badges">
    {% for sev in ["critical","high","medium","low","info"] %}
      {% if counts.get(sev) %}
        <span class="badge {{ sev }}">{{ counts[sev] }} {{ sev }}</span>
      {% endif %}
    {% endfor %}
    {% if not findings %}<span class="badge info">no findings</span>{% endif %}
  </div>
  <div class="filters">
    <button class="on" data-f="all">all ({{ findings|length }})</button>
    {% for sev in ["critical","high","medium","low","info"] %}
      {% if counts.get(sev) %}
        <button data-f="{{ sev }}">{{ sev }} ({{ counts[sev] }})</button>
      {% endif %}
    {% endfor %}
  </div>
</header>

{% if warnings %}
<h3>scan warnings</h3>
{% for w in warnings %}<div class="warn">! {{ w }}</div>{% endfor %}
{% endif %}

{% if findings %}
<div class="section-title">findings</div>
{% for f in findings %}
<div class="card {{ f.severity }}" data-sev="{{ f.severity }}">
  <h2><span class="sev {{ f.severity }}">{{ f.severity }}</span> {{ f.title }}
    <span style="color:var(--dim);font-size:12px">CVSS {{ f.cvss }}{% if f.cwe %}
      · {{ f.cwe }}{% endif %}</span>
  </h2>
  <div class="metaline">
    <span class="k">where:</span> {{ f.url }}{% if f.parameter %}
    (<span class="k">parameter:</span> {{ f.parameter }}){% endif %}
    · <span class="k">plugin:</span> {{ f.plugin }} · id: {{ f.id }}
  </div>
  <div class="desc">{{ f.description }}</div>
  <div class="fix"><b>remediation:</b> {{ f.remediation }}</div>
  {% if f.evidence_request %}
  <h3>evidence — request</h3><pre>{{ f.evidence_request }}</pre>
  {% endif %}
  {% if f.evidence_response %}
  <h3>evidence — response</h3><pre>{{ f.evidence_response }}</pre>
  {% endif %}
</div>
{% endfor %}
{% else %}
<div class="section-title">no findings</div>
<p style="color:var(--dim)">Nothing flagged at this profile/mode. Try
<code>--profile deep --active</code> (target must be in argos.allow).</p>
{% endif %}

<h3>checks run ({{ checks_run|length }})</h3>
<pre>{{ checks_run|join(", ") }}</pre>

<div class="footer">generated by argos v{{ version }} — authorized testing only.
 Interactive filter requires JavaScript; the report is readable without it.</div>
</div>
<script>
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on');
  const f=b.dataset.f;
  document.querySelectorAll('.card').forEach(c=>{
    c.style.display=(f==='all'||c.dataset.sev===f)?'':'none';
  });
}));
</script>
</body></html>
"""


def to_html(result: ScanResult) -> str:
    env = Environment(autoescape=True)  # noqa: S701 - HTML report, escaping required
    tpl = env.from_string(TEMPLATE)
    counts = result.counts()
    return tpl.render(
        result=result,
        version=__version__,
        counts=counts,
        findings=result.findings,
        warnings=result.warnings,
        checks_run=result.checks_run,
        started=datetime.fromtimestamp(result.started_at, tz=UTC).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
    )


def write(result: ScanResult, path: Path) -> None:
    path.write_text(to_html(result), encoding="utf-8")
