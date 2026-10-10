"""One self-contained HTML file: inline CSS, no JavaScript, no external resources.

Every dynamic value (hosts, evidence, reasons, registrar names...) is attacker-influenced, so
everything that is not a fixed structural tag goes through esc().
"""

from __future__ import annotations

import html
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from openosint import __version__
from openosint.exposure.models import STATUS_ERROR, STATUS_OK, CheckResult, ExposureReport, Finding
from openosint.exposure.report import catalog_en, catalog_it
from openosint.exposure.report.priorities import sort_key, top_priorities
from openosint.exposure.scoring import INCOMPLETE, REQUIRED_CHECKS

REPORT_VERSION = 1
CATALOGS = {"en": catalog_en.CATALOG, "it": catalog_it.CATALOG}
DYNAMIC_TITLE_IDS = catalog_en.DYNAMIC_TITLE_IDS
CATEGORY_ORDER = ("email", "tls", "registration", "http_headers")
ROME = "Europe/Rome"

CSS = """
:root{--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--bg:#fff;--card:#f6f8fa}
*{box-sizing:border-box}
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:var(--fg);background:var(--bg);margin:0}
main{max-width:860px;margin:0 auto;padding:24px 16px 40px}
h1{font-size:1.5rem;margin:0 0 4px}
h2{font-size:1.2rem;margin:28px 0 10px;border-bottom:2px solid var(--line);padding-bottom:4px;break-after:avoid}
h3{font-size:1rem;margin:0 0 6px}
.meta{color:var(--muted);margin:0}
.head{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin-top:16px}
.badge{width:120px;height:120px;border-radius:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;font-weight:700;text-align:center;padding:6px}
.badge .g{font-size:3rem;line-height:1}.badge .g.long{font-size:1.1rem}
.g-A{background:#1a7f37}.g-B{background:#4c8c2b}.g-C{background:#9a6700}.g-D{background:#bc4c00}.g-F{background:#cf222e}.g-incomplete{background:#57606a}
.score{font-size:1.4rem;font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0;break-inside:avoid}
.sev{display:inline-block;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;border-radius:4px;padding:1px 7px;margin-right:6px;color:#fff;vertical-align:middle}
.sev-critical{background:#82071e}.sev-high{background:#cf222e}.sev-medium{background:#9a6700}.sev-low{background:#0969da}.sev-info{background:#57606a}
.lbl{font-weight:600}
pre.ev{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;background:#fff;border:1px solid var(--line);border-radius:4px;padding:6px 8px;margin:6px 0 0;white-space:pre-wrap;word-break:break-all}
.status{border-left:4px solid #9a6700;background:#fff8c5;padding:6px 10px;margin:10px 0;break-inside:avoid}
.small{font-size:.85rem;color:var(--muted)}
dl.gl dt{font-weight:600;float:left;clear:left;width:150px}dl.gl dd{margin:0 0 4px 160px}
footer{margin-top:32px;padding-top:10px;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
@page{size:A4;margin:15mm}
@media print{body{font-size:11pt;-webkit-print-color-adjust:exact;print-color-adjust:exact}main{max-width:none;padding:0}h2{margin-top:18px}.card{background:#fff}}
"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def format_checked_at(iso: str, lang: str) -> str:
    """EN: UTC. IT: Europe/Rome local time with UTC in brackets (UTC only if tzdata is missing)."""
    utc = datetime.fromisoformat(iso)
    if lang == "it":
        try:
            local = utc.astimezone(ZoneInfo(ROME))
        except ZoneInfoNotFoundError:
            return f"{utc:%d/%m/%Y %H:%M} UTC"
        return f"{local:%d/%m/%Y %H:%M} (ora di Roma) [{utc:%d/%m/%Y %H:%M} UTC]"
    return f"{utc:%Y-%m-%d %H:%M} UTC"


def _title(cat: dict, f: Finding) -> str:
    title = cat["findings"][f.id]["title"]
    if f.id in DYNAMIC_TITLE_IDS:  # the only titles with a placeholder; filled with an integer
        title = title.format(days=int(f.days_left) if f.days_left is not None else "?")
    return title


def _finding_card(cat: dict, f: Finding) -> str:
    text = cat["findings"][f.id]
    ui = cat["ui"]
    return (
        f'<div class="card"><h3><span class="sev sev-{esc(f.severity)}">{esc(cat["severity"][f.severity])}</span>'
        f"{esc(_title(cat, f))}</h3>"
        f'<p><span class="lbl">{esc(ui["why"])}:</span> {esc(text["why_it_matters"])}</p>'
        f'<p><span class="lbl">{esc(ui["fix"])}:</span> {esc(text["how_to_fix"])}</p>'
        f'<p class="small">{esc(ui["evidence"])}:</p><pre class="ev">{esc(f.evidence)}</pre></div>'
    )


def _summary(cat: dict, rep: ExposureReport, priorities: list[Finding]) -> str:
    ui = cat["ui"]
    score = "-" if rep.score is None else rep.score
    if rep.grade == INCOMPLETE:
        missing = ", ".join(cat["category"][c] for c in rep.excluded_checks if c in REQUIRED_CHECKS)
        first = (
            ui["summary_grade_none"]
            if rep.score is None
            else ui["summary_grade_incomplete"].format(missing=missing, score=score)
        )
    else:
        first = ui["summary_grade"].format(grade=rep.grade, score=score)
    issues = [f for f in rep.findings if f.severity != "info"]
    parts = [first]
    if not issues:
        parts.append(ui["summary_none"])
    else:
        counts = ", ".join(
            f"{cat['severity'][s]}: {n}"
            for s in ("critical", "high", "medium", "low")
            if (n := sum(1 for f in issues if f.severity == s))
        )
        key = "summary_issues_one" if len(issues) == 1 else "summary_issues"
        parts.append(ui[key].format(n=len(issues), counts=counts))
        parts.append(ui["summary_top"].format(title=_title(cat, priorities[0])))
    return " ".join(parts)


def _reason_text(cat: dict, code: str | None) -> str:
    """Translated reason; raw English detail never reaches the report (it stays in --json)."""
    return cat["reasons"].get(code or "", cat["reasons"]["unexpected_error"])


def _check_status(cat: dict, check: CheckResult | None) -> str:
    if check is None or check.status == STATUS_OK:
        codes = check.note_codes if check else ()
        return "".join(f'<p class="small">{esc(_reason_text(cat, c))}</p>' for c in codes)
    ui = cat["ui"]
    label = ui["check_error"] if check.status == STATUS_ERROR else ui["check_skipped"]
    return f'<div class="status"><strong>{esc(label)}:</strong> {esc(_reason_text(cat, check.reason_code))} {esc(ui["excluded_note"])}</div>'


def _section(cat: dict, rep: ExposureReport, category: str) -> str:
    check = next((c for c in rep.checks if c.name == category), None)
    items = sorted((f for f in rep.findings if f.category == category), key=sort_key)
    body = "".join(_finding_card(cat, f) for f in items)
    if not items and (check is None or check.status == STATUS_OK):
        body = f'<p class="small">{esc(cat["ui"]["no_findings"])}</p>'
    return f"<section><h2>{esc(cat['category'][category])}</h2>{_check_status(cat, check)}{body}</section>"


def render_html(rep: ExposureReport, lang: str = "en") -> str:
    cat = CATALOGS[lang]
    ui = cat["ui"]
    priorities = top_priorities(rep.findings)
    is_incomplete = rep.grade == INCOMPLETE
    badge_text = ui["grade_incomplete"] if is_incomplete else (rep.grade or "-")
    badge_class = "g-incomplete" if is_incomplete else f"g-{rep.grade}"
    score_label = f"{ui['score_partial']} " if is_incomplete else ""
    score = "-" if rep.score is None else f"{rep.score}/100"
    prio = "".join(_finding_card(cat, f) for f in priorities) or f'<p class="small">{esc(ui["no_priorities"])}</p>'
    sections = "".join(_section(cat, rep, c) for c in CATEGORY_ORDER)
    method = "".join(f"<li>{esc(p)}</li>" for p in ui["method_points"])
    glossary = "".join(f"<dt>{esc(t)}</dt><dd>{esc(d)}</dd>" for t, d in ui["glossary_items"])
    return f"""<!doctype html>
<html lang="{esc(ui['html_lang'])}"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(ui['title'])} - {esc(rep.domain)}</title><style>{CSS}</style></head><body><main>
<header><h1>{esc(ui['title'])}</h1>
<p class="meta">{esc(ui['host'])}: <strong>{esc(rep.domain)}</strong> &middot; {esc(ui['registrable'])}: <strong>{esc(rep.registrable_domain)}</strong></p>
<p class="meta">{esc(ui['checked'])}: {esc(format_checked_at(rep.checked_at, lang))}</p>
<div class="head"><div class="badge {esc(badge_class)}"><span class="g{' long' if is_incomplete else ''}">{esc(badge_text)}</span><span>{esc(ui['grade'])}</span></div>
<div class="score">{esc(score_label)}{esc(ui['score'])}: {esc(score)}</div></div></header>
<section><h2>{esc(ui['summary'])}</h2><p>{esc(_summary(cat, rep, priorities))}</p></section>
<section><h2>{esc(ui['priorities'])}</h2>{prio}</section>
<h2>{esc(ui['details'])}</h2>{sections}
<section><h2>{esc(ui['method'])}</h2><ul>{method}</ul></section>
<section><h2>{esc(ui['glossary'])}</h2><dl class="gl">{glossary}</dl></section>
<footer>{esc(ui['footer'])} &middot; {esc(ui['version'])} {esc(__version__)} &middot; {esc(ui['report_version'])} {esc(REPORT_VERSION)}</footer>
</main></body></html>
"""
