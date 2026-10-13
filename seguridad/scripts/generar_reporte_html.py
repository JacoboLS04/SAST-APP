#!/usr/bin/env python3
import json, os, html

RAIZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
RES = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados')
REP = os.path.join(RAIZ, 'seguridad', 'reportes')
TRIAGE = os.path.join(RES, 'triage.json')
STD = os.path.join(RES, 'resultados_sast.json')
CUSTOM = os.path.join(RES, 'resultados_reglas_custom.json')

SEV_ORDER = ['Crítica', 'Alta', 'Media', 'Baja']
SEV_KEY = {'Crítica': 'crit', 'Alta': 'high', 'Media': 'med', 'Baja': 'low'}

CSS = """
:root{--bg:#0f1420;--card:#1a2233;--fg:#e6ebf5;--mut:#93a1bd;--cri:#e5484d;--alt:#f5a623;--med:#f7cc45;--baj:#46a758;}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:24px 32px;border-bottom:1px solid #26304a}h1{margin:0 0 4px;font-size:20px}
.sub{color:var(--mut);font-size:13px}
.wrap{padding:24px 32px;max-width:1400px;margin:0 auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:var(--card);border:1px solid #26304a;border-radius:10px;padding:12px 16px;min-width:120px}
.card b{display:block;font-size:22px}.card span{color:var(--mut);font-size:12px}
.ctrl{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
input,select{background:#121a2a;color:var(--fg);border:1px solid #2d3a57;border-radius:8px;padding:8px 10px;font:inherit}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid #26304a;font-size:13px}
th{position:sticky;top:0;background:#141c2c;color:var(--mut);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
tr:hover td{background:#1f2a41}
.badge{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}
.badge.crit{background:rgba(229,72,77,.15);color:var(--cri)}.badge.high{background:rgba(245,166,35,.15);color:var(--alt)}
.badge.med{background:rgba(247,204,69,.15);color:var(--med)}.badge.low{background:rgba(70,167,88,.15);color:var(--baj)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.est{color:var(--mut)}code{color:#9ecbff}
"""

JS = """
function filtrar(){
  var q=document.getElementById('q').value.toLowerCase();
  var sev=document.getElementById('sev').value;
  var est=document.getElementById('est').value;
  var ori=document.getElementById('ori');
  var oriv=ori?ori.value:'';
  document.querySelectorAll('#tbl tbody tr').forEach(function(tr){
    var ok=(!q||tr.dataset.txt.indexOf(q)>=0)&&(!sev||tr.dataset.sev===sev)
      &&(!est||tr.dataset.est===est)&&(!oriv||tr.dataset.origen===oriv);
    tr.style.display=ok?'':'none';
  });
}
"""


def esc(s):
    return html.escape(str(s if s is not None else ''))


def norm(v):
    if v is None:
        return 'No disponible'
    if isinstance(v, list):
        return '; '.join(str(x) for x in v) or 'No disponible'
    return str(v)


def load(p):
    with open(p) as f:
        return json.load(f)['results']


def load_triage():
    with open(TRIAGE) as f:
        return {t['key']: t for t in json.load(f)['triage']}


def raw_rows(results, tri, origen):
    rows, seen = [], set()
    for r in results:
        key = f"{r['path']}:{r['start']['line']}#{r['check_id']}"
        if key in seen:
            continue
        seen.add(key)
        md = r['extra'].get('metadata') or {}
        t = tri.get(key, {})
        rows.append({
            'ubicacion': f"{r['path']}:{r['start']['line']}",
            'severidad': t.get('severidad_final', 'Media'),
            'cwe': norm(t.get('cwe') or md.get('cwe') or md.get('cwe_id')),
            'owasp': norm(t.get('owasp') or md.get('owasp')),
            'check_id': r['check_id'],
            'descripcion': (r['extra'].get('message') or '').replace('\n', ' '),
            'estado': t.get('estado', 'TP'),
            'origen': origen,
        })
    return rows


def triage_rows(tri, custom_keys):
    rows = []
    for t in tri.values():
        rows.append({
            'ubicacion': f"{t['path']}:{t['line']}",
            'severidad': t.get('severidad_final', 'Media'),
            'cwe': norm(t.get('cwe')),
            'owasp': norm(t.get('owasp')),
            'check_id': t['check_id'],
            'descripcion': (t.get('message') or '').replace('\n', ' '),
            'estado': t.get('estado', 'TP'),
            'origen': 'Regla propia' if t['key'] in custom_keys else 'Packs estándar',
        })
    return rows


def write_html(path, titulo, subtitulo, rows, con_origen):
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    rows.sort(key=lambda r: (order.get(r['severidad'], 99), r['ubicacion']))
    counts = {s: sum(1 for r in rows if r['severidad'] == s) for s in SEV_ORDER}
    cards = ''.join(
        f'<div class="card"><b>{counts[s]}</b><span>{esc(s)}</span></div>' for s in SEV_ORDER
    )
    origen_th = '<th>Origen</th>' if con_origen else ''
    origen_opts = ''
    if con_origen:
        origen_opts = '<option value="">Origen: todos</option><option>Packs estándar</option><option>Regla propia</option>'
    body = []
    for r in rows:
        txt = esc(f"{r['ubicacion']} {r['check_id']} {r['cwe']} {r['owasp']} {r['descripcion']}".lower())
        origen_td = f"<td>{esc(r['origen'])}</td>" if con_origen else ''
        body.append(
            f"<tr data-sev=\"{esc(r['severidad'])}\" data-est=\"{esc(r['estado'])}\" "
            f"data-origen=\"{esc(r['origen'])}\" data-txt=\"{txt}\">"
            f"<td class=\"mono\">{esc(r['ubicacion'])}</td>"
            f"<td><span class=\"badge {SEV_KEY.get(r['severidad'], 'med')}\">{esc(r['severidad'])}</span></td>"
            f"<td class=\"mono\">{esc(r['cwe'])}</td>"
            f"<td>{esc(r['owasp'])}</td>"
            f"<td class=\"mono\">{esc(r['check_id'])}</td>"
            f"<td>{esc(r['estado'])}</td>"
            f"{origen_td}"
            f"<td>{esc(r['descripcion'][:400])}</td></tr>"
        )
    doc = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(titulo)}</title><style>{CSS}</style></head><body>
<header><h1>{esc(titulo)}</h1><div class="sub">{esc(subtitulo)}</div></header>
<div class="wrap">
<div class="cards"><div class="card"><b>{len(rows)}</b><span>Total</span></div>{cards}</div>
<div class="ctrl">
<input id="q" placeholder="Buscar (archivo, regla, CWE...)" oninput="filtrar()" size="40">
<select id="sev" onchange="filtrar()"><option value="">Severidad: todas</option>
<option>Crítica</option><option>Alta</option><option>Media</option><option>Baja</option></select>
<select id="est" onchange="filtrar()"><option value="">Estado: todos</option>
<option>TP</option><option>FP</option></select>
{origen_opts and f'<select id="ori" onchange="filtrar()">{origen_opts}</select>' or ''}
</div>
<table id="tbl"><thead><tr><th>Ubicación</th><th>Severidad</th><th>CWE</th><th>OWASP</th>
<th>Check ID</th><th>Estado</th>{origen_th}<th>Descripción</th></tr></thead>
<tbody>{''.join(body)}</tbody></table>
</div><script>{JS}</script></body></html>"""
    with open(path, 'w') as f:
        f.write(doc)


def main():
    os.makedirs(REP, exist_ok=True)
    tri = load_triage()
    std = load(STD)
    cus = load(CUSTOM)
    custom_keys = {f"{r['path']}:{r['start']['line']}#{r['check_id']}" for r in cus}

    write_html(os.path.join(REP, 'informe_sast.html'),
               'SAST OptiPlant - escaneo estándar',
               f'Packs p/owasp-top-ten, p/python, p/javascript, p/typescript - {len(std)} alertas brutas',
               raw_rows(std, tri, 'Packs estándar'), False)

    write_html(os.path.join(REP, 'informe_reglas_custom.html'),
               'SAST OptiPlant - regla propia (reglas-sqli-idor.yaml)',
               f'Reglas SQLi (A03) y Broken Access Control (A01) - {len(cus)} alertas brutas',
               raw_rows(cus, tri, 'Regla propia'), False)

    write_html(os.path.join(REP, 'informe.html'),
               'SAST OptiPlant - informe combinado',
               f'Escaneo estándar + regla propia, normalizado por triage - {len(tri)} hallazgos',
               triage_rows(tri, custom_keys), True)

    print('html ok', len(tri))


if __name__ == '__main__':
    main()
