#!/usr/bin/env python3
import json, os, csv

RAIZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
TRIAGE = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'triage.json')
STD = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'resultados_sast.json')
CUSTOM = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'resultados_reglas_custom.json')
OUT_TXT = os.path.join(RAIZ, 'seguridad', 'reportes', 'informe_hallazgos.txt')
OUT_CSV = os.path.join(RAIZ, 'seguridad', 'reportes', 'informe_hallazgos.csv')

with open(TRIAGE) as f: tri = {t['key']:t for t in json.load(f)['triage']}

def load(p):
    with open(p) as f: return json.load(f)['results']

items = []
seen = set()
for p in [STD, CUSTOM]:
    for r in load(p):
        k = f"{r['path']}:{r['start']['line']}#{r['check_id']}"
        if k in seen: continue
        seen.add(k)
        t = tri.get(k,{
            'severidad_final':'Media',
            'cwe':'No disponible',
            'owasp':'No disponible',
            'estado':'TP'
        })
        items.append({
            'path': r['path'],
            'line': r['start']['line'],
            'check_id': r['check_id'],
            'message': r['extra'].get('message',''),
            'severidad': t['severidad_final'],
            'cwe': t['cwe'],
            'owasp': t['owasp'],
            'estado': t['estado']
        })

items.sort(key=lambda x:(['Crítica','Alta','Media','Baja'].index(x['severidad']) if x['severidad'] in ['Crítica','Alta','Media','Baja'] else 99, x['path'], x['line']))

# txt
lines=[]
for i in items:
    desc = i['message'].strip().replace('\n',' ')
    if len(desc)>160: desc=desc[:157]+'...'
    lines.append(f"- {i['path']}:{i['line']} | {i['severidad']} | CWE:{i['cwe']} | OWASP:{i['owasp']} | {i['check_id']}\n  {desc}")
with open(OUT_TXT,'w') as f:
    f.write('Hallazgos (formato simple)\n\n')
    f.write('\n'.join(lines))

# csv
with open(OUT_CSV,'w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['ubicacion','archivo','linea','severidad','cwe','owasp','check_id','descripcion','estado'])
    w.writeheader()
    for i in items:
        w.writerow({
            'ubicacion':f"{i['path']}:{i['line']}",
            'archivo':i['path'],
            'linea':i['line'],
            'severidad':i['severidad'],
            'cwe':i['cwe'],
            'owasp':i['owasp'],
            'check_id':i['check_id'],
            'descripcion':i['message'].replace('\n',' ').replace('\r',' ')[:300],
            'estado':i['estado']
        })
print('informe ok', len(items))
