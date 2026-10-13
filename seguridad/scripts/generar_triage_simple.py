#!/usr/bin/env python3
import json, os

RAIZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
TRIAGE = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'triage.json')
STD = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'resultados_sast.json')
CUSTOM = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'resultados_reglas_custom.json')

def load(p):
    with open(p) as f:
        return json.load(f)['results']

res = []
seen = set()
for p in [STD, CUSTOM]:
    for r in load(p):
        key = (r['path'], r['start']['line'], r['check_id'])
        if key in seen: continue
        seen.add(key)
        tri = {
            'key': f"{r['path']}:{r['start']['line']}#{r['check_id']}",
            'path': r['path'],
            'line': r['start']['line'],
            'check_id': r['check_id'],
            'message': r['extra'].get('message',''),
            'severity_rule': r['extra'].get('severity','INFO'),
            'cwe': (r['extra'].get('metadata') or {}).get('cwe') or (r['extra'].get('metadata') or {}).get('cwe_id') or 'No disponible',
            'owasp': (r['extra'].get('metadata') or {}).get('owasp') or 'No disponible',
            'estado': 'TP',  # por defecto TP para triage práctico
            'severidad_final': 'Media'
        }
        m = tri['message'].lower()
        if 'sql' in m or 'injection' in m or tri['cwe']=='CWE-89': tri['severidad_final']='Crítica'; tri['estado']='TP'
        elif 'command' in m or 'exec' in m: tri['severidad_final']='Crítica'
        elif 'pickle' in m: tri['severidad_final']='Crítica'
        elif 'path' in m or 'traversal' in m: tri['severidad_final']='Alta'
        elif 'cors' in m: tri['severidad_final']='Media'
        elif 'secret' in m or 'key' in m or 'password' in m: tri['severidad_final']='Alta'
        res.append(tri)
os.makedirs(os.path.dirname(TRIAGE), exist_ok=True)
with open(TRIAGE,'w') as f:
    json.dump({'triage':res}, f, indent=2)
print('triage ok', len(res))
