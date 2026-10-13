#!/usr/bin/env python3
import json, os, csv

RAIZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
TRIAGE = os.path.join(RAIZ, 'seguridad', 'semgrep', 'resultados', 'triage.json')
CSV = os.path.join(RAIZ, 'seguridad', 'reportes', 'informe_hallazgos.csv')
OUT = os.path.join(RAIZ, 'seguridad', 'docs', 'informe_final.md')

with open(TRIAGE) as f: tri = json.load(f)['triage']
with open(CSV) as f:
    rows = list(csv.DictReader(f))

# agrupar
crit=[r for r in rows if r['severidad']=='Crítica']
alt=[r for r in rows if r['severidad']=='Alta']
med=[r for r in rows if r['severidad']=='Media']
baj=[r for r in rows if r['severidad']=='Baja']

def tbl(lst):
    if not lst: return '| _Sin hallazgos_ |\n'
    s='| Ubicación | Severidad | CWE | OWASP | Check ID | Estado |\n|---|---|---|---|---|---|\n'
    for x in lst[:30]:
        s+=f"| {x['ubicacion']} | {x['severidad']} | {x['cwe']} | {x['owasp']} | {x['check_id']} | {x['estado']} |\n"
    return s

with open(OUT,'w') as f:
    f.write('# Informe final - SAST (simplificado)\n\n')
    f.write('## Objetivo\nClasificar cada hallazgo: ubicación, severidad (crítica/alta/media/baja) y mapeo a CWE/OWASP Top 10 cuando aplique.\n\n')
    f.write('## Resumen\n')
    f.write(f'- Total: {len(rows)} | Críticos: {len(crit)} | Altos: {len(alt)} | Medios: {len(med)} | Bajos: {len(baj)}\n\n')
    f.write('## Críticos\n')
    f.write(tbl(crit))
    f.write('\n## Altos\n')
    f.write(tbl(alt))
    f.write('\n## Medios\n')
    f.write(tbl(med))
    f.write('\n## Bajos\n')
    f.write(tbl(baj))
    f.write('\n## Recomendación genérica\n')
    f.write('- Usar consultas parametrizadas/prepared statements para SQL.\n- Validar/normalizar rutas y evitar concatenación de comandos.\n- No hardcodear secretos.\n- Aplicar principios de menor privilegio y saneamiento.\n')
print('informe final ok')
