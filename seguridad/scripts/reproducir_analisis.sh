#!/usr/bin/env bash
# Reproduce análisis SAST (simple): escaneo por defecto + 1 regla personalizada
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$RAIZ" || exit 1

SEMGREP_BIN="${SEMGREP_BIN:-/home/jacobo/.local/bin/semgrep}"
PY3="${PYTHON_BIN:-python3}"
SCAN_STD="seguridad/semgrep/resultados/resultados_sast.json"
SCAN_CUSTOM="seguridad/semgrep/resultados/resultados_reglas_custom.json"
TRIAGE="seguridad/semgrep/resultados/triage.json"
REGLA_CUSTOM="seguridad/semgrep/reglas/reglas-sqli-idor.yaml"
OUT_TXT="seguridad/reportes/informe_hallazgos.txt"
OUT_CSV="seguridad/reportes/informe_hallazgos.csv"
CONFUSION_TXT="seguridad/reportes/matriz_confusion.txt"
METRICAS_TXT="seguridad/reportes/metricas_conclusiones.txt"
INFORME_FINAL="seguridad/docs/informe_final.md"
GUIA="seguridad/docs/guia_paso_a_paso.md"

comprobar() {
  [ -x "$SEMGREP_BIN" ] || { echo "Falta semgrep en $SEMGREP_BIN"; exit 1; }
  command -v "$PY3" >/dev/null 2>&1 || { echo "Falta python3"; exit 1; }
}

scan_std() {
  echo "==> Escaneo por defecto (packs OWASP/Python/JS/TS)"
  SEMGREP_CORES=1 "$SEMGREP_BIN" scan --metrics=off --jobs 1 --quiet --output "$SCAN_STD" --json \
    --config=p/owasp-top-ten --config=p/python --config=p/javascript --config=p/typescript app-vulnerable
  echo "    -> $(python3 -c 'import json;print(len(json.load(open("'$SCAN_STD'"))["results"]))') hallazgos"
}

scan_custom() {
  echo "==> Escaneo con regla personalizada"
  SEMGREP_CORES=1 "$SEMGREP_BIN" scan --metrics=off --jobs 1 --quiet --output "$SCAN_CUSTOM" --json \
    --config "$REGLA_CUSTOM" app-vulnerable
  echo "    -> $(python3 -c 'import json;print(len(json.load(open("'$SCAN_CUSTOM'"))["results"]))') hallazgos"
}

generar() {
  echo "==> Generando triage, informe, matriz y métricas"
  $PY3 seguridad/scripts/generar_triage_simple.py
  $PY3 seguridad/scripts/generar_informe_simple.py
  $PY3 seguridad/scripts/generar_matriz_confusion.py
  $PY3 seguridad/scripts/generar_metricas_conclusiones.py
  $PY3 seguridad/scripts/generar_informe_final.py
  $PY3 seguridad/scripts/generar_reporte_html.py
}

comprobar
scan_std
scan_custom
generar
echo "==> Completado. Ver: $GUIA, $INFORME_FINAL, $OUT_TXT, $OUT_CSV, $CONFUSION_TXT, $METRICAS_TXT, seguridad/reportes/informe*.html"
