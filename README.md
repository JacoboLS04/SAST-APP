# Análisis estático de seguridad (SAST) – Prueba técnica OptiPlant

Este repositorio reúne la parte de análisis estático de la prueba técnica. Incluye la
aplicación de prueba (`app-vulnerable/`: backend Flask y frontend Angular) y, bajo
`seguridad/`, los escaneos de Semgrep, los resultados, los reportes y su documentación.
El documento técnico completo (infraestructura, comparativa de distribuciones y
seguridad) es `documentacion_optiplant.tex`.

Los CWE y categorías OWASP que aparecen en los reportes se toman de los metadatos de
las reglas de Semgrep. No se asignan CVSS ni CVE externos.

## Estructura

```
app-vulnerable/                 aplicación de prueba (Flask + Angular)
seguridad/
├── semgrep/reglas/             reglas-sqli-idor.yaml (regla propia: A03 y A01)
├── semgrep/resultados/         resultados_sast.json, resultados_reglas_custom.json, triage.json
├── scripts/                    reproducción del análisis y generadores de reportes
├── reportes/                   informe_hallazgos.txt|csv y vistas HTML
└── docs/                       informe_final.md
documentacion_optiplant.tex     documento técnico completo
```

## Requisitos

- Python 3.
- Semgrep 1.180.0 disponible en el `PATH`.
- `SEMGREP_CORES=1` en el entorno. En este equipo `semgrep-core` falla con
  `io_uring_queue_init` / «Cannot allocate memory» si se usa más de un núcleo; la
  variable solo fija el paralelismo y no altera el resultado.

## Ejecución

### Completa en un paso

```bash
cd ~/Documentos/SAST
bash seguridad/scripts/reproducir_analisis.sh
```

El script ejecuta los dos escaneos y regenera los reportes. Intenta además generar la
matriz de confusión y las métricas mediante dos generadores que hoy no están en el
repositorio; el resto de los pasos se completa igualmente.

### Paso a paso

Escaneo con los packs estándar:

```bash
export SEMGREP_CORES=1
semgrep scan --metrics=off --jobs 1 --quiet \
  --output seguridad/semgrep/resultados/resultados_sast.json --json \
  --config=p/owasp-top-ten --config=p/python --config=p/javascript --config=p/typescript \
  app-vulnerable
```

Escaneo con la regla propia:

```bash
semgrep scan --metrics=off --jobs 1 --quiet \
  --output seguridad/semgrep/resultados/resultados_reglas_custom.json --json \
  --config seguridad/semgrep/reglas/reglas-sqli-idor.yaml \
  app-vulnerable
```

Generación de reportes:

```bash
python3 seguridad/scripts/generar_triage_simple.py
python3 seguridad/scripts/generar_informe_simple.py
python3 seguridad/scripts/generar_informe_final.py
python3 seguridad/scripts/generar_reporte_html.py
```

## Resultados esperados

| Paso | Alertas | Detalle |
|---|---|---|
| Escaneo estándar | 54 brutas / 27 únicas | 12 ERROR, 15 WARNING |
| Regla propia | 8 brutas / 4 únicas | A01:2025 (Broken Access Control), CWE-639 |
| Triage | 62 decisiones | TP/FP por hallazgo |

Las cifras brutas se duplican porque el árbol contiene una copia anidada
(`app-vulnerable/app-vulnerable`); al normalizar rutas quedan los valores únicos. Los
escaneos son deterministas para la misma versión, árbol y conjunto de reglas.

## Salidas

| Archivo | Contenido |
|---|---|
| `seguridad/semgrep/resultados/resultados_sast.json` | Alertas del escaneo estándar |
| `seguridad/semgrep/resultados/resultados_reglas_custom.json` | Alertas de la regla propia |
| `seguridad/semgrep/resultados/triage.json` | Decisión por hallazgo (TP/FP) |
| `seguridad/reportes/informe_hallazgos.txt` · `.csv` | Listado de hallazgos |
| `seguridad/reportes/informe.html` · `informe_sast.html` · `informe_reglas_custom.html` | Vistas para navegador |
| `seguridad/docs/informe_final.md` | Resume por severidad (crítica, alta, media, baja) |

## Notas

- Los reportes se generan a partir de los JSON de resultados; los JSON crudos no se
  modifican.
- El análisis estático se complementa con revisión manual y con las reglas propias.
  Los detalles metodológicos y las métricas están en `documentacion_optiplant.tex`.
