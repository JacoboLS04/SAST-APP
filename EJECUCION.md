# Ejecución abreviada del proyecto (fish)

Comandos cortos para ejecutar el proyecto **SAST OptiPlant** sin pegar la línea
completa en la consola. Están definidos como funciones de **fish** en
`~/.config/fish/config.fish`.

> Distro: CachyOS · Shell: fish · `SEMGREP_CORES=1` ya queda exportado por la config
> (mitiga el fallo `io_uring_queue_init` / «Cannot allocate memory» en este equipo).

## Requisitos (una sola vez)

```fish
# Comprobar que las funciones están cargadas en la sesión actual
functions -n | string match "sast*"
functions -n | string match "app-*"

# Si acabas de añadirlas, recarga la config sin abrir otra terminal
source ~/.config/fish/config.fish
```

Herramientas necesarias y estado en este equipo:

| Herramienta | Ruta / estado |
|---|---|
| `semgrep` | `/home/jacobo/.local/bin/semgrep` (1.180.0) |
| `python3` | `/usr/bin/python3` |
| `node` / `npm` | `/usr/bin/node`, `/usr/bin/npm` |
| `docker` | `/usr/local/bin/docker` |
| `bandit` | **no instalado** (comparativa opcional) |
| `pdflatex` | **no instalado** (compilar el `.tex` es opcional) |

## Comandos disponibles

| Comando | Qué hace |
|---|---|
| `sast` | **Pipeline completo**: escaneo estándar + escaneo custom + reportes |
| `sast-std` | Escaneo Semgrep con los packs estándar (OWASP, python, javascript, typescript) |
| `sast-custom` | Escaneo Semgrep con la regla propia `reglas-sqli-idor.yaml` |
| `sast-reportes` | Regenera `triage.json`, `informe_hallazgos.txt|csv`, `docs/informe_final.md` y las vistas `.html` |
| `sast-resumen` | Muestra los conteos de los resultados generados |
| `app-backend` | Levanta la API Flask en `http://localhost:5000/api` |
| `app-frontend` | Levanta el frontend Angular en `http://localhost:4200` |
| `app-lint` | ESLint del frontend Angular |
| `sast-doc` | Compila `documentacion_optiplant.tex` a PDF (requiere `pdflatex`) |

## Ejecución del proyecto al completo

```fish
# 1) Análisis estático completo (escaneos + reportes)
sast

# 2) Ver los resultados
sast-resumen

# 3) (Opcional) Levantar la aplicación en dos terminales
app-backend     # terminal 1
app-frontend    # terminal 2

# 4) (Opcional) Lint del frontend
app-lint

# 5) (Opcional) Compilar la documentación LaTeX
sast-doc
```

### Arranque en frío (primera vez)

```fish
# Backend
cd ~/Documentos/SAST/app-vulnerable/backend
python3 -m venv .venv; and source .venv/bin/activate.fish
pip install -r requirements.txt
python3 app.py

# Frontend (una vez, para instalar dependencias)
cd ~/Documentos/SAST/app-vulnerable/frontend
npm install
```

Después de eso ya puedes usar `app-backend` / `app-frontend` directamente.

## Qué genera cada paso

| Salida | Ruta |
|---|---|
| Resultados Semgrep estándar (JSON) | `seguridad/semgrep/resultados/resultados_sast.json` |
| Resultados regla propia (JSON) | `seguridad/semgrep/resultados/resultados_reglas_custom.json` |
| Triage (TP/FP por hallazgo) | `seguridad/semgrep/resultados/triage.json` |
| Informe de hallazgos | `seguridad/reportes/informe_hallazgos.txt` · `.csv` |
| Informe final | `seguridad/docs/informe_final.md` |
| Vistas HTML (abrir en navegador) | `seguridad/reportes/informe.html` · `informe_sast.html` · `informe_reglas_custom.html` |
| Documento técnico | `documentacion_optiplant.md` · `documentacion_optiplant.tex` |

## Notas

- `SEMGREP_CORES=1` es imprescindible en este equipo; ya queda fijado en la config.
- `sast-reportes` invoca solo los 3 generadores **que existen** en
  `seguridad/scripts/`: `generar_triage_simple.py`, `generar_informe_simple.py` y
  `generar_informe_final.py`. El script `reproducir_analisis.sh` referencia además
  `generar_matriz_confusion.py` y `generar_metricas_conclusiones.py`, que **no
  existen** en el repo (se evitó usarlo por ese motivo).
- Si prefieres una terminal sin las funciones (p. ej. `bash`/`zsh`), equivalen a
  un `alias`:

```bash
alias sast='SEMGREP_CORES=1 semgrep scan --metrics=off --jobs 1 --quiet \
  --config=p/owasp-top-ten --config=p/python --config=p/javascript --config=p/typescript \
  --output ~/Documentos/SAST/seguridad/semgrep/resultados/resultados_sast.json --json \
  ~/Documentos/SAST/app-vulnerable'
```
