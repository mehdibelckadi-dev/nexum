#!/bin/bash
# Nexum Batch Scanner — Extended, no duplicates
# Usage: bash scripts/batch_scan_extended.sh [max_apis]

MAX=${1:-500}  # default 500, puedes pasar otro número

SCANS_DIR="$(dirname "$0")/../scans"
SPECS_DIR="$SCANS_DIR/specs"
REPORTS_DIR="$SCANS_DIR/reports"
LOGS_DIR="$SCANS_DIR/logs"
SCANNED_LOG="$SCANS_DIR/scanned_apis.txt"  # registro permanente

mkdir -p "$SPECS_DIR" "$REPORTS_DIR" "$LOGS_DIR"
touch "$SCANNED_LOG"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOGS_DIR/batch_${TIMESTAMP}.log"

echo "Nexum Batch Scan — $(date)" | tee "$LOG_FILE"
echo "Max APIs: $MAX" | tee -a "$LOG_FILE"
echo "Already scanned: $(wc -l < "$SCANNED_LOG")" | tee -a "$LOG_FILE"
echo "─────────────────────────────────────" | tee -a "$LOG_FILE"

# Descarga lista completa de APIs.guru
curl -s https://api.apis.guru/v2/list.json | \
  python3 -c "
import json, sys
apis = json.load(sys.stdin)
for name, data in apis.items():
    for v, info in data.get('versions', {}).items():
        url = info.get('swaggerUrl') or info.get('openapiUrl','')
        if url:
            print(f'{name}|{url}')
            break
" > "$SCANS_DIR/apis_full_list.txt"

echo "Total available: $(wc -l < "$SCANS_DIR/apis_full_list.txt")" | tee -a "$LOG_FILE"

PASS=0; REVIEW=0; FAIL=0; ERROR=0; SKIPPED=0; COUNT=0

while IFS='|' read -r name url; do
  # Skip si ya escaneado
  if grep -qF "$name" "$SCANNED_LOG" 2>/dev/null; then
    ((SKIPPED++)) || true
    continue
  fi

  # Stop si alcanzamos el máximo
  if [ "$COUNT" -ge "$MAX" ]; then
    echo "Max APIs reached ($MAX)" | tee -a "$LOG_FILE"
    break
  fi

  safe="${name//\//_}"
  safe="${safe//:/_}"
  spec="$SPECS_DIR/${safe}.yaml"
  report="$REPORTS_DIR/${safe}.pdf"

  # Download spec
  if ! curl -s --max-time 15 "$url" -o "$spec" 2>/dev/null; then
    echo "⚠️  $name — download failed" | tee -a "$LOG_FILE"
    ((ERROR++)) || true
    echo "$name" >> "$SCANNED_LOG"  # marca como procesado para no reintentar
    ((COUNT++)) || true
    continue
  fi

  # Verifica que el archivo no está vacío
  if [ ! -s "$spec" ]; then
    echo "⚠️  $name — empty spec" | tee -a "$LOG_FILE"
    ((ERROR++)) || true
    echo "$name" >> "$SCANNED_LOG"
    ((COUNT++)) || true
    continue
  fi

  # Genera report con validación
  EXIT_CODE=0
  nexum report "$spec" \
    --validate \
    --output "$report" \
    2>>"$LOG_FILE" || EXIT_CODE=$?

  case $EXIT_CODE in
    0) echo "✅ $name — DISTRIBUTABLE" | tee -a "$LOG_FILE"; ((PASS++)) || true ;;
    1) echo "🚫 $name — DO_NOT_DISTRIBUTE" | tee -a "$LOG_FILE"; ((FAIL++)) || true ;;
    2) echo "⚠️  $name — REVIEW_REQUIRED" | tee -a "$LOG_FILE"; ((REVIEW++)) || true ;;
    *) echo "❌ $name — ERROR ($EXIT_CODE)" | tee -a "$LOG_FILE"; ((ERROR++)) || true ;;
  esac

  # Marca como escaneado
  echo "$name" >> "$SCANNED_LOG"
  ((COUNT++)) || true

done < "$SCANS_DIR/apis_full_list.txt"

echo "─────────────────────────────────────" | tee -a "$LOG_FILE"
echo "Scanned this run: $COUNT" | tee -a "$LOG_FILE"
echo "Skipped (already done): $SKIPPED" | tee -a "$LOG_FILE"
echo "DISTRIBUTABLE:     $PASS" | tee -a "$LOG_FILE"
echo "REVIEW_REQUIRED:   $REVIEW" | tee -a "$LOG_FILE"
echo "DO_NOT_DISTRIBUTE: $FAIL" | tee -a "$LOG_FILE"
echo "ERRORS:            $ERROR" | tee -a "$LOG_FILE"
echo "Total scanned ever: $(wc -l < "$SCANNED_LOG")" | tee -a "$LOG_FILE"
echo "─────────────────────────────────────" | tee -a "$LOG_FILE"
echo "Reports: $REPORTS_DIR"
echo "Log: $LOG_FILE"
