#!/bin/bash
# Nexum Batch Scanner
# Usage: bash scripts/batch_scan.sh

set -e

SCANS_DIR="$(dirname "$0")/../scans"
SPECS_DIR="$SCANS_DIR/specs"
REPORTS_DIR="$SCANS_DIR/reports"
LOGS_DIR="$SCANS_DIR/logs"

mkdir -p "$SPECS_DIR" "$REPORTS_DIR" "$LOGS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOGS_DIR/batch_${TIMESTAMP}.log"

echo "Nexum Batch Scan — $(date)" | tee "$LOG_FILE"
echo "Output: $SCANS_DIR" | tee -a "$LOG_FILE"
echo "─────────────────────────────────────" | tee -a "$LOG_FILE"

# Download API list from APIs.guru
curl -s https://api.apis.guru/v2/list.json | \
  python3 -c "
import json, sys
apis = json.load(sys.stdin)
for name, data in list(apis.items())[:100]:
    for v, info in data.get('versions', {}).items():
        url = info.get('swaggerUrl') or info.get('openapiUrl','')
        if url:
            print(f'{name}|{url}')
            break
" > "$SCANS_DIR/apis_to_scan.txt"

echo "APIs queued: $(wc -l < "$SCANS_DIR/apis_to_scan.txt")" | tee -a "$LOG_FILE"
echo "─────────────────────────────────────" | tee -a "$LOG_FILE"

PASS=0
REVIEW=0
FAIL=0
ERROR=0

while IFS='|' read -r name url; do
  safe="${name//\//_}"
  spec="$SPECS_DIR/${safe}.yaml"
  report="$REPORTS_DIR/${safe}.pdf"

  # Download spec
  if ! curl -s --max-time 10 "$url" -o "$spec" 2>/dev/null; then
    echo "⚠️  $name — download failed" | tee -a "$LOG_FILE"
    ((ERROR++)) || true
    continue
  fi

  # Generate report with validation
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

done < "$SCANS_DIR/apis_to_scan.txt"

echo "─────────────────────────────────────" | tee -a "$LOG_FILE"
echo "DISTRIBUTABLE:    $PASS" | tee -a "$LOG_FILE"
echo "REVIEW_REQUIRED:  $REVIEW" | tee -a "$LOG_FILE"
echo "DO_NOT_DISTRIBUTE: $FAIL" | tee -a "$LOG_FILE"
echo "ERRORS:           $ERROR" | tee -a "$LOG_FILE"
echo "─────────────────────────────────────" | tee -a "$LOG_FILE"
echo "Reports: $REPORTS_DIR" | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"
