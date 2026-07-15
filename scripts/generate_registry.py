import json
import os
import subprocess
from pathlib import Path

specs_dir = Path("scans/specs")
output_file = Path("web/static/registry_data.json")

specs = sorted([f for f in specs_dir.glob("*.yaml")])
total = len(specs)
results = []

print(f"Processing {total} specs...")

for i, spec in enumerate(specs):
    api_name = spec.stem.replace("_", "/", 1).replace("_", ":")
    
    try:
        result = subprocess.run(
            ["nexum", "scan", str(spec)],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout)
        findings = data.get("findings_summary", [])
        score = data.get("nexum_risk_score", 0)
        tier = data.get("inferred_risk_tier", 0)
        
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        total_findings = len(findings)
        
        results.append({
            "api": api_name,
            "score": score,
            "tier": tier,
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
        })
        
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{total} processed...")
            
    except Exception as e:
        results.append({
            "api": api_name,
            "score": 0,
            "tier": 0,
            "total_findings": -1,
            "critical": 0,
            "high": 0,
        })

with open(output_file, "w") as f:
    json.dump(results, f, indent=2)

print(f"Done. {len(results)} APIs saved to {output_file}")

# Stats
no_findings = sum(1 for r in results if r["total_findings"] == 0)
has_findings = sum(1 for r in results if r["total_findings"] > 0)
has_critical = sum(1 for r in results if r["critical"] > 0)
errors = sum(1 for r in results if r["total_findings"] == -1)

print(f"No findings: {no_findings}")
print(f"Has findings: {has_findings}")
print(f"Has CRITICAL: {has_critical}")
print(f"Errors: {errors}")
