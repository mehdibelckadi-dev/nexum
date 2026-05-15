# Nexum — Clarity Fix Prompt para Claude Code

## Contexto del problema
El Validator (DISTRIBUTABLE/REVIEW_REQUIRED/DO_NOT_DISTRIBUTE) es una 
herramienta interna de QA para verificar PDFs antes de distribuirlos.
NUNCA debe aparecer en la UI pública porque es confuso y puede ser
malinterpretado por CISOs y developers.

Ejemplo del problema:
- Slack tiene score 100/100 con 58 CRITICAL findings
- El validator dice DISTRIBUTABLE (porque confía en sus findings)
- Un CISO lee "Slack: DISTRIBUTABLE" y piensa que Nexum dice que Slack es seguro
- Verde psicológicamente significa "seguro" — usar verde en "Analyzed" es igual de confuso
- Eso es falso y destruye credibilidad

## Regla fundamental
El Validator es INTERNAL QA ONLY. 
Los términos DISTRIBUTABLE/REVIEW_REQUIRED/DO_NOT_DISTRIBUTE
no deben aparecer en NINGUNA página pública.
El color VERDE solo se usa cuando una API tiene 0 findings confirmados.

---

## Datos reales verificados (usar estos números, no inventar)
- Total APIs scanned: 2,517
- APIs with no findings: 2,113 (83.9%)
- APIs with findings: 404 (16.1%)
- APIs with CRITICAL findings: 215 (8.3%)
- NEXUM-004 findings: 2,465 (94.9% of all findings)
- NEXUM-001 findings: 77 (3.0%)
- NEXUM-003 findings: 24 (0.9%)
- NEXUM-002 findings: 23 (0.9%)
- NEXUM-005 findings: 9 (0.3%)

---

## Cambios requeridos — ejecutar todos en una sola sesión

### 1. index.html — Hero stats bar

ANTES:
- "94.1% Distributable certified"
- "< 6% flagged for review"

DESPUÉS:
- Stat 1: número "2,517" | label "APIs scanned"
- Stat 2: número "83.9%" | label "with no findings"
- Stat 3: número "5" | label "deterministic rules"
- Stat 4: número "8.3%" | label "with CRITICAL findings"

El color del stat "8.3%" debe ser var(--accent-red) para el número.
El color de "83.9%" debe ser var(--accent-green) para el número.

### 2. registry.html — Cuatro cambios

**2a. Renombrar veredictos con colores correctos:**

DISTRIBUTABLE → badge "Analyzed" 
- Color: fondo transparent, borde var(--border), texto var(--text-secondary)
- SIN verde — no implica que la API sea segura

REVIEW_REQUIRED → badge "Needs Review"
- Color: fondo rgba(255,204,0,0.1), borde var(--accent-yellow), texto var(--accent-yellow)
- Igual que antes

DO_NOT_DISTRIBUTE → badge "High Risk"
- Color: fondo rgba(255,68,68,0.1), borde var(--accent-red), texto var(--accent-red)
- Igual que antes

**2b. Renombrar filtros:**
- "All" → "All" (sin cambio)
- "Certified" → "Analyzed"
- "Review Required" → "Needs Review"
- "Do Not Distribute" → "High Risk"

**2c. Añadir nota explicativa debajo del subtítulo:**
```html
<p class="registry-note">
  This registry shows scanner confidence in detected findings, 
  not an overall security rating. "Analyzed" means all findings 
  were detected with high confidence — it does not mean the API 
  is safe for autonomous agent access. Always review the full 
  Trust Manifest before granting agent access.
</p>
```

**2d. Actualizar el subtítulo de la página:**
ANTES: "2,480 public APIs audited for agentic risk."
DESPUÉS: "2,517 public APIs scanned for agentic risk patterns. 
83.9% had no findings. 8.3% had CRITICAL findings."

### 3. blog/2517-apis-scanned.html — Tabla de verdicts

Eliminar completamente la tabla de verdicts actual.
Reemplazar con esta tabla de datos reales verificados:

| Metric | Count | Percentage |
|--------|-------|------------|
| APIs scanned | 2,517 | 100% |
| APIs with no findings | 2,113 | 83.9% |
| APIs with findings | 404 | 16.1% |
| APIs with CRITICAL findings | 215 | 8.5% |

Añadir debajo de la tabla este párrafo:
"Of the 404 APIs with findings, 94.9% of all individual findings 
are missing idempotency contracts (NEXUM-004) — the most common 
agentic risk pattern across the entire catalog. Only 8.3% of APIs 
had CRITICAL findings, concentrated in auth leakage and 
destructive ambiguity patterns."

### 4. blog/2517-apis-scanned.html — Eliminar lenguaje de veredictos

Buscar y eliminar cualquier mención de:
- "Distributable" o "DISTRIBUTABLE"
- "DO_NOT_DISTRIBUTE" o "Do Not Distribute"
- "Certified" en contexto de veredicto

Reemplazar con lenguaje descriptivo:
- "APIs with no risk findings detected"
- "APIs with findings requiring attention"  
- "APIs with high-confidence critical findings"

### 5. CSS — Estilos nuevos en nexum.css

```css
/* Registry note */
.registry-note {
  font-size: 13px;
  color: var(--text-secondary);
  max-width: 640px;
  margin-bottom: 24px;
  line-height: 1.6;
  border-left: 2px solid var(--border);
  padding-left: 12px;
}

/* Badge Analyzed — neutro, sin verde */
.badge-analyzed {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-weight: 500;
}

/* Badge Needs Review — amarillo */
.badge-review {
  background: rgba(255, 204, 0, 0.1);
  border: 1px solid var(--accent-yellow);
  color: var(--accent-yellow);
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-weight: 500;
}

/* Badge High Risk — rojo */
.badge-high-risk {
  background: rgba(255, 68, 68, 0.1);
  border: 1px solid var(--accent-red);
  color: var(--accent-red);
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-weight: 500;
}
```

---

## Verificación final obligatoria

Después de todos los cambios, ejecutar:

```bash
grep -r "DISTRIBUTABLE\|DO_NOT_DISTRIBUTE\|Distributable certified\|Certified" web/static/
```

Debe devolver 0 resultados en archivos HTML públicos.
Si devuelve algo, corregirlo antes de confirmar.

pytest 165/165 requerido.
No tocar backend de scanning, reglas, scorer, ni validator Python.
No tocar SESSION_LOG.md ni archivos internos.
No tocar los ejemplos en nexum-trust-manifest — los Tiers son correctos.

---

## Primer mensaje para Claude Code

"Lee este documento completo. Antes de escribir una sola línea,
muéstrame:
1. Lista de archivos que vas a modificar
2. Los términos exactos que vas a eliminar de cada archivo
3. Los colores exactos de cada badge nuevo

No escribas código hasta que yo confirme el plan."
