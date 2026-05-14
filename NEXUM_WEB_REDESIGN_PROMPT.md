# NEXUM — Web Redesign Session Prompt

## Contexto del proyecto
Nexum es una plataforma de certificación y seguridad semántica para APIs usadas por agentes de IA.
- Scanner determinista (sin LLM) que detecta 5 tipos de riesgo agentic
- Trust Manifest v1.0 como artefacto portable de certificación
- 2,480 APIs públicas escaneadas
- getnexum.dev en Railway (FastAPI backend + HTML vanilla frontend actual)

## Stack actual
- Backend: FastAPI (web/app.py)
- Frontend: HTML vanilla (web/static/index.html)
- Deploy: Railway
- Dominio: getnexum.dev

## Lo que existe ahora
- POST /scan → recibe spec, devuelve JSON del manifest
- POST /report → recibe spec, devuelve PDF
- GET /badge/{tier} → SVG badge (recién añadido)
- GET /badge/{tier}/markdown → texto para README

## Objetivo de esta sesión
Rediseñar la web completa para parecer una empresa de seguridad profesional.
No un side project. No un MVP. Una empresa de infraestructura seria.

Referencias de diseño:
- Snyk.io — dashboard de seguridad limpio
- Vercel.com — producto técnico con diseño premium
- Linear.app — tipografía, espaciado, profesionalidad

## Páginas a construir

### 1. Landing page (/) — Hero completo
- Header: logo Nexum + nav (Product, Docs, Registry, GitHub)
- Hero: headline potente + subheadline + CTA
- Headline: "Every API your agent touches needs a Trust Manifest"
- Subheadline: "Nexum scans MCP servers and OpenAPIs for agentic risk patterns. Deterministic. No LLM. In seconds."
- CTA primario: "Scan your API free" → scroll a upload form
- CTA secundario: "View Registry" → /registry
- Stats bar: "2,480 APIs scanned · 94.1% certified · 5 deterministic rules · 0 false positives in CRITICAL"

### 2. Upload section — El scanner
- Drag & drop zone para JSON/YAML
- Dos outputs: Risk Score visible en pantalla + descarga PDF
- Loading state con animación
- Error state claro si el archivo es inválido
- Después del scan: mostrar badge del tier con código markdown para copiar

### 3. How it works — 3 pasos
- Paso 1: Upload your MCP or OpenAPI spec
- Paso 2: Nexum runs 5 deterministic rules (no LLM)
- Paso 3: Get your Trust Manifest + Risk Score

### 4. Las 5 reglas — Features section
Tarjeta por regla:
- NEXUM-001 AuthLeakageRisk — CRITICAL
- NEXUM-002 DestructiveAmbiguity — CRITICAL  
- NEXUM-003 UnboundedScope — HIGH
- NEXUM-004 IdempotencyMissing — HIGH
- NEXUM-005 SchemaVolatility — MEDIUM

### 5. Trust Manifest section
- Explicación del artefacto
- Code block con ejemplo de manifest JSON (tier 2)
- Link a spec pública: github.com/mehdibelckadi-dev/nexum-trust-manifest

### 6. Registry preview (/registry)
- Tabla de APIs escaneadas (desde registry_data.json)
- Columnas: API Name | Tier | Verdict | Badge
- Filtros: All / Certified / Review Required
- Link a getnexum.dev para escanear la tuya

### 7. Footer
- Links: GitHub | Trust Manifest Spec | getnexum.dev
- Tagline: "The contract between your agent and your infrastructure"
- "Nexum · Open specification · MIT License"

## Especificaciones de diseño

### Paleta de colores
```css
--bg-primary: #0a0a0a        /* negro casi puro */
--bg-secondary: #111111      /* cards y secciones */
--bg-tertiary: #1a1a1a       /* hover states */
--text-primary: #ffffff
--text-secondary: #888888
--text-tertiary: #555555
--accent-green: #00ff88      /* Tier 0 / success */
--accent-yellow: #ffcc00     /* Tier 1 / warning */
--accent-red: #ff4444        /* Tier 2 / critical */
--accent-blue: #0066ff       /* links / CTAs */
--border: #222222
```

### Tipografía
```css
font-family: 'Inter', -apple-system, sans-serif
--font-mono: 'JetBrains Mono', 'Fira Code', monospace
```

### Principios de diseño
- Dark theme siempre — es una herramienta de seguridad
- Mucho espacio en blanco — no saturar
- Monospace para código, scores y hallazgos técnicos
- Animaciones sutiles — no distraer
- Mobile responsive — algunos CISOs revisan en móvil

## Estructura de archivos a crear/modificar
```
web/
├── app.py                    ← añadir GET /registry endpoint
├── static/
│   ├── index.html            ← rediseño completo
│   ├── registry.html         ← nueva página
│   ├── css/
│   │   └── nexum.css         ← styles separados
│   └── js/
│       └── nexum.js          ← lógica separada
└── data/
    └── registry_data.json    ← copiado desde scans/
```

## Endpoint nuevo necesario
```python
GET /registry-data
# Devuelve el registry_data.json como JSON
# Para que registry.html lo cargue dinámicamente
```

## Orden de construcción
1. nexum.css — design tokens y componentes base
2. index.html — landing completa con todas las secciones
3. Integrar upload form existente en el nuevo diseño
4. registry.html — tabla de APIs
5. app.py — añadir /registry-data endpoint
6. Verificar que todo funciona en local antes de push

## Constraints técnicos
- Sin frameworks CSS (no Tailwind, no Bootstrap) — CSS vanilla
- Sin frameworks JS (no React, no Vue) — vanilla JS
- Google Fonts permitido (Inter + JetBrains Mono)
- Sin cambios al backend de scanning — solo nuevas rutas
- pytest debe seguir en verde después de los cambios

## Lo que NO hacer
- No añadir auth
- No añadir base de datos
- No añadir historial de scans
- No cambiar la lógica del scanner
- No añadir pricing page todavía

## Primer mensaje para iniciar la sesión
"Lee este documento completo. Antes de escribir una sola línea de código, muéstrame:
1. La estructura de archivos que vas a crear
2. Los colores exactos que usarás
3. El orden de construcción
4. Qué tests añadirás para verificar los nuevos endpoints

No escribas código hasta que yo confirme el plan."
