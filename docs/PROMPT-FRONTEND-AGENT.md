# Prompt para el agente del frontend

> Pegá esto literalmente en el agente que te está ayudando con el front.
> Está escrito para un agente sin contexto del repo — todo lo que
> necesita saber está adentro.

---

Eres un agente de frontend deployando la UI demo de Apohara VOUCH
para el Band of Agents Hackathon (Track 3, deadline 19 jun 2026
hoy). Tu trabajo tiene UNA restricción dura: la UI tiene que estar
visible en una URL pública antes de que termine el día.

## Contexto del proyecto (léelo todo antes de tocar nada)

- Repo: `https://github.com/SuarezPM/apohara-vouch` (HEAD `30e2cb1`)
- Working dir: `/home/thelinconx/apohara-themis/`
- Backend: `crates/themis-orchestrator/` (Rust + axum 0.7, puerto 8080)
- Frontend crate (ya existe): `crates/vouch-frontend/` (Rust + axum + vanilla HTML/JS/CSS — NO React, NO Vue, NO Tailwind)
- Spec fuente: `docs/SPEC.md` y `docs/submission-final.md`
- Submission final (para lablab): `docs/submission-final.md`
- Autor: Pablo, su github es `@SuarezPM`

## Stack obligatorio

- **Sin frameworks JS.** Vanilla HTML + CSS + JS en `crates/vouch-frontend/static/`.
- **EventSource** (Server-Sent Events) para el live feed, NO WebSocket.
- **Sin npm install.** Si necesitas una dep, embebida localmente.
- **Axum 0.7** para el servidor que sirve los archivos estáticos (ya configurado en `crates/vouch-frontend/src/main.rs`).
- **Deploy target: Vercel** (`https://vouch.apohara.dev`). DNS ya configurado en el repo `apohara.dev`.

## Lo que la UI tiene que mostrar (3 paneles exactos)

Esto está en `docs/submission-final.md` línea 124. Léelo y cumplo:

1. **Left panel — Band room transcript**
   - Stream live via `EventSource('/events')`
   - Auto-scroll al último mensaje
   - Cada mensaje: `{agent, body, mentions, ts}`
   - Estilo: chat bubble, agent badge en color por framework (LangGraph=cyan, CrewAI=orange, Pydantic AI=purple, Anthropic SDK=pink)

2. **Top-right — Per-agent cost panel**
   - 4 logos en header: Band (thenvoi) + AI/ML API + Featherless + Apohara
   - Live tick de: tokens in/out por agente, USD cents por agente, total USD
   - Una barra de progreso por agente mostrando el % del budget consumido
   - Highlight cuando un agente excede $1.00 (color amber)

3. **Bottom-right — EU AI Act Art. 12 dashboard**
   - 8 campos del Art. 12: start_time, end_time, reference_database, input_data, natural_person_id, decision_id, policy_version, hash_chain_prev
   - Cada campo: ✓ (verde, populated) o ✗ (gris, null)
   - Contador "X/8 populated" grande en el header del panel
   - AC15 threshold: ≥7/8 debe estar en verde para mostrar "EU AI Act compliant"

## Lo que la UI tiene que hacer cuando el BAAAR HALT fires

Es el wow moment del demo. AC10 dice <90s. Cuando llega el evento
`Event::BaaarHaltFired { reason, halt_class }` por SSE:

1. **Flash rojo** en todo el viewport (border 8px solid `#dc2626`, pulse animation 600ms)
2. **Modal centrado** con:
   - Texto grande: "WORKFLOW HALTED"
   - Razón del halt (ej. "risk_score_exceeded — cross-tenant double-spend")
   - Botón: "Download Evidence Receipt" → `/packets/:id/pdf`
   - Botón: "Verify offline" → link a `cargo run --release --bin vouch-verify`
3. **Banner persistente** abajo: "DEGRADED MODE — using local fallback" si aplica

## Lo que la UI NO debe hacer

- ❌ No usar emoji como UI primario (solo en headings secundarios)
- ❌ No usar spinners sin mensaje de status
- ❌ No usar modales excepto el HALT
- ❌ No usar fuentes <14px
- ❌ No usar frameworks JS (React, Vue, Svelte, etc.)
- ❌ No usar CSS frameworks (Tailwind, Bootstrap, Bulma)
- ❌ No inventar API endpoints — usá solo los que ya existen en `crates/themis-orchestrator/src/http.rs`

## Endpoints del backend que YA existen

NO modifiques el backend. Usá solo estos:

| Método | Path | Para qué |
|---|---|---|
| `GET /` | raiz | La UI misma (3 paneles) |
| `GET /events` | SSE | Live transcript + cost + compliance events |
| `GET /packets/:id/pdf` | PDF | Download del Evidence Receipt |
| `GET /packets/:id/json` | JSON | SealedPacket completo para verificación |
| `GET /fixtures` | JSON | Lista de fixtures demo (stark-001/002/003, wayne-002) |
| `GET /health` | 200 | Healthcheck |

Si necesitás un endpoint que no existe, **NO lo agregues** — replanteá la UI para trabajar con lo que hay. Si es estrictamente necesario, documentá por qué en el commit message y agregalo como cambio SEPARADO del front.

## Cómo deployar

### Path 1: Vercel (recomendado, ya tenés DNS)

```bash
# 1. Build estático
cd crates/vouch-frontend/static
# No hay build step — los archivos se sirven tal cual.

# 2. Configurar Vercel
cd /home/thelinconx/apohara-themis
vercel link --repo apohara-vouch
vercel env add AIML_API_KEY production
vercel env add FEATHERLESS_API_KEY production
# ... (todas las que tengas en ~/.config/apohara/secrets.env)

# 3. Deploy
vercel --prod
# → te da una URL tipo https://apohara-vouch.vercel.app

# 4. Configurar DNS
# En el panel de apohara.dev:
#   CNAME vouch → cname.vercel-dns.com
```

### Path 2: Cloudflare Pages (alternativa, mismo resultado)

```bash
# Build output: crates/vouch-frontend/static/
wrangler pages deploy crates/vouch-frontend/static --project-name vouch
```

### Path 3: Standalone con el binario Rust (para desarrollo local)

```bash
cd /home/thelinconx/apohara-themis
cargo run --release --bin themis-orchestrator &
cargo run --release --bin vouch-frontend
# → http://localhost:7879
```

## Verificación ANTES de declarar terminado

Esto es no negociable. Hacé esto y mostrame el output:

1. **Smoke test local**:
   ```bash
   cd /home/thelinconx/apohara-themis
   cargo build --release --bin vouch-frontend  # debe pasar sin warnings nuevos
   cargo clippy -p vouch-frontend --all-targets -- -D warnings
   cargo test -p vouch-frontend
   ```

2. **Lighthouse score**: corré Lighthouse contra la URL deployada
   (chrome devtools → Lighthouse tab). Performance ≥90, Accessibility ≥95,
   Best Practices ≥95, SEO ≥85. Pegame el reporte.

3. **Carga visual real**: abrí la URL deployada con `mcp__playwright__browser_navigate`
   y screenshot. La página tiene que verse en <2 segundos.

4. **Live SSE feed**: navegá a la URL, esperá 5 segundos, confirmá
   que el panel de transcript muestra al menos un mensaje del orchestrator
   (provider_active, agent_started, etc.).

5. **BAAAR HALT smoke**: triggereá el fixture `stark-001` y confirmá
   que el flash rojo + modal aparecen. Si no podés triggerearlo en
   el ambiente deployado, al menos dejá un botón "Test HALT" en la
   UI que simule el evento SSE (es debug-only, no documentar como
   feature).

6. **Mobile**: abrí la URL en viewport 375×667 (iPhone SE). Los 3
   paneles se tienen que stackear verticalmente sin overflow horizontal.

## Lo que ya existe (NO recrear, USAR)

- `crates/vouch-frontend/static/index.html` — HTML base con los 3 paneles
- `crates/vouch-frontend/static/app.js` — JS del frontend (EventSource + render)
- `crates/vouch-frontend/static/style.css` — CSS dark theme con navy/gold/amber palette
- `crates/vouch-frontend/static/{aiml,featherless,band,apohara}-logo.svg` — logos
  (verificar que existan; si no, generarlos con inkscape o bajar de las páginas oficiales)
- `crates/vouch-frontend/src/main.rs` — servidor axum (no tocar salvo bug)
- `docs/submission-final.md` — descripción del producto (no cambiar)

## Lo que probablemente falte agregar

- **Bind a 0.0.0.0** — el binario ya lo hace, pero verificá que sirva en `0.0.0.0:7879` (no `127.0.0.1`).
- **CSP headers** — agregar Content-Security-Policy en `main.rs` para que los SVG inline no rompan en Safari.
- **Open Graph tags** — `<meta property="og:title">`, `og:description`, `og:image`
  (apuntar a `docs/cover-image.png`). Crítico para que lablab muestre
  una preview rica en el submission card.
- **Favicon** — si no hay, generar uno con `convert -size 64x64 xc:#d4a017 favicon.ico` (Ghostty color).

## Formato del handoff final

Cuando termines, entregá:

1. **URL deployada** (`https://vouch.apohara.dev` o lo que sea)
2. **Lighthouse report** (pegar el JSON del audit)
3. **Screenshot del estado final** (`mcp__playwright__browser_take_screenshot`)
4. **Lista de archivos modificados** (`git diff --name-only origin/main`)
5. **Commit message** que resume el cambio
6. **2-3 líneas** diciendo qué quedó funcionando y qué quedó pendiente

## Honestidad

Si algo no funciona, decímelo. No inventes URLs, no pegues screenshots
de otra cosa, no digas "listo" si no probaste el flujo end-to-end.
Si Vercel te da errores de CORS con el SSE, documentá y proponé
un fix; no escondas el problema.

## Tono

Responde en español (Pablo es argentino, default es es_AR). Sé
directo: si mi spec es ambiguo, preguntá antes de asumir. Si ves
que algo que pido va a romper el backend o el security.md, decímelo
antes de hacerlo.

Arrancá leyéndote estos 3 archivos en este orden:
1. `crates/vouch-frontend/static/index.html` (lo que hay)
2. `crates/themis-orchestrator/src/http.rs` (qué endpoints existen)
3. `docs/submission-final.md` línea 124-131 (qué dice la UI que tiene que hacer)

Después contame qué ves y qué pensás que falta.