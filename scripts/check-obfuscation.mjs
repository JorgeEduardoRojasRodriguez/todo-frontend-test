#!/usr/bin/env node
/**
 * check-obfuscation.mjs — escáner anti código ofuscado / malware.
 *
 * Uso:
 *   node scripts/check-obfuscation.mjs            # escanea archivos rastreados por git
 *   node scripts/check-obfuscation.mjs --staged   # escanea solo lo que está en stage (pre-commit)
 *
 * Sale con código != 0 si encuentra indicios. Diseñado para pre-commit y CI.
 */
import { execSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const STAGED = process.argv.includes('--staged');

// Extensiones de código a revisar.
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.vue', '.json']);
// Carpetas/patrones a ignorar (build output, deps, minificados, locks).
const IGNORE = [
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)\.next\//,
  /(^|\/)\.git\//,
  /(^|\/)coverage\//,
  /\.min\.(js|css)$/,
  /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/,
  // Artefactos generados y librerias vendorizadas que se commitean. Traen
  // base64, eval y \xNN por su propia naturaleza, y marcarlos solo ensena a
  // ignorar la guarda: eran 73 de las 73 detecciones en los repos propios.
  /(^|\/)\.yarn\//,
  /(^|\/)\.pnp\.[cm]?js$/,
  /(^|\/)\.expo\//,
  /(^|\/)vendor\//,
  /(^|\/)www\//,
  /(^|\/)platforms\//,
  // Bundles con hash de contenido: main-es5.133c15df28a3ee837fed.js, los
  // .chunk.js de create-react-app. El hash en el nombre solo lo pone un build.
  /\.[0-9a-f]{8,}\.[cm]?js$/,
  /\.chunk\.js$/,
];
// Archivos de configuración que deben ser pequeños (blanco típico del malware).
const CONFIG_RE = /(^|\/)(postcss|next|tailwind|vite|webpack|rollup|svelte|nuxt|astro|babel|eslint|prettier)\.config\.[cm]?[jt]s$/i;
const CONFIG_MAX_BYTES = 4096; // 4 KB — un config normal pesa < 500 bytes
// tailwind.config.* crece de forma legítima con theme tokens/colores/keyframes
// (aquí pesa ~3.4 KB solo con lo estándar de shadcn) — no es indicio de payload.
const TAILWIND_MAX_BYTES = 8192;

function tracked() {
  const cmd = STAGED
    ? 'git diff --cached --name-only --diff-filter=ACM'
    : 'git ls-files';
  try {
    return execSync(cmd, { encoding: 'utf8' }).split('\n').map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function ignored(f) {
  const p = f.replace(/\\/g, '/');
  return IGNORE.some((re) => re.test(p));
}

// Reglas de detección. Cada una: { name, test(content, file) -> string|null }
// Excepciones declaradas por el repo, una por linea, en .security-allowlist:
//
//   dynamic-eval:public/Content/js/sxx-modal.js   una regla en un archivo
//   public/Content/js/sxx-modal.js                todas las reglas del archivo
//   # comentario
//
// Existe para lo que ya se reviso y se decidio dejar pasar. La alternativa es
// --no-verify, que apaga TODAS las reglas en TODOS los archivos y no deja rastro
// de quien lo decidio ni por que; esto queda en el repo y se revisa en el PR.
function cargarExcepciones() {
  let texto;
  try {
    texto = readFileSync('.security-allowlist', 'utf8');
  } catch {
    return [];
  }
  return texto
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => {
      const i = l.indexOf(':');
      // Se parte en el primer ':' solo si lo de la izquierda parece un nombre de
      // regla; asi una ruta de Windows (C:/...) no se malinterpreta.
      if (i > 0 && /^[a-z0-9-]+$/.test(l.slice(0, i))) {
        return { rule: l.slice(0, i), path: l.slice(i + 1).trim() };
      }
      return { rule: null, path: l };
    });
}

const EXCEPCIONES = cargarExcepciones();

function estaPermitido(rule, file) {
  const ruta = file.replace(/\\/g, '/');
  return EXCEPCIONES.some((e) => (e.rule === null || e.rule === rule)
    && (ruta === e.path || ruta.endsWith('/' + e.path)));
}

// Reconoce la salida de webpack por las marcas que webpack mismo escribe.
// Se mira solo el arranque del archivo: ahi van los banners.
function esSalidaDeBuild(c) {
  const cabeza = c.slice(0, 2000);
  return /^\s*\/\*!\s*For license information please see /.test(cabeza)
    || /webpackBootstrap/.test(cabeza);
}

// Quita solo las lineas que SON comentario. A proposito no corta desde "//" a
// mitad de linea: una URL dentro de un string llevaria a borrar el codigo que
// va despues, y eso seria justo el hueco por donde esconder el payload.
function sinComentarios(c) {
  return c
    .split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
}

const RULES = [
  {
    name: 'hex-var-obfuscation',
    desc: 'Variables hexadecimales tipo _0xabcd (firma de javascript-obfuscator)',
    test: (c) => {
      const m = c.match(/_0x[0-9a-fA-F]{4,}/g);
      return m && m.length >= 5 ? `${m.length} ocurrencias de _0x…` : null;
    },
  },
  {
    name: 'dynamic-eval',
    // Todo bundle grande la dispara: ahi no distingue nada.
    ruidosaEnBundles: true,
    desc: 'Ejecución dinámica de código',
    test: (c) => {
      const hits = [];
      // Solo el eval global: \b tambien casa con ".eval(", que es un metodo
      // cualquiera (tipo.eval(ctx, valor)) y no ejecuta codigo dinamico. Y se
      // ignoran las lineas que SON comentario, donde "eval(" aparece al
      // documentar una funcion.
      if (/(?<![.\w$])eval\s*\(/.test(sinComentarios(c))) hits.push('eval(');
      if (/new\s+Function\s*\(/.test(c)) hits.push('new Function(');
      if (/\bFunction\s*\(\s*['"`]return this/.test(c)) hits.push('Function("return this")');
      return hits.length ? hits.join(', ') : null;
    },
  },
  {
    name: 'base64-decode-exec',
    // Todo bundle grande la dispara: ahi no distingue nada.
    ruidosaEnBundles: true,
    desc: 'Decodifica base64 y probablemente lo ejecuta',
    test: (c) => {
      const hasB64 = /atob\s*\(|Buffer\.from\s*\([^)]*['"`]base64['"`]/.test(c);
      const hasExec = /(?<![.\w$])eval\s*\(|new\s+Function\s*\(|child_process|execSync|spawn/.test(c);
      return hasB64 && hasExec ? 'base64 + eval/child_process' : null;
    },
  },
  {
    name: 'shell-exec',
    desc: 'Ejecución de comandos del sistema',
    test: (c, f) => {
      // Solo en configuraciones. En codigo de servidor lanzar procesos es
      // normal —node-media-server llama a ffmpeg, un pipeline corre tippecanoe,
      // un runner arranca playwright— y ahi la regla no distingue uso legitimo
      // de backdoor: los 9 archivos que marco eran legitimos. El payload en
      // cambio metia spawn("node", ["-e", ...]) dentro de un config, y ahi no
      // tiene ninguna explicacion.
      if (!CONFIG_RE.test(f.replace(/\\/g, '/'))) return null;
      if (/require\(\s*['"`]child_process['"`]\s*\)|from\s+['"`]node:child_process['"`]|\bexecSync\s*\(|\bspawn(Sync)?\s*\(/.test(c)) {
        return 'uso de child_process/exec';
      }
      return null;
    },
  },
  {
    name: 'hex-escape-heavy',
    // Todo bundle grande la dispara: ahi no distingue nada.
    ruidosaEnBundles: true,
    desc: 'Cadenas con escape hexadecimal masivo (\\xNN)',
    test: (c) => {
      const m = c.match(/\\x[0-9a-fA-F]{2}/g);
      return m && m.length >= 50 ? `${m.length} secuencias \\xNN` : null;
    },
  },
  {
    name: 'long-obfuscated-line',
    desc: 'Config con una linea de codigo larguisima (posible payload)',
    test: (c, f) => {
      // Solo configuraciones. El relleno de espacios parecia suficiente para
      // reconocer el payload, pero no lo es: en un bundle de una sola linea el
      // relleno puede caer dentro de un string de CSS y detras venir JS
      // minificado legitimo, con mas operadores que el payload mismo. Lo que de
      // verdad los separa son los identificadores _0x…, y de eso se encarga
      // hex-var-obfuscation.
      //
      // En un archivo de configuracion, en cambio, una linea densa de 1500+
      // chars no tiene explicacion legitima, con relleno o sin el.
      if (!CONFIG_RE.test(f.replace(/\\/g, '/'))) return null;
      for (const line of c.split('\n')) {
        if (line.length <= 1500) continue;
        const ops = (line.match(/[;{}]|=>|\)\s*\{|\}\s*\)|\bfunction\b|\|\||&&/g) || []).length;
        if (ops < 25) continue;
        // El relleno de espacios es como se esconde: empuja el payload fuera de
        // la pantalla del editor. Se reporta cuando esta, porque es la senal
        // mas clara de que fue inyectado y no escrito.
        const pad = /[ \t]{20,}/.exec(line);
        const detras = pad ? line.length - (pad.index + pad[0].length) : 0;
        return pad
          ? `linea de ${line.length} chars, con ${detras} escondidos detras de un relleno de ${pad[0].length} espacios`
          : `linea de ${line.length} chars con ${ops} operadores`;
      }
      return null;
  },
  },
  {
    name: 'config-too-large',
    desc: 'Archivo de configuración anormalmente grande (posible payload inyectado)',
    test: (c, f) => {
      const p = f.replace(/\\/g, '/');
      if (!CONFIG_RE.test(p)) return null;
      const isTailwind = /(^|\/)tailwind\.config\.[cm]?[jt]s$/i.test(p);
      const max = isTailwind ? TAILWIND_MAX_BYTES : CONFIG_MAX_BYTES;
      const bytes = Buffer.byteLength(c, 'utf8');
      if (bytes <= max) return null;
      // El tamano por si solo no sirve: hay configs legitimos grandes, como un
      // vite.config.js de 5568 bytes en 230 lineas o un next.config.mjs de 7297
      // en 170. Lo que delata al payload es que el peso viene de POCAS lineas,
      // porque el inyector lo pega todo en una. Medido: el payload real trae
      // 1100 bytes por linea y esos dos configs 24 y 43.
      const lineas = c.split('\n').length;
      const porLinea = bytes / lineas;
      if (porLinea < 300) return null;
      return `${bytes} bytes en ${lineas} lineas (${Math.round(porLinea)} por linea)`;
    },
  },
  {
    name: 'suspicious-install-script',
    desc: 'Script de instalación (pre/post/install) en package.json',
    test: (c, f) => {
      if (!/(^|\/)package\.json$/.test(f.replace(/\\/g, '/'))) return null;
      try {
        const j = JSON.parse(c);
        const s = j.scripts || {};
        // Que exista un postinstall es normal: husky, "quasar prepare",
        // patch-package. Lo que importa es que BAJE o EJECUTE algo arbitrario.
        const RIESGO = /curl|wget|\bnode\s+-e\b|\beval\b|base64|atob|powershell|Invoke-WebRequest|\bsh\s+-c\b|https?:\/\//i;
        const bad = ['preinstall', 'install', 'postinstall']
          .filter((k) => s[k] && RIESGO.test(s[k]));
        return bad.length
          ? bad.map((k) => `${k}: ${s[k]}`).join(' | ')
          : null;
      } catch { return null; }
    },
  },
];

const findings = [];
for (const f of tracked()) {
  if (ignored(f)) continue;
  // Auto-exclusión: este escáner contiene los patrones de detección como texto.
  if (f.replace(/\\/g, '/').endsWith('scripts/check-obfuscation.mjs')) continue;
  const ext = path.extname(f).toLowerCase();
  const isConfig = CONFIG_RE.test(f.replace(/\\/g, '/'));
  const isPkg = /(^|\/)package\.json$/.test(f.replace(/\\/g, '/'));
  if (!CODE_EXT.has(ext) && !isConfig) continue;
  let content;
  try {
    if (statSync(f).size > 5 * 1024 * 1024) continue; // >5MB, saltar
    content = readFileSync(f, 'utf8');
  } catch { continue; }
  const esBundle = esSalidaDeBuild(content);
  for (const rule of RULES) {
    if (rule.ruidosaEnBundles && esBundle) continue;
    // suspicious-install-script solo aplica a package.json; el resto no debería
    // marcar package.json por datos legítimos, pero lo dejamos correr.
    const hit = rule.test(content, f);
    if (!hit) continue;
    if (estaPermitido(rule.name, f)) continue;
    findings.push({ file: f, rule: rule.name, detail: hit, desc: rule.desc });
  }
}

if (findings.length === 0) {
  console.log(`✔ Sin código ofuscado detectado (${STAGED ? 'staged' : 'repo'}).`);
  process.exit(0);
}

console.error(`\n✖ POSIBLE CÓDIGO OFUSCADO / MALWARE detectado (${findings.length} hallazgo(s)):\n`);
for (const h of findings) {
  console.error(`  • [${h.rule}] ${h.file}`);
  console.error(`      ${h.desc}: ${h.detail}`);
}
console.error(`\nCommit/deploy BLOQUEADO. Revisa cada archivo de la lista.`);
console.error(`
Si ya lo revisaste y es codigo legitimo, declaralo en .security-allowlist
(una linea por excepcion, se revisa en el PR como cualquier otro cambio):

  ${findings.map((h) => `${h.rule}:${h.file.replace(/\\/g, '/')}`).join('\n  ')}

Evita "git commit --no-verify": apaga todas las reglas en todos los archivos y
no deja constancia de quien lo decidio ni por que.
`);
process.exit(1);
