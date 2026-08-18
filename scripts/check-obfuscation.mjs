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
];
// Archivos de configuración que deben ser pequeños (blanco típico del malware).
const CONFIG_RE = /(^|\/)(postcss|next|tailwind|vite|webpack|rollup|svelte|nuxt|astro|babel|eslint|prettier)\.config\.[cm]?[jt]s$/i;
const CONFIG_MAX_BYTES = 2048; // 2 KB — un config normal pesa < 500 bytes

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
    desc: 'Ejecución dinámica de código',
    test: (c) => {
      const hits = [];
      if (/\beval\s*\(/.test(c)) hits.push('eval(');
      if (/new\s+Function\s*\(/.test(c)) hits.push('new Function(');
      if (/\bFunction\s*\(\s*['"`]return this/.test(c)) hits.push('Function("return this")');
      return hits.length ? hits.join(', ') : null;
    },
  },
  {
    name: 'base64-decode-exec',
    desc: 'Decodifica base64 y probablemente lo ejecuta',
    test: (c) => {
      const hasB64 = /atob\s*\(|Buffer\.from\s*\([^)]*['"`]base64['"`]/.test(c);
      const hasExec = /\beval\s*\(|new\s+Function\s*\(|child_process|execSync|spawn/.test(c);
      return hasB64 && hasExec ? 'base64 + eval/child_process' : null;
    },
  },
  {
    name: 'shell-exec',
    desc: 'Ejecución de comandos del sistema',
    test: (c, f) => {
      // Permitido en scripts de build/deploy propios; sospechoso en config/app.
      if (/scripts?\//.test(f.replace(/\\/g, '/'))) return null;
      if (/require\(\s*['"`]child_process['"`]\s*\)|from\s+['"`]node:child_process['"`]|\bexecSync\s*\(|\bspawn(Sync)?\s*\(/.test(c)) {
        return 'uso de child_process/exec';
      }
      return null;
    },
  },
  {
    name: 'hex-escape-heavy',
    desc: 'Cadenas con escape hexadecimal masivo (\\xNN)',
    test: (c) => {
      const m = c.match(/\\x[0-9a-fA-F]{2}/g);
      return m && m.length >= 50 ? `${m.length} secuencias \\xNN` : null;
    },
  },
  {
    name: 'long-obfuscated-line',
    desc: 'Línea larguísima con estructura de código minificado/ofuscado',
    test: (c, f) => {
      // Ignorar .json (datos legítimos largos).
      if (f.endsWith('.json')) return null;
      for (const line of c.split('\n')) {
        if (line.length <= 1500) continue;
        // Distinguir CÓDIGO minificado/ofuscado de un string largo de datos
        // (base64, paths de SVG, texto). El código tiene muchos operadores.
        const ops = (line.match(/[;{}]|=>|\)\s*\{|\}\s*\)|\bfunction\b|\|\||&&/g) || []).length;
        const density = ops / (line.length / 100); // operadores por cada 100 chars
        if (ops >= 25 && density >= 3) {
          return `línea de ${line.length} chars con ${ops} operadores (código minificado/ofuscado)`;
        }
      }
      return null;
    },
  },
  {
    name: 'config-too-large',
    desc: 'Archivo de configuración anormalmente grande (posible payload inyectado)',
    test: (c, f) => {
      if (!CONFIG_RE.test(f.replace(/\\/g, '/'))) return null;
      const bytes = Buffer.byteLength(c, 'utf8');
      return bytes > CONFIG_MAX_BYTES ? `${bytes} bytes (máx esperado ${CONFIG_MAX_BYTES})` : null;
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
        const bad = ['preinstall', 'install', 'postinstall'].filter((k) => s[k]);
        return bad.length ? `scripts: ${bad.join(', ')} — revisar manualmente` : null;
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
  for (const rule of RULES) {
    // suspicious-install-script solo aplica a package.json; el resto no debería
    // marcar package.json por datos legítimos, pero lo dejamos correr.
    const hit = rule.test(content, f);
    if (hit) findings.push({ file: f, rule: rule.name, detail: hit, desc: rule.desc });
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
console.error(`\nCommit/deploy BLOQUEADO. Revisa estos archivos. Si es un falso positivo,`);
console.error(`ajusta scripts/check-obfuscation.mjs o usa "git commit --no-verify" solo si estás 100% seguro.\n`);
process.exit(1);
