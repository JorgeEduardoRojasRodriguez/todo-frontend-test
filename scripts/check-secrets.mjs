#!/usr/bin/env node
/**
 * check-secrets.mjs — bloquea que se suban archivos con datos sensibles.
 *
 * Uso:
 *   node scripts/check-secrets.mjs            # revisa archivos rastreados por git
 *   node scripts/check-secrets.mjs --staged   # revisa solo lo que está en stage (pre-commit)
 *
 * Detecta (a) NOMBRES de archivo sensibles (.env, llaves, keystores, service-accounts)
 * y (b) CONTENIDO con secretos (llaves privadas, tokens GitHub/AWS/Stripe/Google, etc.).
 * Sale con código != 0 si encuentra algo. Diseñado para pre-commit y CI.
 *
 * Bypass de emergencia (solo si estás 100% seguro): git commit --no-verify
 */
import { execSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

const STAGED = process.argv.includes('--staged');

// Carpetas/artefactos a ignorar.
const IGNORE = [
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)\.next\//,
  /(^|\/)\.git\//,
  /(^|\/)coverage\//,
  /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/,
  // El propio escáner contiene los patrones como texto: excluirlo.
  /(^|\/)scripts\/check-secrets\.mjs$/,
];

// Nombres de ejemplo/plantilla permitidos (no llevan secretos reales).
const ALLOW_FILE = [
  /(^|\/)\.env\.(example|sample|template|dist|local\.example)$/i,
  /(^|\/)debug\.keystore$/i, // keystore de debug de Android: estándar y público, no es secreto
];

// NOMBRES de archivo que NO deben subirse nunca.
const SENSITIVE_FILE = [
  { re: /(^|\/)\.env(\.[A-Za-z0-9_.-]+)?$/i, why: 'archivo .env (variables de entorno con secretos)' },
  { re: /\.pem$/i, why: 'archivo .pem (posible llave/cert privado)' },
  { re: /\.(key|p12|pfx|jks|keystore)$/i, why: 'llave privada / keystore' },
  { re: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i, why: 'llave privada SSH' },
  { re: /(^|\/)(credentials|secret|secrets)\.(json|ya?ml)$/i, why: 'archivo de credenciales/secretos' },
  { re: /service[-_]?account.*\.json$/i, why: 'service account de Google/GCP' },
  { re: /firebase[-_]adminsdk.*\.json$/i, why: 'clave admin de Firebase' },
  { re: /\.mobileprovision$/i, why: 'perfil de aprovisionamiento de iOS' },
];

// PATRONES de contenido (alta confianza, poco ruido).
const SECRET_CONTENT = [
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, why: 'bloque de llave privada' },
  { re: /\bghp_[0-9A-Za-z]{36}\b/, why: 'token de acceso personal de GitHub (ghp_)' },
  { re: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/, why: 'token fino de GitHub (github_pat_)' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, why: 'AWS Access Key ID' },
  { re: /\bASIA[0-9A-Z]{16}\b/, why: 'AWS temporary Access Key ID' },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, why: 'token de Slack' },
  { re: /\bsk_live_[0-9A-Za-z]{16,}\b/, why: 'llave secreta LIVE de Stripe' },
  { re: /\brk_live_[0-9A-Za-z]{16,}\b/, why: 'restricted key LIVE de Stripe' },
  { re: /\bAIza[0-9A-Za-z_\-]{35}\b/, why: 'API key de Google' },
  { re: /\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b/, why: 'API key de SendGrid' },
  { re: /\bglpat-[0-9A-Za-z_\-]{20}\b/, why: 'token de GitLab' },
];

// Solo escaneamos contenido de archivos de texto (para secretos embebidos en código).
const TEXT_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|vue|json|ya?ml|env|txt|md|sh|py|rb|php|java|kt|properties|xml|html|toml|ini|cfg|conf)$/i;
const MAX_SCAN_BYTES = 512 * 1024; // no leer archivos enormes

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

const norm = (f) => f.replace(/\\/g, '/');
const ignored = (f) => IGNORE.some((re) => re.test(norm(f)));
const allowed = (f) => ALLOW_FILE.some((re) => re.test(norm(f)));

const files = tracked().filter((f) => !ignored(f));
const findings = [];

for (const f of files) {
  const p = norm(f);

  // (a) nombre sensible
  if (!allowed(f)) {
    const hit = SENSITIVE_FILE.find((s) => s.re.test(p));
    if (hit) findings.push({ file: f, kind: 'archivo', why: hit.why });
  }

  // (b) contenido con secretos (solo texto, tamaño razonable)
  if (!TEXT_EXT.test(p)) continue;
  let content;
  try {
    if (statSync(f).size > MAX_SCAN_BYTES) continue;
    content = readFileSync(f, 'utf8');
  } catch {
    continue;
  }
  for (const s of SECRET_CONTENT) {
    if (s.re.test(content)) findings.push({ file: f, kind: 'contenido', why: s.why });
  }
}

if (findings.length === 0) {
  console.log(`✔ Sin datos sensibles detectados (${STAGED ? 'stage' : 'repo'}).`);
  process.exit(0);
}

console.error(`\n✖ Se detectaron datos sensibles (${findings.length}):\n`);
for (const x of findings) {
  console.error(`  [${x.kind}] ${x.file}`);
  console.error(`      -> ${x.why}`);
}
console.error(`
Estos archivos/valores NO deben subirse al repositorio.
  - Si es un archivo (.env, llave, keystore): quítalo del stage y agrégalo a .gitignore.
      git rm --cached <archivo>   (si ya estaba trackeado)
  - Si es un secreto embebido: muévelo a una variable de entorno / .env (ignorado).
  - Rota cualquier credencial que ya se haya subido: se considera comprometida.
  - Bypass SOLO si estás 100% seguro de que es un ejemplo/placeholder:
      git commit --no-verify
`);
process.exit(1);
