#!/usr/bin/env node
/**
 * check-deps.mjs — revisa las dependencias, la otra puerta de entrada del malware.
 *
 * Uso:
 *   node scripts/check-deps.mjs
 *
 * Falla duro (código != 0) solo con lo que indica compromiso real:
 *   1. Advisories de PAQUETE MALICIOSO (malware, backdoor, criptominero, cuenta
 *      del autor secuestrada). Es exactamente el vector de "hackearon el paquete".
 *   2. Dependencias resueltas FUERA del registro oficial de npm (tarball suelto,
 *      URL de git, host raro): se puede meter código arbitrario sin publicar nada.
 *
 * Reporta sin fallar los CVEs normales (critical/high/moderate/low). Son deuda
 * técnica que hay que atender, pero si tumbaran el build cada vez, el rojo se
 * vuelve el estado normal y ahí se esconde lo que sí es un ataque.
 *
 * Bypass de emergencia (solo si estás 100% seguro): git commit --no-verify
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

// Marcadores de que el advisory habla de código malicioso, no de un bug.
//
// El campo cwe es lo confiable: GitHub clasifica el malware real como CWE-506
// (código malicioso embebido) o CWE-912 (funcionalidad oculta), y ningún CVE
// corriente los usa. Buscar palabras en el título no sirve solo: "Request
// Hijacking" y "compiling malicious input" son bugs de prototype pollution y de
// generación de código, y darían falso positivo en axios y en @babel.
const MALWARE_CWE = new Set(['CWE-506', 'CWE-912']);

// Títulos que solo aparecen en advisories de malware, como red de respaldo por
// si un advisory viene sin cwe.
const MALWARE_TITULO = /(contains|embeds) malicious code|^malicious (package|code|version)\b|embedded malware|is a malicious|crypto ?(currency )?miner|malicious version of/i;

function es_malware(via) {
  for (const c of via.cwe ?? []) {
    if (MALWARE_CWE.has(c)) return true;
  }
  return MALWARE_TITULO.test(via.title ?? '');
}

// De dónde es legítimo bajar un paquete.
const REGISTRO_OK = /^https?:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com)\//;

const LOCKS = ['package-lock.json', 'npm-shrinkwrap.json'];
const lock = LOCKS.find((f) => existsSync(f));

if (!existsSync('package.json')) {
  console.log('✔ Sin package.json: no hay dependencias de npm que revisar.');
  process.exit(0);
}
if (!lock) {
  console.log('✔ Sin package-lock.json: no hay árbol de dependencias fijado que revisar.');
  console.log('  (Conviene commitear el lockfile: sin él, cada instalación puede traer código distinto.)');
  process.exit(0);
}

const hallazgos = [];

// ── 1) Advisories de paquete malicioso ────────────────────────────────────────
// npm audit sale con código != 0 cuando encuentra algo, así que hay que capturar
// la salida en lugar de dejar que la excepción se propague.
function auditar() {
  try {
    return execFileSync('npm', ['audit', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 64 * 1024 * 1024,
      shell: process.platform === 'win32',
    });
  } catch (e) {
    // Con vulnerabilidades presentes el JSON viene igual en stdout.
    if (e.stdout) return e.stdout;
    return null;
  }
}

const bruto = auditar();
let resumen = null;

if (!bruto) {
  console.log('⚠ No se pudo ejecutar "npm audit" (¿sin red?). Se revisa solo el lockfile.');
} else {
  let datos;
  try {
    datos = JSON.parse(bruto);
  } catch {
    console.log('⚠ La salida de "npm audit" no se pudo interpretar. Se revisa solo el lockfile.');
    datos = null;
  }

  if (datos) {
    resumen = datos.metadata?.vulnerabilities ?? null;

    // Formato de npm 7+.
    for (const [nombre, info] of Object.entries(datos.vulnerabilities ?? {})) {
      for (const via of info.via ?? []) {
        if (typeof via !== 'object') continue;
        if (es_malware(via)) {
          hallazgos.push({
            kind: 'paquete-malicioso',
            file: `${nombre}@${info.range ?? '?'}`,
            why: `${via.title ?? 'sin titulo'}${via.url ? ` (${via.url})` : ''}`,
          });
        }
      }
    }

    // Formato de npm 6, por si algún repo usa un npm viejo.
    for (const a of Object.values(datos.advisories ?? {})) {
      if (es_malware({ title: a.title, cwe: a.cwe ? [a.cwe] : [] })) {
        hallazgos.push({
          kind: 'paquete-malicioso',
          file: `${a.module_name}@${a.vulnerable_versions ?? '?'}`,
          why: a.title,
        });
      }
    }
  }
}

// ── 2) Dependencias que no vienen del registro oficial ────────────────────────
// Se lee el lockfile directo: no hace falta red y detecta el caso en que alguien
// apunta una dependencia a un tarball propio.
try {
  const datos = JSON.parse(readFileSync(lock, 'utf8'));
  const paquetes = datos.packages ?? {};
  for (const [ruta, info] of Object.entries(paquetes)) {
    if (!ruta) continue; // "" es el propio proyecto
    const url = info.resolved;
    if (!url) continue; // los link/workspace locales no traen resolved
    if (info.link) continue;
    if (REGISTRO_OK.test(url)) continue;
    hallazgos.push({
      kind: 'origen-no-oficial',
      file: ruta.replace(/^node_modules\//, ''),
      why: `se descarga de ${url}`,
    });
  }
} catch (e) {
  console.log(`⚠ No se pudo leer ${lock}: ${e.message}`);
}

// ── Reporte ───────────────────────────────────────────────────────────────────
if (resumen) {
  const { critical = 0, high = 0, moderate = 0, low = 0 } = resumen;
  const total = critical + high + moderate + low;
  if (total === 0) {
    console.log('✔ npm audit: sin vulnerabilidades conocidas.');
  } else {
    console.log(`ℹ npm audit: critical=${critical} high=${high} moderate=${moderate} low=${low}`);
    console.log('  Esto NO tumba el build. Atiéndelo con "npm audit fix" cuando puedas.');
  }
}

if (hallazgos.length === 0) {
  console.log('✔ Sin paquetes maliciosos ni orígenes sospechosos.');
  process.exit(0);
}

console.error(`\n✖ Dependencias sospechosas (${hallazgos.length}):\n`);
for (const x of hallazgos) {
  console.error(`  [${x.kind}] ${x.file}`);
  console.error(`      -> ${x.why}`);
}
console.error(`
Una dependencia comprometida ejecuta código en tu máquina y en CI.
  - [paquete-malicioso] Sube o baja de versión ya: "npm audit fix" o fija una versión sana.
      Da por comprometido todo secreto que haya estado en esa máquina o en ese CI, y rótalo.
  - [origen-no-oficial] Una dependencia que no viene de registry.npmjs.org debe estar
      justificada. Si nadie la puso a propósito, es una vía de entrada: quítala.
  - Bypass SOLO si sabes exactamente por qué está ahí:
      git commit --no-verify
`);
process.exit(1);
