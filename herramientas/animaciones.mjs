// Inquieta · herramienta para las animaciones a pedido (animaciones.json).
//   node herramientas/animaciones.mjs                 valida todo animaciones.json (debe terminar en «todo ok»)
//   node herramientas/animaciones.mjs --hoja h.html   además escribe una hoja con 4 cuadros de cada animación, para mirarla
//   node herramientas/animaciones.mjs --guia          imprime la guía del formato de posturas (la misma que usa la app)
// Usa el motor y la biblioteca que están dentro de index.html: lo que pasa aquí es lo que verá la app.
import { readFileSync, writeFileSync } from 'node:fs';
import vm from 'node:vm';
const raiz = new URL('..', import.meta.url).pathname;
const html = readFileSync(raiz + 'index.html', 'utf8');
const trozo = (a, b) => { const i = html.indexOf(a); const j = html.indexOf(b, i); if (i < 0 || j < 0) throw new Error('no encuentro ' + a); return html.slice(i, j + b.length); };
const cargar = (codigo, nombre) => { const m = { exports: {} }; vm.runInNewContext(codigo, { module: m, console }, { filename: nombre }); return m.exports; };
const FIG = cargar(trozo('/* Inquieta · dibujos propios', 'module.exports = FIG;'), 'figura.js');
const EJ = cargar(trozo('/* Inquieta · biblioteca inicial', 'module.exports = EJ;'), 'ejercicios.js');
if (process.argv.includes('--guia')) {
  const api = readFileSync(raiz + 'netlify/functions/api.mjs', 'utf8'); const m = api.match(/const GUIA_ANIM = ("(?:[^"\\]|\\.)*");/);
  console.log(JSON.parse(m[1])); process.exit(0);
}
const J = JSON.parse(readFileSync(raiz + 'animaciones.json', 'utf8')); let mal = 0; const hojas = [];
for (const [id, x] of Object.entries(J.anim || {})) {
  const problemas = [];
  if (!/^[\w-]{3,40}$/.test(id)) problemas.push('id inválido');
  const limpia = EJ.limpiarAnim(x.anim);
  if (!limpia) problemas.push('la animación no tiene el formato correcto');
  else {
    if (JSON.stringify(limpia) !== JSON.stringify(EJ.limpiarAnim(JSON.parse(JSON.stringify(limpia))))) problemas.push('formato inestable');
    const e = EJ.propia(id, { n: x.n, g: x.g, m: x.m, s: x.s, anim: x.anim });
    const r = FIG.validar(e); if (!r.ok) problemas.push(...r.fallas);
    if (limpia.f.length < 1) problemas.push('sin posturas');
    FIG.figura(e, { animar: true });
    const R = FIG.cuadros(e).fr; const n = R.length; const elegidos = n > 3 ? [0, Math.floor(n / 6), Math.floor(n / 3), Math.floor(n / 2)].map((i) => R[i]) : R;
    hojas.push(`<figure><div>${elegidos.map((Q) => FIG.figura({ ...e, id: id + Math.random(), f: [Q], _listo: false, ico: 0 })).join('')}</div><figcaption>${x.n} · ${r.ok ? 'validada' : r.fallas.join(', ')}${r.avisos.length ? ' · avisos: ' + r.avisos.join(', ') : ''}</figcaption></figure>`);
  }
  if (!x.n) problemas.push('falta el nombre (n)');
  if (problemas.length) { mal++; console.log('✗', id, x.n || '', '→', problemas.join(' | ')); } else console.log('✓', id, x.n);
}
const i = process.argv.indexOf('--hoja');
if (i > 0) writeFileSync(process.argv[i + 1], `<!doctype html><meta charset="utf-8"><style>body{font:14px system-ui;margin:16px;background:#fff}figure{margin:0 0 18px}figure div{display:grid;grid-template-columns:repeat(4,1fr);gap:6px}svg{width:100%;height:auto;background:#f4f6f8;border-radius:8px}.fig .b1,.fig .b2{fill:#1e2530}.fig .b2{fill:#8b93a1}.fig .h1{fill:#00cfcb}.fig .h2{fill:#7fe3e0}.fig .ln{fill:none;stroke:#1e2530;stroke-linecap:round}.fig .e1,.fig .e2{fill:#566072}.fig .e4{fill:#c9d0da}.fig .bd{stroke:#00cfcb}.fig .bg{fill:#fff}</style>${hojas.join('')}`);
console.log(mal ? `${mal} con problemas` : `todo ok (${Object.keys(J.anim || {}).length} animaciones)`);
process.exit(mal ? 1 : 0);
