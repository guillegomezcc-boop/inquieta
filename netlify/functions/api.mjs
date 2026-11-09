/* Inquieta · API de la app (Netlify Functions + Blobs).
   - Solo Fernanda escribe: PIN de 6 números → llave firmada (HMAC) que queda guardada en su celular.
   - Datos: un solo documento con todas las colecciones. Cada cambio trae «modificado» y gana el más reciente;
     lo borrado queda como lápida para que también se borre en los otros celulares.
   - Fotos de ejercicios: /api/img/<id> (id aleatorio de 128 bits; sin datos de alumnos).
   - Alumno: /api/r/<link> devuelve SOLO su rutina actual (sin salud ni historial).
   - Alumno: POST /api/r/<link>/sesion guarda su entrenamiento (RPE, series, peso) en «sesiones», asociado a él. */
import { getStore } from '@netlify/blobs';
import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const COLS = new Set(['alumnos', 'rutinas', 'clases', 'base', 'ejercicios', 'plantillas', 'sesiones']);
const ORIGENES = new Set(['https://guillegomezcc-boop.github.io', 'https://inquieta.netlify.app', 'http://localhost:8790', 'http://127.0.0.1:8790']);
const MAX_DOC = 300000;
const MAX_IMG = 4.5 * 1024 * 1024;
const TIPOS_IMG = /^image\/(jpeg|png|webp|gif)$/;

const datosStore = () => getStore({ name: 'inquieta-datos', consistency: 'strong' });
const imgStore = () => getStore({ name: 'inquieta-img', consistency: 'strong' });
const b64u = (b) => Buffer.from(b).toString('base64url');
const espera = (ms) => new Promise((r) => setTimeout(r, ms));
const derivar = (pin, sal) => new Promise((ok, mal) => scrypt(pin, sal, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? mal(e) : ok(k))));
const iguales = (a, b) => a.length === b.length && timingSafeEqual(a, b);
const sinR = (d) => { const o = { ...d }; delete o._r; return o; };

function cors(req) {
  const o = req.headers.get('origin') || '';
  if (!ORIGENES.has(o) && !/^https:\/\/[a-z0-9-]+--inquieta\.netlify\.app$/.test(o)) return { Vary: 'Origin' };
  return { 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS', 'Access-Control-Max-Age': '86400', Vary: 'Origin' };
}
const json = (req, cuerpo, status = 200) => new Response(JSON.stringify(cuerpo), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors(req) } });
const error = (req, status, mensaje, extra = {}) => json(req, { mensaje, ...extra }, status);

// Configuración: secreto para firmar las llaves y el PIN (con sal, derivado con scrypt).
async function leerConfig(s) {
  let e = await s.getWithMetadata('config', { type: 'json' });
  if (!e) { await s.setJSON('config', { secreto: b64u(randomBytes(32)) }, { onlyIfNew: true }); e = await s.getWithMetadata('config', { type: 'json' }); }
  // Si Fernanda olvida el PIN: poner la variable INQ_BORRAR_PIN con un texto nuevo y volver a publicar borra el PIN una sola vez.
  const env = globalThis.Netlify && globalThis.Netlify.env;
  const borrar = env ? env.get('INQ_BORRAR_PIN') : '';
  if (borrar && e.data.pinBorrado !== borrar) {
    const c = { ...e.data, pinBorrado: borrar }; delete c.pin;
    await s.setJSON('config', c, { onlyIfMatch: e.etag });
    e = await s.getWithMetadata('config', { type: 'json' });
  }
  return { c: e.data, etag: e.etag };
}
function firmar(c) {
  const t = Date.now().toString(36);
  return `${c.pin.v}.${t}.${b64u(createHmac('sha256', c.secreto).update(c.pin.v + '.' + t).digest())}`;
}
function autorizado(req, c) {
  const m = (req.headers.get('authorization') || '').match(/^Bearer ([\w-]+)\.([\w-]+)\.([\w-]+)$/);
  if (!m || !c.pin || m[1] !== c.pin.v) return false;
  return iguales(Buffer.from(m[3], 'base64url'), createHmac('sha256', c.secreto).update(m[1] + '.' + m[2]).digest());
}

async function entrar(req, context, s) {
  const { c, etag } = await leerConfig(s);
  const cuerpo = await req.json().catch(() => ({}));
  const pin = String(cuerpo.pin || '');
  if (cuerpo.crear) {
    if (c.pin) return error(req, 409, 'Ya tienes un PIN. Escríbelo para entrar.', { hayPin: true });
    if (!/^\d{6}$/.test(pin)) return error(req, 400, 'El PIN tiene que ser de 6 números.');
    const sal = randomBytes(16);
    const nuevo = { ...c, pin: { sal: b64u(sal), hash: b64u(await derivar(pin, sal)), v: b64u(randomBytes(9)), creado: new Date().toISOString() } };
    const r = await s.setJSON('config', nuevo, { onlyIfMatch: etag });
    if (!r.modified) return error(req, 409, 'Ya tienes un PIN. Escríbelo para entrar.', { hayPin: true });
    return json(req, { token: firmar(nuevo) });
  }
  if (!c.pin) return error(req, 404, 'Todavía no hay PIN. Créalo desde el celular donde tienes tus datos.', { hayPin: false });
  // Bloqueo por intentos: 5 errores desde el mismo lugar → espera (cada vez más larga); tope diario general.
  const ip = (context && context.ip) || 'local';
  const lim = (await s.get('intentos', { type: 'json' })) || { ips: {}, dia: '', total: 0 };
  const hoy = new Date().toISOString().slice(0, 10);
  if (lim.dia !== hoy) Object.assign(lim, { dia: hoy, total: 0 });
  const yo = lim.ips[ip] || { n: 0, hasta: 0 };
  const ahora = Date.now();
  if (yo.hasta > ahora) return error(req, 429, `Demasiados intentos. Espera ${Math.ceil((yo.hasta - ahora) / 60000)} min y vuelve a probar.`, { hayPin: true });
  if (lim.total >= 100) return error(req, 429, 'Demasiados intentos por hoy. Prueba de nuevo mañana.', { hayPin: true });
  const ok = /^\d{6}$/.test(pin) && iguales(await derivar(pin, Buffer.from(c.pin.sal, 'base64url')), Buffer.from(c.pin.hash, 'base64url'));
  if (!ok) {
    yo.n += 1; lim.total += 1;
    if (yo.n >= 5) yo.hasta = ahora + 15 * 60000 * 2 ** Math.min(5, yo.n - 5);
    lim.ips[ip] = yo;
    const ips = Object.entries(lim.ips); if (ips.length > 300) lim.ips = Object.fromEntries(ips.slice(-300));
    await s.setJSON('intentos', lim);
    await espera(350);
    return error(req, 401, yo.hasta > ahora ? 'PIN incorrecto. Por seguridad, espera 15 minutos antes de intentar otra vez.' : `PIN incorrecto. Te quedan ${5 - yo.n} ${5 - yo.n === 1 ? 'intento' : 'intentos'}.`, { hayPin: true });
  }
  if (lim.ips[ip]) { delete lim.ips[ip]; await s.setJSON('intentos', lim); }
  return json(req, { token: firmar(c) });
}

async function datos(req, s) {
  const cuerpo = req.method === 'POST' ? await req.json().catch(() => null) : null;
  const desde = Math.max(0, Number(cuerpo ? cuerpo.desde : new URL(req.url).searchParams.get('desde')) || 0);
  const cambios = cuerpo && Array.isArray(cuerpo.cambios) ? cuerpo.cambios.slice(0, 5000) : [];
  for (let intento = 0; intento < 8; intento++) {
    const e = await s.getWithMetadata('datos', { type: 'json' });
    const D = e && e.data ? e.data : { rev: 0, docs: {} };
    const rev = (D.rev || 0) + 1; let hubo = false;
    for (const x of cambios) {
      if (!x || !COLS.has(x.c) || typeof x.id !== 'string' || !x.id || x.id.length > 120) continue;
      const col = D.docs[x.c] || (D.docs[x.c] = {});
      const prev = col[x.id];
      let doc;
      if (x.d && typeof x.d === 'object' && !Array.isArray(x.d)) { if (JSON.stringify(x.d).length > MAX_DOC) continue; doc = sinR(x.d); }
      else doc = { _borrado: true, modificado: String(x.m || new Date().toISOString()) };
      if (prev && String(prev.modificado || '') > String(doc.modificado || '')) continue; // en la nube hay algo más nuevo
      if (prev && JSON.stringify(sinR(prev)) === JSON.stringify(doc)) continue;
      col[x.id] = { ...doc, _r: rev }; hubo = true;
    }
    if (hubo) {
      D.rev = rev;
      const r = !e ? await s.setJSON('datos', D, { onlyIfNew: true }) : e.etag ? await s.setJSON('datos', D, { onlyIfMatch: e.etag }) : await s.setJSON('datos', D);
      if (!r.modified) { await espera(50 + Math.random() * 100 * (intento + 1)); continue; } // otro celular escribió justo ahora
    }
    const salida = [];
    for (const [c, col] of Object.entries(D.docs)) for (const [id, d] of Object.entries(col)) if ((d._r || 0) > desde) salida.push({ c, id, d: sinR(d) });
    return json(req, { rev: D.rev || 0, cambios: salida });
  }
  return error(req, 503, 'La nube está ocupada. Se reintenta solo.');
}

async function imagen(req, id, c) {
  const st = imgStore();
  if (req.method === 'GET') {
    const e = await st.getWithMetadata(id, { type: 'arrayBuffer' });
    if (!e) return new Response('No existe', { status: 404, headers: cors(req) });
    return new Response(e.data, { headers: { 'Content-Type': (e.metadata && e.metadata.tipo) || 'image/jpeg', 'Cache-Control': 'public, max-age=31536000, immutable', ...cors(req) } });
  }
  if (!autorizado(req, c)) return error(req, 401, 'Tu sesión se cerró. Escribe tu PIN otra vez.');
  const tipo = (req.headers.get('content-type') || '').split(';')[0].trim();
  if (!TIPOS_IMG.test(tipo)) return error(req, 415, 'Solo fotos JPG, PNG, WebP o GIF.');
  const buf = await req.arrayBuffer();
  if (!buf.byteLength || buf.byteLength > MAX_IMG) return error(req, 413, 'La imagen es muy pesada (máximo 4 MB).');
  await st.set(id, buf, { metadata: { tipo } });
  return json(req, { ok: true });
}

// Lo que ve el alumno con su link: su nombre de pila y su rutina actual. Nada de salud ni del historial.
async function rutinaAlumno(req, token, s) {
  const D = (await s.get('datos', { type: 'json' })) || { docs: {} };
  const t = Buffer.from(token);
  const al = Object.entries(D.docs.alumnos || {}).find(([, a]) => !a._borrado && typeof a.token === 'string' && iguales(Buffer.from(a.token), t));
  if (!al) return error(req, 404, 'Este link ya no está activo. Pídele uno nuevo a tu entrenadora.');
  const [aid, a] = al;
  const rutinas = Object.values(D.docs.rutinas || {}).filter((w) => !w._borrado && w.alumnoId === aid && !w.archivada)
    .sort((x, y) => String(x.letra).localeCompare(String(y.letra), 'es', { numeric: true }));
  const limpiar = (e) => { const o = { n: String(e.n || '') }; for (const k of ['lib', 'plan', 'se', 're', 'ti', 'pe', 'de', 'no']) if (e[k] != null && e[k] !== '') o[k] = e[k]; return o; };
  const dias = rutinas.map((w) => ({
    letra: String(w.letra || ''), titulo: String(w.titulo || ''),
    ej: w.circuitos ? w.circuitos.flatMap((c) => (c.ej || []).map((e) => ({ n: String(e.n || ''), ...(e.lib ? { lib: String(e.lib) } : {}), plan: [e.p, e.r].filter(Boolean).join(' · '), bloque: String(c.nombre || '') }))) : (w.ej || []).map(limpiar),
  }));
  const ejercicios = {};
  for (const [id, x] of Object.entries(D.docs.ejercicios || {})) {
    if (x._borrado) continue;
    const o = {}; for (const k of ['n', 'g', 'm', 's', 'nota', 'img', 'base', 'oculto', 'al']) if (x[k] != null && x[k] !== '') o[k] = x[k];
    ejercicios[id] = o;
  }
  const actualizado = rutinas.reduce((m, w) => (String(w.modificado || '') > m ? String(w.modificado) : m), '');
  return json(req, { nombre: String(a.nombre || '').trim().split(/\s+/)[0], entrenadora: 'Fernanda Rojas', dias, ejercicios, actualizado });
}

// El alumno guarda su sesión: solo con su link, solo para él, con campos acotados. Llega a Fernanda con la sincronización.
const txt = (v, n) => String(v ?? '').slice(0, n);
const num = (v, a, b) => { if (v == null || v === '') return null; const x = Number(v); return Number.isFinite(x) ? Math.min(b, Math.max(a, x)) : null; };
async function sesionAlumno(req, token, s) {
  const b = await req.json().catch(() => null);
  if (!b || typeof b !== 'object' || !/^se-[\w-]{6,40}$/.test(String(b.id || ''))) return error(req, 400, 'Sesión no válida.');
  if (JSON.stringify(b).length > 40000) return error(req, 413, 'Sesión demasiado grande.');
  const lista = (l, max) => (Array.isArray(l) ? l.slice(0, max) : []);
  const doc = {
    fecha: /^\d{4}-\d{2}-\d{2}$/.test(String(b.fecha || '')) ? b.fecha : new Date().toISOString().slice(0, 10),
    inicio: txt(b.inicio, 30), fin: txt(b.fin, 30), duracion: num(b.duracion, 0, 6 * 3600),
    dia: txt(b.dia, 12), titulo: txt(b.titulo, 80), obs: txt(b.obs, 600),
    ej: lista(b.ej, 40).map((e) => ({ n: txt(e && e.n, 120), lib: txt(e && e.lib, 60), hecho: !!(e && e.hecho), series: num(e && e.series, 0, 30), reps: txt(e && e.reps, 40), peso: txt(e && e.peso, 40), rpe: num(e && e.rpe, 1, 10), plan: txt(e && e.plan, 80) })),
    cal: num(b.cal, 0, 30), calTotal: num(b.calTotal, 0, 30), est: num(b.est, 0, 30), estTotal: num(b.estTotal, 0, 30),
    modificado: new Date().toISOString(),
  };
  for (let intento = 0; intento < 8; intento++) {
    const e = await s.getWithMetadata('datos', { type: 'json' });
    const D = e && e.data ? e.data : { rev: 0, docs: {} };
    const t = Buffer.from(token);
    const al = Object.entries(D.docs.alumnos || {}).find(([, a]) => !a._borrado && typeof a.token === 'string' && iguales(Buffer.from(a.token), t));
    if (!al) return error(req, 404, 'Este link ya no está activo. Pídele uno nuevo a tu entrenadora.');
    const col = D.docs.sesiones || (D.docs.sesiones = {});
    const prev = col[b.id];
    if (prev && prev.alumnoId !== al[0]) return error(req, 409, 'Sesión no válida.');
    D.rev = (D.rev || 0) + 1;
    col[b.id] = { ...doc, alumnoId: al[0], _r: D.rev };
    const r = !e ? await s.setJSON('datos', D, { onlyIfNew: true }) : await s.setJSON('datos', D, { onlyIfMatch: e.etag });
    if (r.modified) return json(req, { ok: true });
    await espera(50 + Math.random() * 100 * (intento + 1));
  }
  return error(req, 503, 'La nube está ocupada. Se reintenta solo.');
}

export default async (req, context) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(req) });
  const p = new URL(req.url).pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  try {
    if (p[0] === 'img' && /^[a-f0-9]{32}$/.test(p[1] || '') && (req.method === 'GET' || req.method === 'PUT')) {
      return await imagen(req, p[1], req.method === 'PUT' ? (await leerConfig(datosStore())).c : null);
    }
    if (p[0] === 'r' && /^[\w-]{16,64}$/.test(p[1] || '') && req.method === 'GET') return await rutinaAlumno(req, p[1], datosStore());
    if (p[0] === 'r' && /^[\w-]{16,64}$/.test(p[1] || '') && p[2] === 'sesion' && req.method === 'POST') return await sesionAlumno(req, p[1], datosStore());
    const s = datosStore();
    if (p[0] === 'estado' && req.method === 'GET') { const { c } = await leerConfig(s); return json(req, { pin: !!c.pin }); }
    if (p[0] === 'entrar' && req.method === 'POST') return await entrar(req, context, s);
    if (p[0] === 'datos' && (req.method === 'POST' || req.method === 'GET')) {
      const { c } = await leerConfig(s);
      if (!autorizado(req, c)) return error(req, 401, 'Tu sesión se cerró. Escribe tu PIN otra vez.');
      return await datos(req, s);
    }
    return error(req, 404, 'No existe.');
  } catch (e) {
    console.error('api', p.join('/'), e);
    return error(req, 500, 'Hubo un problema en la nube. Inténtalo de nuevo.');
  }
};

export const config = { path: '/api/*' };
