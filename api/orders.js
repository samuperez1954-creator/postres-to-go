/* Postres To Go — API de pedidos (Vercel serverless + Upstash Redis por REST).
 *   POST   /api/orders            el cliente envía un pedido (página o app)
 *   GET    /api/orders?since=N    el panel lista los pedidos (necesita clave)
 *   PATCH  /api/orders            el panel cambia estado / pago / nota
 *   DELETE /api/orders?id=...     el panel borra un pedido
 * Variables de entorno: ADMIN_PIN, y la base de datos de Upstash
 * (KV_REST_API_URL + KV_REST_API_TOKEN, o UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN).
 */
'use strict';
const crypto = require('crypto');

const DB_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const DB_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';

const FLAVORS = {
  limon: 'Pie de limón', oreo: 'Cookies & Cream', avellana: 'Chocolate avellana', tres: 'Tres leches',
  cheese: 'Cheesecake', maracuya: 'Maracuyá', fresas: 'Fresas con crema'
};
const STATUSES = ['nuevo', 'preparando', 'listo', 'entregado', 'cancelado'];
const RECEIVERS = ['13464350004', '13465467997'];
const KEEP = 600;            // pedidos que lista el panel
const MAX_CANS = 500;        // tope por pedido

function unitPrice(n) { return n >= 25 ? 5.5 : n >= 7 ? 6 : n >= 4 ? 6.5 : 7; }

async function db(cmds) {
  const r = await fetch(DB_URL + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + DB_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds)
  });
  if (!r.ok) throw new Error('db ' + r.status);
  const out = await r.json();
  out.forEach(function (x) { if (x && x.error) throw new Error('db ' + x.error); });
  return out.map(function (x) { return x.result; });
}

function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.end(JSON.stringify(obj));
}

function clientIp(req) {
  const h = req.headers;
  return String(h['x-real-ip'] || (h['x-forwarded-for'] || '').split(',')[0] || 'unknown').trim().slice(0, 64);
}

function clean(v, max) {
  // Quita caracteres de control y recorta. El panel además escapa todo al mostrarlo.
  return String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function normPin(s) { return String(s || '').toUpperCase().replace(/[\s-]/g, ''); }
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(a).digest();
  const y = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(x, y);
}

/* Revisa la clave del panel, con bloqueo tras varios intentos fallidos. */
async function checkAdmin(req, res) {
  const pin = normPin(process.env.ADMIN_PIN);
  if (pin.length < 6) { send(res, 503, { error: 'pin_not_set' }); return false; }
  const ip = clientIp(req);
  const failKey = 'ptg:fail:' + ip;
  const [fails] = await db([['GET', failKey]]);
  if (Number(fails || 0) >= 8) { send(res, 429, { error: 'locked' }); return false; }
  const given = normPin(req.headers['x-admin-pin']);
  if (!given || !safeEqual(given, pin)) {
    await db([['INCR', failKey], ['EXPIRE', failKey, 900]]);
    send(res, 401, { error: 'bad_pin' });
    return false;
  }
  if (Number(fails || 0) > 0) await db([['DEL', failKey]]);
  return true;
}

function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch (e) { return false; }
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (e) { return null; } }
  return null;
}

async function createOrder(req, res) {
  if (!sameOrigin(req)) return send(res, 403, { error: 'origin' });
  const b = await readBody(req);
  if (!b || typeof b !== 'object') return send(res, 400, { error: 'body' });
  if (b.hp) return send(res, 200, { ok: true, number: 0 });   // trampa para robots: finge éxito

  // Límite por persona: 6 pedidos por 10 minutos
  const ip = clientIp(req);
  const rlKey = 'ptg:rl:' + ip + ':' + Math.floor(Date.now() / 600000);
  const [cnt] = await db([['INCR', rlKey], ['EXPIRE', rlKey, 700]]);
  if (Number(cnt) > 6) return send(res, 429, { error: 'rate' });

  // Productos: solo sabores conocidos, cantidades enteras
  const items = {};
  let n = 0;
  const src = b.items && typeof b.items === 'object' ? b.items : {};
  Object.keys(FLAVORS).forEach(function (id) {
    const q = Math.floor(Number(src[id]));
    if (q > 0) { items[id] = Math.min(q, MAX_CANS); n += items[id]; }
  });
  if (n < 1 || n > MAX_CANS) return send(res, 400, { error: 'items' });

  const name = clean(b.name, 60), phone = clean(b.phone, 30), addr = clean(b.addr, 160);
  const ship = b.ship === 'delivery' ? 'delivery' : 'pickup';
  const pay = b.pay === 'cash' ? 'cash' : 'zelle';
  if (!name || phone.replace(/\D/g, '').length < 7) return send(res, 400, { error: 'contact' });
  if (ship === 'delivery' && !addr) return send(res, 400, { error: 'addr' });

  // El precio lo calcula el servidor, nunca el celular del cliente
  const unit = unitPrice(n), shipCost = ship === 'delivery' && n < 4 ? 6 : 0;
  const total = Math.round((n * unit + shipCost) * 100) / 100;

  // Evita pedidos repetidos por doble clic (mismo contenido en 2 minutos)
  const sig = crypto.createHash('sha1').update(JSON.stringify([phone.replace(/\D/g, ''), items, ship, addr, total])).digest('hex').slice(0, 20);
  const dupKey = 'ptg:dup:' + sig;
  const [prev] = await db([['GET', dupKey]]);
  if (prev) return send(res, 200, { ok: true, number: Number(prev), dup: true });

  const [seq] = await db([['INCR', 'ptg:seq']]);
  const number = 1000 + Number(seq);
  const id = String(number);
  const ref = /^[A-Z0-9]{4,8}$/.test(String(b.ref || '')) ? String(b.ref) : '';
  const rcv = RECEIVERS.indexOf(String(b.rcv)) >= 0 ? String(b.rcv) : '';
  const order = {
    id: id, number: number, ref: ref, ts: Date.now(), status: 'nuevo', paid: false,
    name: name, phone: phone, ship: ship, addr: ship === 'delivery' ? addr : '',
    pay: pay, items: items, cans: n, unit: unit, shipCost: shipCost, total: total,
    when: clean(b.when, 60), note: clean(b.note, 200), lang: b.lang === 'en' ? 'en' : 'es',
    source: b.source === 'app' ? 'app' : 'web', rcv: rcv, adminNote: ''
  };
  await db([
    ['SET', 'ptg:order:' + id, JSON.stringify(order)],
    ['ZADD', 'ptg:orders', order.ts, id],
    ['SET', dupKey, number, 'EX', 120],
    ['INCR', 'ptg:ver']
  ]);
  return send(res, 200, { ok: true, number: number });
}

async function listOrders(req, res) {
  if (!(await checkAdmin(req, res))) return;
  const since = String((req.query && req.query.since) || '');
  const [ver] = await db([['GET', 'ptg:ver']]);
  const v = String(ver || '0');
  if (since && since === v) return send(res, 200, { ver: v, same: true });
  const [ids] = await db([['ZREVRANGE', 'ptg:orders', 0, KEEP - 1]]);
  let orders = [];
  if (ids && ids.length) {
    const rows = await db([['MGET'].concat(ids.map(function (i) { return 'ptg:order:' + i; }))]);
    orders = (rows[0] || []).filter(Boolean).map(function (s) { try { return JSON.parse(s); } catch (e) { return null; } }).filter(Boolean);
  }
  return send(res, 200, { ver: v, orders: orders });
}

async function patchOrder(req, res) {
  if (!sameOrigin(req)) return send(res, 403, { error: 'origin' });
  if (!(await checkAdmin(req, res))) return;
  const b = await readBody(req);
  const id = clean(b && b.id, 12);
  if (!/^\d{4,9}$/.test(id)) return send(res, 400, { error: 'id' });
  const [raw] = await db([['GET', 'ptg:order:' + id]]);
  if (!raw) return send(res, 404, { error: 'missing' });
  const o = JSON.parse(raw);
  if (b.status !== undefined) {
    if (STATUSES.indexOf(b.status) < 0) return send(res, 400, { error: 'status' });
    o.status = b.status;
  }
  if (b.paid !== undefined) o.paid = !!b.paid;
  if (b.adminNote !== undefined) o.adminNote = clean(b.adminNote, 300);
  o.updated = Date.now();
  await db([['SET', 'ptg:order:' + id, JSON.stringify(o)], ['INCR', 'ptg:ver']]);
  return send(res, 200, { ok: true, order: o });
}

async function deleteOrder(req, res) {
  if (!sameOrigin(req)) return send(res, 403, { error: 'origin' });
  if (!(await checkAdmin(req, res))) return;
  const id = clean(req.query && req.query.id, 12);
  if (!/^\d{4,9}$/.test(id)) return send(res, 400, { error: 'id' });
  await db([['DEL', 'ptg:order:' + id], ['ZREM', 'ptg:orders', id], ['INCR', 'ptg:ver']]);
  return send(res, 200, { ok: true });
}

module.exports = async function handler(req, res) {
  try {
    if (!DB_URL || !DB_TOKEN) return send(res, 503, { error: 'db_not_configured' });
    if (req.method === 'POST') return await createOrder(req, res);
    if (req.method === 'GET') return await listOrders(req, res);
    if (req.method === 'PATCH') return await patchOrder(req, res);
    if (req.method === 'DELETE') return await deleteOrder(req, res);
    res.setHeader('Allow', 'GET, POST, PATCH, DELETE');
    return send(res, 405, { error: 'method' });
  } catch (e) {
    console.error('orders api error:', e && e.message);
    return send(res, 500, { error: 'server' });
  }
};
