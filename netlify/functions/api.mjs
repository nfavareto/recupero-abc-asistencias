// Gestión de llamados — Recupero de medio de pago Medic Assist
// Backend: Netlify Functions v2 + Netlify Blobs (sin base externa)
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

/* ───────────── Definiciones de campaña ───────────── */
const TIPS = {
  no_efectivo: {
    label: "No efectivos",
    items: [
      { k: "tm", label: "TM (9 a 13)", franja: "TM" },
      { k: "no_contesta", label: "No contesta" },
      { k: "contestador", label: "Contestador" },
      { k: "reciclado", label: "Reciclado" },
      { k: "archivar", label: "Archivar", cierra: true },
      { k: "datos_erroneos", label: "Datos erróneos" },
      { k: "tt", label: "TT (13 a 17)", franja: "TT" },
      { k: "tn", label: "TN (17 a 21)", franja: "TN" },
    ],
  },
  efectivo: {
    label: "Efectivos",
    items: [
      { k: "no_reune", label: "No reúne requisitos", cierra: true },
      { k: "solo_debito", label: "Solo T Débito", cierra: true },
      { k: "fallecido", label: "Fallecido", cierra: true },
      { k: "ya_tiene", label: "Ya tiene el producto", cierra: true },
      { k: "volver", label: "Volver a llamar", agenda: "requerida" },
      { k: "no_interesado", label: "No interesado", cierra: true },
      { k: "interesado", label: "Interesado", agenda: "opcional" },
      {
        k: "venta", label: "Venta", cierra: true, venta: true,
        subs: ["1 MA 1 Electro 1 Odonto", "2 MA 1 Electro 2 Odonto", "3 MA 1 Electro 3 Odonto"],
      },
    ],
  },
};
const MARCAS = ["Visa", "Mastercard", "American Express", "Naranja"];
const DEF_CONFIG = {
  campaign: "Recupero de medio de pago — Medic Assist",
  maxIntentos: 5,
  quincenaEstricta: true,
  minEntreIntentos: 60,
  lockMin: 15,
  horaInicio: 9,
  horaFin: 13,
  maxDiarios: 2,
};

/* ───────────── Utilidades ───────────── */
const store = () => getStore({ name: "medic-recupero", consistency: "strong" });
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
class HttpError extends Error { constructor(m, s = 400) { super(m); this.status = s; } }
const fail = (m, s = 400) => { throw new HttpError(m, s); };

async function readJSON(key, def) {
  const v = await store().get(key, { type: "json" });
  return v ?? def;
}
// Escritura con control de concurrencia optimista (etag) y reintentos
async function mutate(key, def, fn) {
  const st = store();
  for (let i = 0; i < 8; i++) {
    const cur = await st.getWithMetadata(key, { type: "json" });
    const data = cur ? cur.data : structuredClone(def);
    const res = await fn(data);
    const r = await st.setJSON(key, data, cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true });
    if (!r || r.modified !== false) return res;
    await new Promise((ok) => setTimeout(ok, 60 * (i + 1) + Math.random() * 60));
  }
  fail("Hubo mucha actividad simultánea. Probá guardar de nuevo.", 409);
}

// Hora Argentina (UTC-3, sin horario de verano)
const arDate = (t = Date.now()) => new Date(t - 3 * 3600e3);
const franjaNow = () => {
  const h = arDate().getUTCHours();
  if (h >= 9 && h < 13) return "TM";
  if (h >= 13 && h < 17) return "TT";
  if (h >= 17 && h < 21) return "TN";
  return null;
};
const horaAR = (t = Date.now()) => { const d = arDate(t); return d.getUTCHours() + d.getUTCMinutes() / 60; };
const enHorario = (cfg, t) => { const h = horaAR(t); return h >= cfg.horaInicio && h < cfg.horaFin; };
const quincenaNow = () => (arDate().getUTCDate() <= 15 ? 1 : 2);
const startOfDayAR = () => {
  const d = arDate();
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) + 3 * 3600e3;
};
const digits = (s) => String(s ?? "").replace(/\D/g, "");

/* ───────────── Auth ───────────── */
const hashP = (p, salt = crypto.randomBytes(16).toString("hex")) => ({
  salt, hash: crypto.scryptSync(String(p), salt, 32).toString("hex"),
});
const checkP = (p, u) => {
  const a = Buffer.from(crypto.scryptSync(String(p), u.salt, 32).toString("hex"));
  const b = Buffer.from(u.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
async function getUsers() {
  let d = await readJSON("users", null);
  if (!d) {
    const ip = process.env.INIT_PASS || "Medic2026!";
    d = {
      users: [
        { u: "supervisor", name: "Supervisor", role: "supervisor", activo: true, ...hashP(ip) },
        { u: "operador1", name: "Operador 1", role: "operador", quincena: 1, activo: true, ...hashP(ip) },
        { u: "operador2", name: "Operador 2", role: "operador", quincena: 2, activo: true, ...hashP(ip) },
        { u: "cliente", name: "Medic Assist", role: "cliente", activo: true, ...hashP(ip) },
      ],
    };
    await store().setJSON("users", d);
  }
  return d;
}
const publicUser = (u) => ({ u: u.u, name: u.name, role: u.role, quincena: u.quincena || null, activo: u.activo !== false });

async function auth(req) {
  const tok = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!/^[a-f0-9]{64}$/.test(tok)) fail("Sesión vencida. Ingresá de nuevo.", 401);
  const s = await readJSON(`ses/${tok}`, null);
  if (!s || s.exp < Date.now()) fail("Sesión vencida. Ingresá de nuevo.", 401);
  const { users } = await getUsers();
  const u = users.find((x) => x.u === s.u && x.activo !== false);
  if (!u) fail("Usuario inactivo.", 401);
  return { ...publicUser(u), token: tok };
}
const need = (user, ...roles) => { if (!roles.includes(user.role)) fail("No tenés permiso para esta acción.", 403); };

/* ───────────── Cifrado de tarjetas ───────────── */
function tcKey() {
  const k = process.env.TC_KEY;
  if (!k || k.length < 16) fail("Falta configurar la variable TC_KEY en Netlify (mínimo 16 caracteres). Sin ella no se pueden guardar tarjetas.", 500);
  return crypto.createHash("sha256").update(k).digest();
}
function encrypt(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", tcKey(), iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") };
}
function decrypt(e) {
  const d = crypto.createDecipheriv("aes-256-gcm", tcKey(), Buffer.from(e.iv, "base64"));
  d.setAuthTag(Buffer.from(e.tag, "base64"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(e.data, "base64")), d.final()]).toString("utf8"));
}
const luhn = (n) => {
  let s = 0, alt = false;
  for (let i = n.length - 1; i >= 0; i--) {
    let d = +n[i];
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    s += d; alt = !alt;
  }
  return s % 10 === 0;
};
function validarTC({ numero, banco, marca, vto }) {
  const n = digits(numero);
  if (!MARCAS.includes(marca)) fail("Elegí la marca de la tarjeta.");
  if (!String(banco || "").trim()) fail("Completá el banco emisor.");
  if (marca === "American Express") {
    if (!/^3[47]\d{13}$/.test(n)) fail("Una American Express tiene 15 dígitos y empieza con 34 o 37.");
  } else if (marca === "Visa") {
    if (!/^4\d{12}(\d{3}){0,2}$/.test(n)) fail("Una Visa empieza con 4 y tiene 13, 16 o 19 dígitos.");
  } else if (marca === "Mastercard") {
    if (!/^(5[1-5]\d{14}|2(2[2-9]\d|[3-6]\d\d|7[01]\d|720)\d{12})$/.test(n)) fail("Una Mastercard empieza con 51–55 o 2221–2720 y tiene 16 dígitos.");
  } else if (marca === "Naranja") {
    if (!/^\d{16}$/.test(n)) fail("Una Naranja tiene 16 dígitos.");
  }
  if (marca !== "Naranja" && !luhn(n)) fail("El número no es válido (falla el dígito verificador). Revisalo con el cliente.");
  let v = String(vto || "").trim();
  if (v) {
    const m = v.match(/^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/);
    if (!m || +m[1] < 1 || +m[1] > 12) fail("El vencimiento va como MM/AA.");
    v = `${m[1].padStart(2, "0")}/${m[2].slice(-2)}`;
  }
  return { numero: n, banco: String(banco).trim(), marca, vto: v };
}

/* ───────────── Registros ───────────── */
const REC_DEF = { seq: 0, items: {} };
const findTip = (grupo, k) => TIPS[grupo]?.items.find((i) => i.k === k);
const recState = (r) => (r.estado === "cerrado" ? "cerrado" : r.intentos > 0 ? "en_curso" : "pendiente");
async function audit(user, accion, detalle) {
  await mutate("audit", { items: [] }, (a) => {
    a.items.push({ at: Date.now(), u: user.u, accion, detalle });
    if (a.items.length > 5000) a.items = a.items.slice(-5000);
  });
}
function checkQuincena(user, cfg) {
  if (user.role === "operador" && cfg.quincenaEstricta && user.quincena && user.quincena !== quincenaNow()) {
    fail(user.quincena === 1
      ? "Tu período de gestión es del 1 al 15 de cada mes. El supervisor puede habilitarte desde Configuración."
      : "Tu período de gestión es del 16 a fin de mes. El supervisor puede habilitarte desde Configuración.", 403);
  }
}
function lockedByOther(r, user) {
  return r.lock && r.lock.until > Date.now() && r.lock.by !== user.u;
}

/* ───────────── Handler ───────────── */
export default async (req) => {
  try {
    const url = new URL(req.url);
    const p = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
    const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};

    /* Login */
    if (p === "login") {
      const { users } = await getUsers();
      const u = users.find((x) => x.u === String(body.u || "").trim().toLowerCase());
      if (!u || u.activo === false || !checkP(body.p || "", u)) fail("Usuario o contraseña incorrectos.", 401);
      const token = crypto.randomBytes(32).toString("hex");
      await store().setJSON(`ses/${token}`, { u: u.u, exp: Date.now() + 12 * 3600e3 });
      return json({ token, user: publicUser(u) });
    }

    const user = await auth(req);
    const cfg = { ...DEF_CONFIG, ...(await readJSON("config", {})) };

    switch (p) {
      case "logout": {
        await store().delete(`ses/${user.token}`);
        return json({ ok: true });
      }

      case "state": {
        const out = { user, config: cfg, tips: TIPS, marcas: MARCAS, franja: franjaNow(), enHorario: enHorario(cfg), quincena: quincenaNow() };
        const recs = await readJSON("records", REC_DEF);
        const items = Object.values(recs.items);
        out.fuentes = [...new Set(items.map((r) => r.fuente))].sort();
        if (user.role === "operador") {
          const t0 = startOfDayAR();
          let hoy = 0, contactos = 0, ventas = 0;
          for (const r of items) for (const h of r.hist || [])
            if (h.by === user.u && h.at >= t0) { hoy++; if (h.grupo === "efectivo") contactos++; if (h.k === "venta") ventas++; }
          out.hoy = { gestiones: hoy, contactos, ventas };
          out.abiertos = items.filter((r) => r.estado !== "cerrado").length;
          out.agendaVencida = items.filter((r) => r.estado !== "cerrado" && r.agenda && r.agenda.at <= Date.now()).length;
        }
        return json(out);
      }

      /* Carga de base (supervisor). Las filas llegan ya normalizadas y con la TC anterior enmascarada */
      case "upload": {
        need(user, "supervisor");
        const fuente = String(body.fuente || "").trim().slice(0, 80);
        const rows = Array.isArray(body.rows) ? body.rows : [];
        if (!fuente) fail("Falta el nombre de la fuente.");
        if (!rows.length) fail("El archivo no tiene filas para cargar.");
        const res = await mutate("records", REC_DEF, (db) => {
          const byDni = {};
          for (const r of Object.values(db.items)) if (r.dni) byDni[r.dni] = r;
          let nuevos = 0, actualizados = 0, omitidos = 0;
          for (const row of rows) {
            const dni = digits(row.dni);
            const nombre = String(row.nombre || "").trim().slice(0, 120);
            if (!dni && !nombre) { omitidos++; continue; }
            // Nunca aceptar un número de tarjeta completo en la base: se fuerza la máscara
            const tcA = String(row.tcAnterior || "").replace(/\d(?=\d{4})/g, (d, i) => (i < 6 ? d : "•")).slice(0, 30);
            const tels = (row.telefonos || []).map(digits).filter((t) => t.length >= 6 && t.length <= 15);
            const ex = dni && byDni[dni];
            if (ex) {
              for (const t of tels) if (!ex.telefonos.some((x) => x.n === t)) ex.telefonos.push({ n: t, origen: "base", at: Date.now() });
              ex.data = { ...ex.data, ...(row.data || {}) };
              if (row.notas && !String(ex.notas || "").includes(row.notas)) ex.notas = [ex.notas, row.notas].filter(Boolean).join(" | ");
              if (!ex.fuentes?.includes(fuente)) ex.fuentes = [...(ex.fuentes || [ex.fuente]), fuente];
              actualizados++;
              continue;
            }
            const id = String(++db.seq);
            const rec = {
              id, dni, nombre, fuente, fuentes: [fuente], cargado: Date.now(),
              telefonos: tels.map((n) => ({ n, origen: "base", at: Date.now() })),
              tcAnterior: tcA, notas: String(row.notas || "").slice(0, 2000), data: row.data || {},
              intentos: 0, sinContacto: 0, contactado: false, estado: "pendiente",
              franja: null, agenda: null, ultima: null, ultimaAt: null, lock: null, hist: [], tcCargada: false, tc: null, cobrado: false,
            };
            db.items[id] = rec;
            if (dni) byDni[dni] = rec;
            nuevos++;
          }
          return { nuevos, actualizados, omitidos };
        });
        await audit(user, "carga_base", `${fuente}: ${res.nuevos} nuevos, ${res.actualizados} actualizados`);
        return json(res);
      }

      /* Próximo registro de la cola */
      case "next": {
        need(user, "operador", "supervisor");
        checkQuincena(user, cfg);
        const fuente = body.fuente || "";
        const now = Date.now(), t0 = startOfDayAR();
        const rec = await mutate("records", REC_DEF, (db) => {
          const items = Object.values(db.items);
          // Si ya tiene uno tomado, se lo devuelve
          let mine = items.find((r) => r.estado !== "cerrado" && r.lock && r.lock.by === user.u && r.lock.until > now);
          if (mine) { mine.lock.until = now + cfg.lockMin * 60e3; return mine; }
          const cand = items.filter((r) => {
            if (r.estado === "cerrado" || lockedByOther(r, user)) return false;
            if (fuente && !(r.fuentes || [r.fuente]).includes(fuente)) return false;
            const due = r.agenda && r.agenda.at <= now;
            if (r.agenda && !due) return false;
            if (!due && r.ultimaAt && now - r.ultimaAt < cfg.minEntreIntentos * 60e3) return false;
            if (!due && r.hist.filter((h) => h.grupo !== "sistema" && h.at >= t0).length >= cfg.maxDiarios) return false;
            if (!r.telefonos.some((t) => !t.invalido)) return false;
            return true;
          });
          cand.sort((a, b) => {
            const da = a.agenda ? 0 : 1, dbb = b.agenda ? 0 : 1;
            if (da !== dbb) return da - dbb;
            if (a.agenda && b.agenda) return a.agenda.at - b.agenda.at;
            if (a.intentos !== b.intentos) return a.intentos - b.intentos;
            return (a.ultimaAt || 0) - (b.ultimaAt || 0) || +a.id - +b.id;
          });
          const r = cand[0];
          if (!r) return null;
          r.lock = { by: user.u, name: user.name, until: now + cfg.lockMin * 60e3 };
          return r;
        });
        return json({ record: rec });
      }

      /* Abrir un registro puntual (búsqueda o agenda) */
      case "abrir": {
        need(user, "operador", "supervisor");
        checkQuincena(user, cfg);
        const rec = await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          if (!r) fail("No existe el registro.", 404);
          if (r.estado === "cerrado" && user.role !== "supervisor") fail("Ese registro está cerrado. Pedile al supervisor que lo reabra.");
          if (lockedByOther(r, user)) fail(`Lo está gestionando ${r.lock.name}.`);
          for (const o of Object.values(db.items)) if (o.lock && o.lock.by === user.u && o.id !== r.id) o.lock = null;
          r.lock = { by: user.u, name: user.name, until: Date.now() + cfg.lockMin * 60e3 };
          return r;
        });
        return json({ record: rec });
      }

      case "liberar": {
        await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          if (!r) fail("No existe el registro.", 404);
          if (user.role !== "supervisor" && r.lock && r.lock.by !== user.u) fail("No podés liberar un registro de otro usuario.", 403);
          r.lock = null;
        });
        return json({ ok: true });
      }

      case "buscar": {
        need(user, "operador", "supervisor");
        const q = String(body.q || "").trim().toLowerCase();
        if (q.length < 3) fail("Escribí al menos 3 caracteres.");
        const qd = digits(q);
        const recs = await readJSON("records", REC_DEF);
        const res = Object.values(recs.items).filter((r) =>
          (qd.length >= 3 && (r.dni.includes(qd) || r.telefonos.some((t) => t.n.includes(qd)))) || r.nombre.toLowerCase().includes(q)
        ).slice(0, 15).map((r) => ({ id: r.id, nombre: r.nombre, dni: r.dni, estado: recState(r), ultima: r.ultima?.label || null, lock: r.lock && r.lock.until > Date.now() ? r.lock.name : null }));
        return json({ results: res });
      }

      /* Teléfonos: el operador agrega o marca como erróneo; queda guardado para el próximo contacto */
      case "telefono": {
        need(user, "operador", "supervisor");
        const n = digits(body.n);
        const rec = await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          if (!r) fail("No existe el registro.", 404);
          if (lockedByOther(r, user)) fail(`Lo está gestionando ${r.lock.name}.`);
          if (body.accion === "agregar") {
            if (n.length < 8 || n.length > 15) fail("El teléfono debe tener entre 8 y 15 dígitos (con característica).");
            if (r.telefonos.some((t) => t.n === n)) fail("Ese teléfono ya está cargado.");
            r.telefonos.push({ n, origen: "operador", by: user.name, at: Date.now(), nota: String(body.nota || "").slice(0, 60) });
          } else if (body.accion === "invalido") {
            const t = r.telefonos.find((x) => x.n === n);
            if (!t) fail("No se encontró ese teléfono.");
            t.invalido = !!body.valor;
          } else if (body.accion === "principal") {
            const i = r.telefonos.findIndex((x) => x.n === n);
            if (i > 0) r.telefonos.unshift(...r.telefonos.splice(i, 1));
          } else fail("Acción desconocida.");
          return r;
        });
        return json({ record: rec });
      }

      /* Tipificación */
      case "tipificar": {
        need(user, "operador", "supervisor");
        const def = findTip(body.grupo, body.k);
        if (!def) fail("Elegí una tipificación.");
        if (def.subs && !def.subs.includes(body.sub)) fail("Elegí el producto vendido.");
        let agendaAt = null;
        if (def.agenda) {
          agendaAt = body.agendaAt ? Date.parse(body.agendaAt) : null;
          if (def.agenda === "requerida" && !agendaAt) fail("Indicá fecha y hora para volver a llamar.");
          if (agendaAt && agendaAt < Date.now() - 5 * 60e3) fail("La fecha de rellamado ya pasó.");
          if (agendaAt && !enHorario(cfg, agendaAt)) fail(`El rellamado tiene que quedar dentro del horario de gestión (${cfg.horaInicio} a ${cfg.horaFin} hs).`);
        }
        const rec = await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          if (!r) fail("No existe el registro.", 404);
          if (r.estado === "cerrado" && user.role !== "supervisor") fail("El registro ya está cerrado.");
          if (lockedByOther(r, user)) fail(`Lo está gestionando ${r.lock.name}.`);
          if (def.venta && !r.tcCargada) fail("Para tipificar Venta primero guardá los datos de la tarjeta nueva.");
          const tel = digits(body.tel) || r.telefonos.find((t) => !t.invalido)?.n || "";
          const now = Date.now();
          r.intentos++;
          if (body.grupo === "no_efectivo") r.sinContacto++; else r.contactado = true;
          r.franja = def.franja || null;
          r.agenda = agendaAt ? { at: agendaAt, by: user.name, nota: String(body.obs || "").slice(0, 200) } : null;
          let cierre = null;
          if (def.k === "datos_erroneos") {
            const t = r.telefonos.find((x) => x.n === tel);
            if (t) t.invalido = true;
            if (!r.telefonos.some((x) => !x.invalido)) cierre = "Sin teléfonos válidos";
          }
          if (def.cierra) cierre = def.label;
          if (!cierre && body.grupo === "no_efectivo" && r.sinContacto >= cfg.maxIntentos) cierre = "Tope de intentos sin contacto";
          r.estado = cierre ? "cerrado" : "en_curso";
          r.motivoCierre = cierre;
          if (cierre) r.agenda = null;
          r.ultima = { grupo: body.grupo, k: def.k, label: def.label, sub: body.sub || null, at: now, by: user.name };
          r.ultimaAt = now;
          r.hist.push({
            at: now, by: user.u, byName: user.name, grupo: body.grupo, k: def.k, label: def.label,
            sub: body.sub || null, obs: String(body.obs || "").slice(0, 1000), tel, q: quincenaNow(),
            intento: r.intentos, cierre,
          });
          r.lock = null;
          return r;
        });
        return json({ record: rec });
      }

      /* Tarjeta nueva: se guarda cifrada. El operador no la puede volver a ver ni editar */
      case "tc": {
        need(user, "operador", "supervisor");
        const tc = validarTC(body);
        const recs = await readJSON("records", REC_DEF);
        const r0 = recs.items[body.id];
        if (!r0) fail("No existe el registro.", 404);
        if (r0.tcCargada && user.role !== "supervisor") fail("La tarjeta ya fue cargada y quedó bloqueada. Si hay un error, avisale al supervisor.", 403);
        if (lockedByOther(r0, user)) fail(`Lo está gestionando ${r0.lock.name}.`);
        await store().setJSON(`tc/${body.id}`, { ...encrypt(tc), by: user.u, at: Date.now() });
        const rec = await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          r.tcCargada = true;
          r.tc = { last4: tc.numero.slice(-4), marca: tc.marca, banco: tc.banco, vto: tc.vto, by: user.name, at: Date.now() };
          return r;
        });
        await audit(user, r0.tcCargada ? "tc_reemplazo" : "tc_carga", `registro ${body.id} (${r0.nombre})`);
        return json({ record: rec });
      }

      case "tc-reveal": {
        need(user, "supervisor");
        const e = await readJSON(`tc/${body.id}`, null);
        if (!e) fail("Ese registro no tiene tarjeta cargada.", 404);
        await audit(user, "tc_ver", `registro ${body.id}`);
        return json({ tc: decrypt(e) });
      }

      case "ventas-tc": {
        need(user, "supervisor");
        const recs = await readJSON("records", REC_DEF);
        const out = [];
        for (const r of Object.values(recs.items)) {
          if (!r.tcCargada) continue;
          const e = await readJSON(`tc/${r.id}`, null);
          if (!e) continue;
          const tc = decrypt(e);
          out.push({
            id: r.id, dni: r.dni, nombre: r.nombre, fuente: r.fuente, ultima: r.ultima?.label || "", producto: r.ultima?.sub || "",
            fecha: r.ultima?.at || r.tc?.at, operador: r.tc?.by || "", ...tc,
          });
        }
        await audit(user, "tc_export", `${out.length} tarjetas`);
        return json({ items: out });
      }

      /* Listado completo (supervisor / cliente) */
      case "records": {
        need(user, "supervisor", "cliente");
        const recs = await readJSON("records", REC_DEF);
        return json({ items: Object.values(recs.items) });
      }

      case "agenda": {
        const recs = await readJSON("records", REC_DEF);
        const items = Object.values(recs.items).filter((r) => r.estado !== "cerrado" && r.agenda)
          .sort((a, b) => a.agenda.at - b.agenda.at)
          .map((r) => ({ id: r.id, nombre: r.nombre, dni: r.dni, agenda: r.agenda, ultima: r.ultima?.label, lock: r.lock && r.lock.until > Date.now() ? r.lock.name : null }));
        return json({ items });
      }

      case "reabrir": {
        need(user, "supervisor");
        await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          if (!r) fail("No existe el registro.", 404);
          r.estado = r.intentos ? "en_curso" : "pendiente";
          r.motivoCierre = null; r.sinContacto = 0; r.lock = null;
          r.hist.push({ at: Date.now(), by: user.u, byName: user.name, grupo: "sistema", k: "reabierto", label: "Reabierto por supervisor", obs: String(body.obs || "") });
        });
        await audit(user, "reabrir", `registro ${body.id}`);
        return json({ ok: true });
      }

      case "marcar-cobrado": {
        need(user, "supervisor");
        await mutate("records", REC_DEF, (db) => {
          const r = db.items[body.id];
          if (!r) fail("No existe el registro.", 404);
          r.cobrado = Boolean(body.cobrado);
          r.hist.push({ at: Date.now(), by: user.u, byName: user.name, grupo: "sistema", k: "cobrado", label: r.cobrado ? "Marcado como cobrado" : "Desmarcado como cobrado" });
        });
        await audit(user, "marcar-cobrado", `registro ${body.id}: ${body.cobrado ? "cobrado" : "no cobrado"}`);
        return json({ ok: true });
      }

      case "users": {
        need(user, "supervisor");
        if (req.method === "GET") return json({ users: (await getUsers()).users.map(publicUser) });
        const u = String(body.u || "").trim().toLowerCase();
        if (!/^[a-z0-9._-]{3,30}$/.test(u)) fail("El usuario usa de 3 a 30 letras, números, punto o guion, sin espacios.");
        if (!["operador", "supervisor", "cliente"].includes(body.role)) fail("Rol inválido.");
        await mutate("users", { users: [] }, (d) => {
          let x = d.users.find((y) => y.u === u);
          if (!x) {
            if (!body.p || String(body.p).length < 6) fail("Para un usuario nuevo definí una contraseña de al menos 6 caracteres.");
            x = { u }; d.users.push(x);
          }
          x.name = String(body.name || u).slice(0, 60);
          x.role = body.role;
          x.quincena = body.role === "operador" ? ([1, 2].includes(+body.quincena) ? +body.quincena : null) : null;
          x.activo = body.activo !== false;
          if (body.p) { if (String(body.p).length < 6) fail("La contraseña necesita al menos 6 caracteres."); Object.assign(x, hashP(body.p)); }
          if (!d.users.some((y) => y.role === "supervisor" && y.activo !== false)) fail("Tiene que quedar al menos un supervisor activo.");
        });
        await audit(user, "usuario", u);
        return json({ ok: true });
      }

      case "config": {
        need(user, "supervisor");
        const n = {
          campaign: String(body.campaign || DEF_CONFIG.campaign).slice(0, 100),
          maxIntentos: Math.max(1, Math.min(20, +body.maxIntentos || 5)),
          quincenaEstricta: !!body.quincenaEstricta,
          minEntreIntentos: Math.max(0, Math.min(1440, +body.minEntreIntentos || 0)),
          lockMin: Math.max(5, Math.min(120, +body.lockMin || 15)),
          horaInicio: Math.max(0, Math.min(23, +body.horaInicio || 9)),
          horaFin: Math.max(1, Math.min(24, +body.horaFin || 13)),
          maxDiarios: Math.max(1, Math.min(10, +body.maxDiarios || 2)),
        };
        if (n.horaFin <= n.horaInicio) fail("La hora de fin tiene que ser posterior a la de inicio.");
        await store().setJSON("config", n);
        await audit(user, "config", JSON.stringify(n));
        return json({ config: n });
      }

      case "audit": {
        need(user, "supervisor");
        const a = await readJSON("audit", { items: [] });
        return json({ items: a.items.slice(-500).reverse() });
      }

      case "reset": {
        need(user, "supervisor");
        if (body.confirmar !== "BORRAR") fail("Escribí BORRAR para confirmar.");
        const st = store();
        const { blobs } = await st.list({ prefix: "tc/" });
        for (const b of blobs) await st.delete(b.key);
        await st.setJSON("records", REC_DEF);
        await audit(user, "reset", "base y tarjetas borradas");
        return json({ ok: true });
      }

      default:
        fail("Ruta inexistente.", 404);
    }
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: "Error interno: " + (e.message || e) }, 500);
  }
};
