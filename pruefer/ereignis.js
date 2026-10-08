import { hex, unhex, sha256Bytes, leafHashOfData, rootOfLeaves, hashChildren, emptyRoot } from "./merkle.js";

const encoder = new TextEncoder();

export const FELDNAME = /^[A-Za-z0-9_]{1,64}$/;
export const SALZ = /^[A-Za-z0-9_-]{16,64}$/;
export const KOPFFELDER = ["seq", "type", "at", "hv", "prevHash", "feldWurzel"];
const RESERVIERT = new Set([...KOPFFELDER, "hash", "salze"]);
const MAX_FELDER = 4096;

export function canonicalJson(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

export async function sha256Hex(text) {
  return hex(await sha256Bytes(text));
}

export function inhaltsnamen(ereignis) {
  return Object.keys(ereignis).filter((k) => !RESERVIERT.has(k)).sort();
}

export async function feldBlatt(name, salz, wert) {
  return leafHashOfData(encoder.encode(canonicalJson({ n: name, s: salz, w: wert })));
}

export async function feldWurzelBerechnen(ereignis) {
  const namen = inhaltsnamen(ereignis);
  if (namen.length > MAX_FELDER) throw new Error("Zu viele Felder.");
  const salze = ereignis.salze;
  if (!salze || typeof salze !== "object" || Array.isArray(salze)) throw new Error("Die Salze fehlen.");
  const salzNamen = Object.keys(salze).sort();
  if (salzNamen.length !== namen.length || salzNamen.some((n, i) => n !== namen[i])) throw new Error("Die Salze passen nicht zu den Feldern.");
  const blaetter = [];
  for (const name of namen) {
    if (!FELDNAME.test(name)) throw new Error(`Ungültiger Feldname ${name}.`);
    if (typeof salze[name] !== "string" || !SALZ.test(salze[name])) throw new Error(`Ungültiges Salz für ${name}.`);
    blaetter.push(await feldBlatt(name, salze[name], ereignis[name]));
  }
  return hex(await rootOfLeaves(blaetter));
}

export async function kopfHash(vorgaenger, kopf) {
  return sha256Hex(vorgaenger + canonicalJson(kopf));
}

export function kopfVon(ereignis) {
  return { seq: ereignis.seq, type: ereignis.type, at: ereignis.at, hv: 2, prevHash: ereignis.prevHash, feldWurzel: ereignis.feldWurzel };
}

export async function ereignisHashBerechnen(ereignis) {
  if (!ereignis || typeof ereignis !== "object" || Array.isArray(ereignis)) throw new Error("Kein Ereignis.");
  const { hash, ...basis } = ereignis;
  if (basis.hv === undefined) return sha256Hex(basis.prevHash + JSON.stringify(basis));
  if (basis.hv !== 2) throw new Error("Unbekannte Hashversion.");
  if (typeof basis.feldWurzel !== "string" || !/^[0-9a-f]{64}$/.test(basis.feldWurzel)) throw new Error("Die Feldwurzel fehlt.");
  const wurzel = await feldWurzelBerechnen(basis);
  if (wurzel !== basis.feldWurzel) throw new Error("Die Feldwurzel passt nicht zu den Feldern.");
  return kopfHash(basis.prevHash, kopfVon(basis));
}

export async function ereignisHashPruefen(ereignis) {
  try {
    const berechnet = await ereignisHashBerechnen(ereignis);
    return { ok: berechnet === ereignis.hash, version: ereignis.hv === 2 ? 2 : 1, grund: berechnet === ereignis.hash ? "" : "Die Prüfsumme weicht ab." };
  } catch (err) {
    return { ok: false, version: ereignis?.hv === 2 ? 2 : 1, grund: String(err?.message ?? err) };
  }
}

export async function auszugPruefen(auszug) {
  try {
    if (!auszug || auszug.schema !== "defconder-auszug-1") throw new Error("Unbekanntes Format.");
    const k = auszug.kopf;
    if (!k || typeof k !== "object") throw new Error("Der Kopf fehlt.");
    if (k.hv !== 2 || !Number.isInteger(k.seq) || typeof k.type !== "string" || !Number.isFinite(k.at) || typeof k.prevHash !== "string" || typeof k.hash !== "string") throw new Error("Der Kopf ist unvollständig.");
    if (!Array.isArray(auszug.blaetter) || auszug.blaetter.length > MAX_FELDER) throw new Error("Die Blätter fehlen oder sind zu viele.");
    const blaetter = [];
    const offene = [];
    let letzter = null;
    for (const b of auszug.blaetter) {
      if (!b || typeof b !== "object") throw new Error("Ein Blatt ist ungültig.");
      if (typeof b.h === "string") {
        if (!/^[0-9a-f]{64}$/.test(b.h)) throw new Error("Eine verdeckte Blattprüfsumme ist ungültig.");
        blaetter.push(unhex(b.h));
        continue;
      }
      if (typeof b.n !== "string" || !FELDNAME.test(b.n) || RESERVIERT.has(b.n)) throw new Error("Ein offener Feldname ist ungültig.");
      if (typeof b.s !== "string" || !SALZ.test(b.s)) throw new Error("Ein Salz ist ungültig.");
      if (!("w" in b)) throw new Error("Ein offenes Feld hat keinen Wert.");
      if (letzter !== null && !(b.n > letzter)) throw new Error("Offene Felder sind nicht eindeutig sortiert.");
      letzter = b.n;
      blaetter.push(await feldBlatt(b.n, b.s, b.w));
      offene.push({ name: b.n, wert: b.w });
    }
    const wurzel = hex(await rootOfLeaves(blaetter));
    if (wurzel !== k.feldWurzel) throw new Error("Die Feldwurzel passt nicht zu den Blättern.");
    const hash = await kopfHash(k.prevHash, { seq: k.seq, type: k.type, at: k.at, hv: 2, prevHash: k.prevHash, feldWurzel: k.feldWurzel });
    if (hash !== k.hash) throw new Error("Die Prüfsumme des Ereignisses passt nicht zum Kopf.");
    return { ok: true, hash, seq: k.seq, type: k.type, offene, verdeckt: blaetter.length - offene.length };
  } catch (err) {
    return { ok: false, grund: String(err?.message ?? err) };
  }
}

export { emptyRoot, hashChildren };
