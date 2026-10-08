import { hex, sha256Bytes } from "./merkle.js";

const encoder = new TextEncoder();
const EM_DASH = "\u2014";
const MAX_SIGNATURES = 32;

export const TYP_ED25519 = 0x01;
export const TYP_KOSIGNATUR = 0x04;

export function base64Encode(bytes) {
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text);
}

export function base64Decode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) throw new Error("Ungültiges Base64.");
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  if (base64Encode(out) !== text) throw new Error("Base64 ist nicht kanonisch.");
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function schluesselKennung(name, typ, publicKey) {
  const hash = await sha256Bytes(concat(encoder.encode(name), Uint8Array.of(0x0a, typ), publicKey));
  return hash.slice(0, 4);
}

export async function schluesselText(name, typ, publicKey) {
  const kennung = await schluesselKennung(name, typ, publicKey);
  return `${name}+${hex(kennung)}+${base64Encode(concat(Uint8Array.of(typ), publicKey))}`;
}

export async function schluesselLesen(text) {
  if (typeof text !== "string") throw new Error("Schlüssel fehlt.");
  const roh = text.trim();
  const erstes = roh.indexOf("+");
  const zweites = erstes < 0 ? -1 : roh.indexOf("+", erstes + 1);
  if (erstes < 1 || zweites < 0) throw new Error("Schlüssel hat nicht die Form Name+Kennung+Daten.");
  const name = roh.slice(0, erstes);
  const kennungHex = roh.slice(erstes + 1, zweites);
  const daten = roh.slice(zweites + 1);
  if (!name || /\s/.test(name)) throw new Error("Ungültiger Schlüsselname.");
  const bytes = base64Decode(daten);
  if (bytes.length !== 33) throw new Error("Nur Ed25519-Schlüssel werden unterstützt.");
  const typ = bytes[0];
  if (typ !== TYP_ED25519 && typ !== TYP_KOSIGNATUR) throw new Error("Unbekannter Signaturtyp.");
  const publicKey = bytes.slice(1);
  const erwartet = hex(await schluesselKennung(name, typ, publicKey));
  if (erwartet !== kennungHex) throw new Error("Die Kennung passt nicht zum Schlüssel.");
  return { name, typ, publicKey, kennung: erwartet };
}

export function notizLesen(text) {
  if (typeof text !== "string" || text.length > 200000) throw new Error("Ungültige Notiz.");
  const trennung = text.lastIndexOf("\n\n");
  if (trennung < 0) throw new Error("Notiz hat keinen Signaturteil.");
  const koerper = text.slice(0, trennung + 1);
  const rest = text.slice(trennung + 2);
  if (!rest.endsWith("\n")) throw new Error("Signaturzeilen müssen mit Zeilenumbruch enden.");
  for (const ch of koerper) {
    const code = ch.codePointAt(0);
    if (code < 0x20 && code !== 0x0a) throw new Error("Steuerzeichen im Text.");
  }
  const zeilen = rest.slice(0, -1).split("\n");
  if (zeilen.length === 0 || zeilen.length > MAX_SIGNATURES) throw new Error("Anzahl der Signaturen ungültig.");
  const signaturen = zeilen.map((zeile) => {
    if (!zeile.startsWith(`${EM_DASH} `)) throw new Error("Signaturzeile beginnt nicht mit dem Gedankenstrich.");
    const teile = zeile.slice(2).split(" ");
    if (teile.length !== 2) throw new Error("Signaturzeile ist ungültig.");
    const blob = base64Decode(teile[1]);
    if (blob.length < 5) throw new Error("Signatur zu kurz.");
    return { name: teile[0], kennung: hex(blob.slice(0, 4)), wert: blob.slice(4) };
  });
  return { koerper, signaturen };
}

export function pruefpunktLesen(koerper) {
  if (!koerper.endsWith("\n")) throw new Error("Prüfpunkt endet nicht mit Zeilenumbruch.");
  const zeilen = koerper.slice(0, -1).split("\n");
  if (zeilen.length < 3 || zeilen.some((z) => z.length === 0)) throw new Error("Prüfpunkt hat weniger als drei Zeilen.");
  const [origin, groesseText, wurzelText, ...erweiterungen] = zeilen;
  if (!/^(0|[1-9][0-9]*)$/.test(groesseText)) throw new Error("Baumgröße ist keine Dezimalzahl.");
  const groesse = Number(groesseText);
  if (!Number.isSafeInteger(groesse)) throw new Error("Baumgröße zu groß.");
  const wurzel = base64Decode(wurzelText);
  if (wurzel.length !== 32) throw new Error("Wurzel hat nicht 32 Byte.");
  return { origin, groesse, wurzelHex: hex(wurzel), erweiterungen };
}

export function pruefpunktText({ origin, groesse, wurzelHex, erweiterungen = [] }) {
  const wurzel = new Uint8Array(wurzelHex.match(/../g).map((h) => parseInt(h, 16)));
  return `${origin}\n${groesse}\n${base64Encode(wurzel)}\n${erweiterungen.map((e) => `${e}\n`).join("")}`;
}

async function ed25519Pruefen(publicKey, nachricht, signatur) {
  try {
    const key = await globalThis.crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, signatur, nachricht);
  } catch {
    return false;
  }
}

export async function signaturenPruefen(notiz, vertraute) {
  const bekannt = new Map(vertraute.map((v) => [`${v.name}|${v.kennung}`, v]));
  const gueltig = [];
  const fehlerhaft = [];
  const gesehen = new Set();
  for (const s of notiz.signaturen) {
    const schluessel = bekannt.get(`${s.name}|${s.kennung}`);
    if (!schluessel) continue;
    const eindeutig = `${s.name}|${s.kennung}`;
    if (gesehen.has(eindeutig)) {
      fehlerhaft.push({ name: s.name, grund: "doppelte Signatur desselben Schlüssels" });
      continue;
    }
    gesehen.add(eindeutig);
    if (schluessel.typ === TYP_ED25519) {
      const nachricht = encoder.encode(notiz.koerper);
      const ok = s.wert.length === 64 && (await ed25519Pruefen(schluessel.publicKey, nachricht, s.wert));
      if (ok) gueltig.push({ name: s.name, typ: schluessel.typ });
      else fehlerhaft.push({ name: s.name, grund: "Signatur ungültig" });
    } else if (schluessel.typ === TYP_KOSIGNATUR) {
      if (s.wert.length !== 72) {
        fehlerhaft.push({ name: s.name, grund: "Signaturlänge ungültig" });
        continue;
      }
      const zeit = new DataView(s.wert.buffer, s.wert.byteOffset, 8).getBigUint64(0, false);
      const nachricht = encoder.encode(`cosignature/v1\ntime ${zeit}\n${notiz.koerper}`);
      const ok = await ed25519Pruefen(schluessel.publicKey, nachricht, s.wert.slice(8));
      if (ok) gueltig.push({ name: s.name, typ: schluessel.typ, zeit: Number(zeit) });
      else fehlerhaft.push({ name: s.name, grund: "Signatur ungültig" });
    }
  }
  return { gueltig, fehlerhaft };
}
