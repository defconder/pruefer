import { hex, unhex, sha256Bytes } from "./merkle.js";
import { notizLesen, base64Decode } from "./note.js";
import { ripemd160 } from "./ripemd160.js";
import { bitcoinKopfPruefen, STANDARD_MINDESTARBEIT_BITS } from "./zeitanker.js";
import { pruefpunktPruefen } from "./pruefer-kern.js";
import { stufeBestimmen } from "./aussage.js";

export const ZEITBEWEIS_SCHEMA = "defconder-zeitbeweis-1";

const encoder = new TextEncoder();
const MAGIE = Uint8Array.from([0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
const BITCOIN_TAG = "0588960d73d71901";
const AUSSTEHEND_TAG = "83dfe30d2ef90c8e";
const MAX_NACHRICHT = 4096;
const MAX_KNOTEN = 20000;
const MAX_TIEFE = 256;
const MAX_DATEI = 1000000;
const ZWEI_STUNDEN_MS = 2 * 60 * 60 * 1000;

class Leser {
  constructor(bytes) {
    this.b = bytes;
    this.pos = 0;
  }

  byte() {
    if (this.pos >= this.b.length) throw new Error("Die Datei endet zu früh.");
    return this.b[this.pos++];
  }

  bytes(n) {
    if (!Number.isInteger(n) || n < 0 || this.pos + n > this.b.length) throw new Error("Die Datei endet zu früh.");
    const out = this.b.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  varuint() {
    let wert = 0;
    for (let i = 0; i < 5; i += 1) {
      const x = this.byte();
      wert += (x & 0x7f) * 2 ** (7 * i);
      if ((x & 0x80) === 0) return wert;
    }
    throw new Error("Eine Längenangabe ist zu groß.");
  }

  varbytes(max, min = 0) {
    const n = this.varuint();
    if (n > max || n < min) throw new Error("Eine Längenangabe liegt außerhalb des erlaubten Bereichs.");
    return this.bytes(n);
  }

  ende() {
    return this.pos === this.b.length;
  }
}

function verbinden(...teile) {
  const out = new Uint8Array(teile.reduce((n, t) => n + t.length, 0));
  let o = 0;
  for (const t of teile) {
    out.set(t, o);
    o += t.length;
  }
  return out;
}

async function zweig(l, nachricht, tag, tiefe, attest, zaehler) {
  zaehler.knoten += 1;
  if (zaehler.knoten > MAX_KNOTEN) throw new Error("Der Beweis hat zu viele Knoten.");
  if (tag === 0x00) {
    const art = hex(l.bytes(8));
    const nutzlast = l.varbytes(MAX_NACHRICHT);
    if (art === BITCOIN_TAG) {
      const inneres = new Leser(nutzlast);
      const hoehe = inneres.varuint();
      if (!inneres.ende()) throw new Error("Die Bestätigung durch Bitcoin hat überzählige Bytes.");
      attest.push({ art: "bitcoin", hoehe, nachricht });
    } else if (art === AUSSTEHEND_TAG) attest.push({ art: "ausstehend" });
    else attest.push({ art: "unbekannt", tag: art });
    return;
  }
  let neu;
  if (tag === 0x08) neu = await sha256Bytes(nachricht);
  else if (tag === 0x03) neu = ripemd160(nachricht);
  else if (tag === 0xf0) neu = verbinden(nachricht, l.varbytes(MAX_NACHRICHT, 1));
  else if (tag === 0xf1) neu = verbinden(l.varbytes(MAX_NACHRICHT, 1), nachricht);
  else if (tag === 0xf2) neu = Uint8Array.from(nachricht).reverse();
  else if (tag === 0xf3) neu = encoder.encode(hex(nachricht));
  else if (tag === 0x02 || tag === 0x67) throw new Error(`Die Operation ${tag === 0x02 ? "SHA-1" : "Keccak-256"} wird nicht unterstützt.`);
  else throw new Error(`Unbekannte Operation ${tag.toString(16)}.`);
  if (neu.length > MAX_NACHRICHT || neu.length === 0) throw new Error("Eine Zwischennachricht ist zu lang.");
  await baum(l, neu, tiefe + 1, attest, zaehler);
}

async function baum(l, nachricht, tiefe, attest, zaehler) {
  if (tiefe > MAX_TIEFE) throw new Error("Der Beweis ist zu tief verschachtelt.");
  let tag = l.byte();
  while (tag === 0xff) {
    await zweig(l, nachricht, l.byte(), tiefe, attest, zaehler);
    tag = l.byte();
  }
  await zweig(l, nachricht, tag, tiefe, attest, zaehler);
}

export async function otsAuswerten(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_DATEI) throw new Error("Der Beweis ist zu groß oder kein Byte-Feld.");
  const l = new Leser(bytes);
  const kopf = l.bytes(MAGIE.length);
  for (let i = 0; i < MAGIE.length; i += 1) if (kopf[i] !== MAGIE[i]) throw new Error("Das ist keine OpenTimestamps-Datei.");
  if (l.varuint() !== 1) throw new Error("Unbekannte Hauptversion des Beweises.");
  if (l.byte() !== 0x08) throw new Error("Der Beweis beginnt nicht mit einer SHA-256-Prüfsumme.");
  const digest = l.bytes(32);
  const attest = [];
  await baum(l, digest, 0, attest, { knoten: 0 });
  if (!l.ende()) throw new Error("Nach dem Beweis folgen weitere Daten.");
  return { digest, attestierungen: attest };
}

export function merkleWurzelAusKopf(kopfHex) {
  return unhex(kopfHex).slice(36, 68);
}

function gleich(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export async function zeitbeweisPruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form des Zeitbeweises", false, text);
    return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht prüfbar", spaetestens: null, fruehestens: null };
  };
  try {
    if (!doc || doc.schema !== ZEITBEWEIS_SCHEMA) return abbruch("Unbekanntes Format.");
    if (typeof doc.notiz !== "string" || typeof doc.ots !== "string" || typeof doc.koepfe !== "object" || doc.koepfe === null || Array.isArray(doc.koepfe)) return abbruch("Prüfpunkt, Beweis oder Blockköpfe fehlen.");
    const festgelegt = Boolean(opts.logSchluessel);
    const logSchluessel = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof logSchluessel !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const punktErgebnis = await pruefpunktPruefen(doc.notiz, { ...opts, logSchluessel });
    for (const c of punktErgebnis.checks) add(`punkt_${c.id}`, c.label, c.ok, c.detail);
    if (!punktErgebnis.punkt) return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", spaetestens: null, fruehestens: null };

    const notiz = notizLesen(doc.notiz);
    const digest = await sha256Bytes(encoder.encode(notiz.koerper));
    let ots;
    try {
      ots = await otsAuswerten(base64Decode(doc.ots));
    } catch (err) {
      add("ots", "Der Zeitbeweis ist eine lesbare OpenTimestamps-Datei", false, String(err.message ?? err));
      return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", spaetestens: null, fruehestens: null, punkt: punktErgebnis.punkt };
    }
    add("ots", `Der Zeitbeweis ist lesbar und enthält ${ots.attestierungen.length} Bestätigung${ots.attestierungen.length === 1 ? "" : "en"}`, true);
    add("digest", "Der Zeitbeweis bezieht sich genau auf den signierten Text des Prüfpunkts", gleich(ots.digest, digest), `SHA-256 des Prüfpunkttextes ${hex(digest).slice(0, 16)}…`);

    let bester = null;
    let ausstehend = 0;
    for (const a of ots.attestierungen) {
      if (a.art === "ausstehend") {
        ausstehend += 1;
        continue;
      }
      if (a.art !== "bitcoin") continue;
      const kopfHex = doc.koepfe[String(a.hoehe)];
      if (typeof kopfHex !== "string") {
        add("bitcoin", `Bestätigung durch Bitcoin-Block ${a.hoehe}`, false, "Der Blockkopf zu dieser Höhe liegt dem Dokument nicht bei.");
        continue;
      }
      const kopf = await bitcoinKopfPruefen(kopfHex, { mindestArbeitBits: opts.mindestArbeitBits ?? STANDARD_MINDESTARBEIT_BITS });
      if (!kopf.blockHash) {
        add("bitcoin", `Blockkopf zu Höhe ${a.hoehe} ist gültig`, false, kopf.grund);
        continue;
      }
      const wurzelOk = gleich(merkleWurzelAusKopf(kopfHex), a.nachricht);
      const gueltig = kopf.ok && wurzelOk;
      add("bitcoin", `Der Prüfpunkt steckt im Bitcoin-Block ${kopf.blockHash.slice(0, 16)}… (Höhe ${a.hoehe}, Blockzeit ${new Date(kopf.blockZeit).toISOString()})`, gueltig, gueltig ? `Rechenarbeit des Blocks rund 2^${kopf.arbeitBits}. Vergleichen Sie die Blockprüfsumme mit einer Blockübersicht Ihrer Wahl.` : !kopf.ok ? kopf.grund : "Die Wurzel der Transaktionen im Blockkopf passt nicht zum Ergebnis des Beweises.");
      if (gueltig && (!bester || kopf.blockZeit < bester.blockZeit)) bester = { hoehe: a.hoehe, blockHash: kopf.blockHash, blockZeit: kopf.blockZeit };
    }
    if (!bester) add("bestaetigung", "Mindestens eine gültige Bestätigung durch Bitcoin", false, ausstehend > 0 ? "Der Beweis ist noch nicht in einem Block bestätigt (ausstehend). Er muss aufgerüstet werden, wenn die Kalenderserver die Bestätigung geliefert haben." : "Keine Bestätigung gefunden.");

    const spaetestens = bester ? bester.blockZeit + ZWEI_STUNDEN_MS : null;
    const fruehestens = punktErgebnis.zeitanker?.fruehestens ?? null;
    if (spaetestens !== null && fruehestens !== null) add("korridor", `Der Prüfpunkt entstand frühestens ${new Date(fruehestens).toISOString()} und bestand spätestens ${new Date(spaetestens).toISOString()}`, fruehestens <= spaetestens, fruehestens <= spaetestens ? "" : "Die Untergrenze liegt nach der Obergrenze, die Zeitangaben widersprechen sich.");

    warnungen.push("Blockzeiten sind nur auf etwa zwei Stunden genau. Der Prüfer rechnet vorsichtig mit der Blockzeit plus zwei Stunden als spätestem Zeitpunkt. Das stützt sich auf die übliche Annahme, dass die Mehrheit der Miner richtige Uhren hat.");
    warnungen.push("Der Beweis zeigt, dass der Prüfpunkt bis zu diesem Zeitpunkt bestand. Er zeigt nicht, dass sein Inhalt wahr ist.");
    if (!festgelegt) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Der Zeitbeweis zeigt nur, wann dieser Text bestand, nicht, wer ihn erzeugt hat.");
    const intern = checks.every((c) => c.ok);
    const { stufe, stufeText } = stufeBestimmen(intern, festgelegt, punktErgebnis);
    if (intern && Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    const ok = checks.every((c) => c.ok);
    return { ok, checks, warnungen, stufe, stufeText: ok ? stufeText : "Nicht bestanden", spaetestens, fruehestens, bitcoin: bester, pq: punktErgebnis.pq, punkt: punktErgebnis.punkt };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}
