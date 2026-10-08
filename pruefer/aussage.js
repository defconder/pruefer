import { hex, unhex, sha256Bytes, leafHashOfData, rootOfLeaves, verifyInclusion, verifyInclusionOfLeaf, MAX_BAUMGROESSE } from "./merkle.js";
import { notizLesen, pruefpunktLesen, base64Decode, base64Encode } from "./note.js";
import { pruefpunktPruefen } from "./pruefer-kern.js";

const encoder = new TextEncoder();

export const INDEXREGELN = "indexregeln-1";
export const INDEXZEILE = "defconder-index-1";
export const SCHLUESSELFELDER = ["id", "recordId", "userId", "actorId", "createdBy", "executedBy", "publishedBy", "deletedBy", "uploadedBy", "approvedBy", "sha256", "assetId", "entityTypeId", "actionTypeId", "objectId", "username", "purposeId", "apiKeyId"];
const MAX_WERT = 200;
const MAX_SCHLUESSEL = 400;
const MAX_EREIGNISSE_IN_AUSSAGE = 100000;
const NULL32 = new Uint8Array(32);
const EINS32 = new Uint8Array(32).fill(255);

export function schluesselVon(ereignis) {
  const menge = new Set();
  if (typeof ereignis.type === "string") menge.add(`typ=${ereignis.type}`);
  for (const feld of SCHLUESSELFELDER) {
    const wert = ereignis[feld];
    if (typeof wert === "string" && wert.length >= 1 && wert.length <= MAX_WERT) {
      menge.add(`${feld}=${wert}`);
      menge.add(`${ereignis.type}|${feld}=${wert}`);
    }
  }
  return [...menge];
}

function verbinden(...teile) {
  const out = new Uint8Array(teile.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of teile) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function schluesselHash(schluessel) {
  return sha256Bytes(encoder.encode(`${INDEXREGELN}\n${schluessel}`));
}

export function anzahlBytes(anzahl) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(anzahl), false);
  return out;
}

export function blattDaten(schluesselHashBytes, anzahl, kette) {
  return verbinden(schluesselHashBytes, anzahlBytes(anzahl), kette);
}

export async function kettePlus(kette, ereignisHashHex) {
  return sha256Bytes(verbinden(kette, unhex(ereignisHashHex)));
}

export async function kettenWert(ereignisHashes) {
  let kette = NULL32;
  for (const h of ereignisHashes) kette = await kettePlus(kette, h);
  return kette;
}

export async function indexAufbauen(ereignisse) {
  const tabelle = new Map();
  for (const e of ereignisse) {
    for (const schluessel of schluesselVon(e)) {
      const eintrag = tabelle.get(schluessel) ?? { anzahl: 0, kette: NULL32, hashes: [] };
      eintrag.kette = await kettePlus(eintrag.kette, e.hash);
      eintrag.anzahl += 1;
      eintrag.hashes.push(e.hash);
      tabelle.set(schluessel, eintrag);
    }
  }
  const zeilen = [];
  for (const [schluessel, eintrag] of tabelle) zeilen.push({ schluessel, keyHash: await schluesselHash(schluessel), ...eintrag });
  zeilen.push({ schluessel: null, keyHash: NULL32, anzahl: 0, kette: NULL32, hashes: [] });
  zeilen.push({ schluessel: null, keyHash: EINS32, anzahl: 0, kette: NULL32, hashes: [] });
  zeilen.sort((a, b) => (hex(a.keyHash) < hex(b.keyHash) ? -1 : hex(a.keyHash) > hex(b.keyHash) ? 1 : 0));
  const blaetter = [];
  for (const z of zeilen) blaetter.push(await leafHashOfData(blattDaten(z.keyHash, z.anzahl, z.kette)));
  const wurzel = hex(await rootOfLeaves(blaetter));
  return { zeilen, blaetter, wurzel, anzahl: zeilen.length, tabelle };
}

export function indexZeile(anzahl, wurzelHex) {
  return `${INDEXZEILE} ${anzahl} ${base64Encode(unhex(wurzelHex))}`;
}

export function indexZeileLesen(erweiterungen) {
  const zeilen = (erweiterungen ?? []).filter((z) => z.startsWith(`${INDEXZEILE} `));
  if (zeilen.length !== 1) throw new Error(zeilen.length === 0 ? "Der Prüfpunkt enthält keine Indexzeile." : "Der Prüfpunkt enthält mehrere Indexzeilen.");
  const teile = zeilen[0].split(" ");
  if (teile.length !== 3 || !/^(0|[1-9][0-9]*)$/.test(teile[1])) throw new Error("Die Indexzeile ist ungültig.");
  const anzahl = Number(teile[1]);
  if (!Number.isSafeInteger(anzahl) || anzahl < 2 || anzahl > MAX_BAUMGROESSE) throw new Error("Die Zahl der Indexeinträge ist ungültig.");
  const wurzel = base64Decode(teile[2]);
  if (wurzel.length !== 32) throw new Error("Die Indexwurzel hat nicht 32 Byte.");
  return { anzahl, wurzelHex: hex(wurzel) };
}

function istHex64(text) {
  return typeof text === "string" && /^[0-9a-f]{64}$/.test(text);
}

async function blattPruefen(b, anzahlBlaetter, wurzelHex) {
  if (!b || typeof b !== "object" || !istHex64(b.keyHash) || !istHex64(b.kette) || !Number.isSafeInteger(b.anzahl) || b.anzahl < 0 || !Number.isInteger(b.index) || !Array.isArray(b.pfad)) return false;
  const leaf = await leafHashOfData(blattDaten(unhex(b.keyHash), b.anzahl, unhex(b.kette)));
  return verifyInclusionOfLeaf({ index: b.index, treeSize: anzahlBlaetter, leaf, path: b.pfad, rootHash: wurzelHex });
}

export function stufeBestimmen(intern, festgelegt, punktErgebnis) {
  let stufe = 0;
  let stufeText = "Nur in sich stimmig";
  if (intern && festgelegt) {
    stufe = 1;
    stufeText = "Protokollschlüssel gebunden";
  }
  if (intern && festgelegt && punktErgebnis.schwelle > 0 && punktErgebnis.zeugenGueltig >= punktErgebnis.schwelle) {
    stufe = 2;
    stufeText = `Bezeugt von ${punktErgebnis.zeugenGueltig} unabhängigen Zeugen`;
  }
  if (!intern) stufeText = "Nicht bestanden";
  return { stufe, stufeText };
}

export async function aussagePruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const aussagen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form der Aussage", false, text);
    return { ok: false, checks, warnungen, aussagen, stufe: 0, stufeText: "Nicht prüfbar" };
  };
  try {
    if (!doc || doc.schema !== "defconder-aussage-1") return abbruch("Unbekanntes Format.");
    if (doc.regeln !== INDEXREGELN) return abbruch("Unbekannte Indexregeln.");
    if (typeof doc.notiz !== "string" || !Array.isArray(doc.aussagen) || doc.aussagen.length === 0 || doc.aussagen.length > 200) return abbruch("Prüfpunkt oder Aussagen fehlen.");
    const festgelegt = Boolean(opts.logSchluessel);
    const logSchluessel = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof logSchluessel !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const punktErgebnis = await pruefpunktPruefen(doc.notiz, { ...opts, logSchluessel });
    for (const c of punktErgebnis.checks) add(`punkt_${c.id}`, c.label, c.ok, c.detail);
    if (!punktErgebnis.punkt) return { ok: false, checks, warnungen, aussagen, stufe: 0, stufeText: "Nicht bestanden" };
    const punkt = punktErgebnis.punkt;
    const index = indexZeileLesen(punkt.erweiterungen);
    add("indexzeile", `Der Prüfpunkt bindet einen Index mit ${index.anzahl} Einträgen`, true, `Indexwurzel ${index.wurzelHex.slice(0, 16)}…`);
    for (const a of doc.aussagen) {
      if (!a || typeof a.schluessel !== "string" || a.schluessel.length === 0 || a.schluessel.length > MAX_SCHLUESSEL) {
        add("aussage", "Aussage hat einen gültigen Schlüssel", false, "Schlüssel fehlt oder ist zu lang.");
        continue;
      }
      const K = hex(await schluesselHash(a.schluessel));
      if (a.art === "vorhanden") {
        const leafOk = await blattPruefen({ keyHash: K, anzahl: a.anzahl, kette: a.kette, index: a.index, pfad: a.pfad }, index.anzahl, index.wurzelHex);
        add("vorhanden_index", `„${a.schluessel}“ steht im Index des Prüfpunkts (${a.anzahl} Ereignisse)`, leafOk && a.anzahl >= 1, leafOk ? "" : "Der Einschlussbeweis des Indexeintrags ist ungültig.");
        let listeOk = true;
        let listeText = "";
        if (a.ereignisse !== undefined) {
          if (!Array.isArray(a.ereignisse) || a.ereignisse.length !== a.anzahl || a.ereignisse.length > MAX_EREIGNISSE_IN_AUSSAGE || !a.ereignisse.every(istHex64) || new Set(a.ereignisse).size !== a.ereignisse.length) {
            listeOk = false;
            listeText = "Die Liste der Ereignisse passt nicht zur Anzahl.";
          } else {
            listeOk = hex(await kettenWert(a.ereignisse)) === a.kette;
            listeText = listeOk ? "" : "Die Kettenprüfsumme der Ereignisse weicht ab.";
          }
          add("vorhanden_liste", `Die ${a.anzahl} genannten Ereignisse sind genau die im Index erfassten`, listeOk, listeText);
        }
        let belegeOk = true;
        if (a.belege !== undefined) {
          if (!Array.isArray(a.belege) || !Array.isArray(a.ereignisse) || a.belege.length !== a.ereignisse.length) belegeOk = false;
          else {
            let letzteSeq = -1;
            for (let i = 0; i < a.belege.length; i += 1) {
              const b = a.belege[i];
              if (!b || !Number.isInteger(b.seq) || b.seq <= letzteSeq || b.seq >= punkt.groesse || !(await verifyInclusion({ index: b.seq, treeSize: punkt.groesse, eventHash: a.ereignisse[i], path: b.pfad, rootHash: punkt.wurzelHex }))) {
                belegeOk = false;
                break;
              }
              letzteSeq = b.seq;
            }
          }
          add("vorhanden_belege", "Jedes genannte Ereignis liegt nachweislich im Protokoll des Prüfpunkts, in der Reihenfolge der Folgenummern", belegeOk);
        }
        const ok = leafOk && a.anzahl >= 1 && listeOk && belegeOk;
        aussagen.push({ art: "vorhanden", schluessel: a.schluessel, ok, anzahl: a.anzahl, text: `Zu „${a.schluessel}“ gibt es im Protokoll bis Größe ${punkt.groesse} genau ${a.anzahl} Ereignis${a.anzahl === 1 ? "" : "se"}${a.ereignisse ? "" : " (Anzahl, ohne Liste)"}.` });
      } else if (a.art === "abwesend") {
        const l = a.links;
        const r = a.rechts;
        const lOk = await blattPruefen(l, index.anzahl, index.wurzelHex);
        const rOk = await blattPruefen(r, index.anzahl, index.wurzelHex);
        const nachbarn = lOk && rOk && r.index === l.index + 1;
        const dazwischen = lOk && rOk && l.keyHash < K && K < r.keyHash;
        add("abwesend_index", `Zwischen zwei benachbarten Indexeinträgen liegt „${a.schluessel}“ nicht`, lOk && rOk && nachbarn && dazwischen, !lOk || !rOk ? "Ein Einschlussbeweis der Nachbarn ist ungültig." : !nachbarn ? "Die Nachbarn liegen nicht nebeneinander." : !dazwischen ? "Der Schlüssel liegt nicht zwischen den Nachbarn." : "");
        aussagen.push({ art: "abwesend", schluessel: a.schluessel, ok: lOk && rOk && nachbarn && dazwischen, text: `Zu „${a.schluessel}“ gibt es im Protokoll bis Größe ${punkt.groesse} kein Ereignis.` });
      } else {
        add("aussage", "Art der Aussage ist bekannt", false, `Unbekannte Art ${String(a.art).slice(0, 30)}.`);
      }
    }
    warnungen.push("Die Aussage gilt für den Index, den der Betreiber im Prüfpunkt festgelegt hat. Dass der Index vollständig aus dem Protokoll abgeleitet wurde, lässt sich nur durch Nachrechnen mit dem vollständigen Protokoll prüfen, zum Beispiel mit dem Beobachter.");
    if (!festgelegt) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Die Aussage beweist nur, dass sie in sich stimmig ist.");
    const intern = checks.every((c) => c.ok);
    const { stufe, stufeText } = stufeBestimmen(intern, festgelegt, punktErgebnis);
    if (intern && Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    return { ok: checks.every((c) => c.ok), checks, warnungen, aussagen, stufe, stufeText: checks.every((c) => c.ok) ? stufeText : "Nicht bestanden", punkt };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}

export { notizLesen, pruefpunktLesen, unhex };
