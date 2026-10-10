import { unhex, hex, verifyInclusion, verifyConsistency } from "./merkle.js";
import { schluesselLesen, TYP_ED25519 } from "./note.js";
import { ereignisHashPruefen, auszugPruefen } from "./ereignis.js";
import { pruefpunktPruefen, canonicalJson } from "./pruefer-kern.js";
import { stufeBestimmen, aussagePruefen } from "./aussage.js";

export const FREIGABE_SCHEMA = "defconder-freigabe-1";
export const AUSKUNFT_SCHEMA = "defconder-freigabeauskunft-1";
export const BERICHT_SCHEMA = "defconder-freigabebericht-1";
export const QUITTUNG_SCHEMA = "defconder-freigabequittung-1";
const encoder = new TextEncoder();
const MAX_QUITTUNGEN = 200;
const MAX_HUETER = 32;

function istHex(text, laenge) {
  return typeof text === "string" && new RegExp(`^[0-9a-f]{${laenge}}$`).test(text);
}

async function ed25519Pruefen(publicKey, nachricht, signaturHex) {
  try {
    if (!istHex(signaturHex, 128)) return false;
    const key = await globalThis.crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, unhex(signaturHex), nachricht);
  } catch {
    return false;
  }
}

export function ohneSignatur(objekt) {
  const kopie = { ...objekt };
  delete kopie.signatur;
  return kopie;
}

export async function huetersLesen(liste) {
  const nachName = new Map();
  for (const text of liste ?? []) {
    const s = await schluesselLesen(text);
    if (s.typ !== TYP_ED25519) throw new Error("Ein Hüterschlüssel muss ein Ed25519-Schlüssel sein.");
    if (nachName.has(s.name)) throw new Error("Zwei Hüter haben denselben Namen.");
    nachName.set(s.name, s);
  }
  return nachName;
}

async function signiertPruefen(objekt, hueterMap) {
  const s = hueterMap.get(objekt?.hueter);
  if (!s) return false;
  return ed25519Pruefen(s.publicKey, encoder.encode(canonicalJson(ohneSignatur(objekt))), objekt.signatur);
}

export async function ereignisLesen(eintrag) {
  if (!eintrag || typeof eintrag !== "object" || (eintrag.event && eintrag.auszug) || !(eintrag.event || eintrag.auszug)) return { ok: false, grund: "Das Ereignis fehlt oder ist doppelt." };
  if (eintrag.auszug) {
    const a = await auszugPruefen(eintrag.auszug);
    if (!a.ok) return { ok: false, grund: a.grund };
    const offen = {};
    for (const o of a.offene ?? []) offen[o.name] = o.wert;
    const k = eintrag.auszug.kopf;
    return { ok: true, ereignis: { ...offen, seq: k.seq, type: k.type, at: k.at, hv: k.hv, prevHash: k.prevHash, hash: k.hash } };
  }
  const r = await ereignisHashPruefen(eintrag.event);
  return r.ok ? { ok: true, ereignis: eintrag.event } : { ok: false, grund: r.grund };
}

export async function freigabePruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form des Freigabenachweises", false, text);
    return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht prüfbar", gueltigeHueter: [] };
  };
  try {
    if (!doc || doc.schema !== FREIGABE_SCHEMA) return abbruch("Unbekanntes Format.");
    if (typeof doc.notiz !== "string" || typeof doc.objektId !== "string" || doc.objektId.length === 0 || !doc.anfrage || !Array.isArray(doc.anfrage.pfad) || !Array.isArray(doc.quittungen) || doc.quittungen.length === 0 || doc.quittungen.length > MAX_QUITTUNGEN) return abbruch("Prüfpunkt, Objekt, Anfrage oder Quittungen fehlen.");
    const festgelegt = Boolean(opts.logSchluessel);
    const logSchluessel = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof logSchluessel !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const punktErgebnis = await pruefpunktPruefen(doc.notiz, { ...opts, logSchluessel });
    for (const c of punktErgebnis.checks) add(`punkt_${c.id}`, c.label, c.ok, c.detail);
    if (!punktErgebnis.punkt) return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", gueltigeHueter: [] };
    const punkt = punktErgebnis.punkt;

    const gelesen = await ereignisLesen(doc.anfrage);
    if (!gelesen.ok) {
      add("anfrage", "Die Anfrage steht als gültiges Ereignis im Nachweis", false, gelesen.grund);
      return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", gueltigeHueter: [] };
    }
    const e = gelesen.ereignis;
    const drin = Number.isInteger(e.seq) && e.seq < punkt.groesse && (await verifyInclusion({ index: e.seq, treeSize: punkt.groesse, eventHash: e.hash, path: doc.anfrage.pfad, rootHash: punkt.wurzelHex }));
    add("anfrage", `Die Anfrage (Ereignis ${e.seq}, ${e.type}) steht im Protokoll des Prüfpunkts`, drin, drin ? "" : "Der Einschlussbeweis ist ungültig.");
    const objektOk = e.objectId === doc.objektId;
    add("anfrage_objekt", `Die Anfrage nennt das Objekt „${doc.objektId}“`, objektOk, objektOk ? "" : "Das Objekt im Ereignis ist ein anderes oder verdeckt.");
    if (typeof opts.erwartetesObjekt === "string") add("erwartet_objekt", `Der Nachweis gilt für das verlangte Objekt „${opts.erwartetesObjekt}“`, doc.objektId === opts.erwartetesObjekt && e.objectId === opts.erwartetesObjekt, "");
    if (typeof opts.erwarteterNutzer === "string") add("erwartet_nutzer", `Die Anfrage stammt vom verlangten Nutzer „${opts.erwarteterNutzer}“`, e.userId === opts.erwarteterNutzer, "");
    if (doc.nutzerId !== undefined) add("anfrage_nutzer", `Die Anfrage stammt vom Nutzer „${doc.nutzerId}“`, e.userId === doc.nutzerId, "");
    if (Array.isArray(opts.erlaubteTypen) && opts.erlaubteTypen.length > 0) add("anfrage_typ", "Das Ereignis hat einen Typ, der als Anfrage zählt", opts.erlaubteTypen.includes(e.type), `Typ ${e.type}`);

    const hueterGebunden = Array.isArray(opts.hueter) && opts.hueter.length > 0;
    const hueter = await huetersLesen(hueterGebunden ? opts.hueter : doc.hueter);
    const schwelle = Number.isInteger(opts.hueterSchwelle) ? opts.hueterSchwelle : doc.schwelle;
    if (!Number.isInteger(schwelle) || schwelle < 1 || schwelle > MAX_HUETER) return abbruch("Die Schwelle der Hüter fehlt oder ist unzulässig.");

    const gueltig = [];
    const probleme = [];
    const gesehen = new Set();
    for (const q of doc.quittungen) {
      let grund = "";
      if (!q || q.schema !== QUITTUNG_SCHEMA || typeof q.hueter !== "string") grund = "Form";
      else if (gesehen.has(q.hueter)) grund = "doppelt";
      else if (!(await signiertPruefen(q, hueter))) grund = "Signatur oder Hüter unbekannt";
      else if (q.anfrageHash !== e.hash || q.seq !== e.seq || q.objektId !== doc.objektId || (doc.nutzerId !== undefined && q.nutzerId !== doc.nutzerId)) grund = "nennt eine andere Anfrage";
      else if (!Number.isInteger(q.groesse) || q.groesse <= e.seq || q.groesse > punkt.groesse || !istHex(q.wurzel, 64)) grund = "nennt einen unzulässigen Stand des Protokolls";
      else if (q.groesse === punkt.groesse) {
        if (q.wurzel !== punkt.wurzelHex) grund = "nennt eine andere Wurzel für denselben Stand";
      } else {
        const k = (doc.konsistenz ?? {})[`${q.groesse}-${punkt.groesse}`];
        const ok = Array.isArray(k?.pfad) && (await verifyConsistency({ oldSize: q.groesse, newSize: punkt.groesse, oldRoot: q.wurzel, newRoot: punkt.wurzelHex, proof: k.pfad }));
        if (!ok) grund = "nennt einen Stand, der nicht zum Prüfpunkt passt (Konsistenzbeweis fehlt oder ist ungültig)";
      }
      gesehen.add(q?.hueter);
      if (grund) probleme.push(`${q?.hueter ?? "?"}: ${grund}`);
      else gueltig.push(q.hueter);
    }
    add("quittungen", `${gueltig.length} von mindestens ${schwelle} geforderten Quittungen festgelegter Hüter sind gültig und beziehen sich auf genau diese Anfrage`, gueltig.length >= schwelle, probleme.join("; "));
    if (probleme.length > 0 && gueltig.length >= schwelle) warnungen.push(`Einige Quittungen sind ungültig und zählen nicht: ${probleme.join("; ")}`);
    if (!hueterGebunden) warnungen.push("Die Schlüssel der Hüter sind nicht festgelegt. Der Nachweis zeigt nur, dass er in sich stimmig ist, nicht, dass die Hüter die sind, denen Sie vertrauen.");
    warnungen.push("Der Nachweis zeigt, dass die Anfrage vor der Freigabe im Protokoll stand. Er zeigt nicht, dass die Hüter nicht zusammengearbeitet haben, und nicht, dass der Empfänger den Klartext nicht weitergegeben hat.");
    if (!festgelegt) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Der Nachweis zeigt nur, dass er in sich stimmig ist.");
    const intern = checks.every((c) => c.ok);
    let { stufe, stufeText } = stufeBestimmen(intern, festgelegt, punktErgebnis);
    if (!hueterGebunden && stufe > 0) {
      stufe = 0;
      stufeText = "Nur in sich stimmig, Hüter nicht festgelegt";
    }
    if (intern && Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    const ok = checks.every((c) => c.ok);
    return { ok, checks, warnungen, stufe, stufeText: ok ? stufeText : "Nicht bestanden", gueltigeHueter: gueltig, schwelle, anfrage: { seq: e.seq, type: e.type, hash: e.hash, objektId: doc.objektId }, pq: punktErgebnis.pq, punkt };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}

export async function freigabeberichtPruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form des Freigabeberichts", false, text);
    return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht prüfbar", ausgeschlossen: false, freigaben: [] };
  };
  try {
    if (!doc || doc.schema !== BERICHT_SCHEMA) return abbruch("Unbekanntes Format.");
    if (typeof doc.objektId !== "string" || doc.objektId.length === 0 || !Array.isArray(doc.auskuenfte) || doc.auskuenfte.length > MAX_HUETER) return abbruch("Objekt oder Auskünfte fehlen.");
    if (!Array.isArray(opts.hueter) || opts.hueter.length === 0) return abbruch("Es sind keine Schlüsselhüter festgelegt. Ohne sie lässt sich nichts schließen.");
    const hueter = await huetersLesen(opts.hueter);
    const n = hueter.size;
    const k = Number.isInteger(opts.hueterSchwelle) ? opts.hueterSchwelle : doc.schwelle;
    if (!Number.isInteger(k) || k < 1 || k > n) return abbruch("Die Schwelle der Hüter fehlt oder ist unzulässig.");

    const gueltig = new Map();
    const probleme = [];
    for (const a of doc.auskuenfte) {
      let grund = "";
      if (!a || a.schema !== AUSKUNFT_SCHEMA || typeof a.hueter !== "string" || !Array.isArray(a.quittungen) || a.quittungen.length > MAX_QUITTUNGEN) grund = "Form";
      else if (gueltig.has(a.hueter)) grund = "doppelt";
      else if (a.objektId !== doc.objektId) grund = "betrifft ein anderes Objekt";
      else if (!(await signiertPruefen(a, hueter))) grund = "Signatur oder Hüter unbekannt";
      else if (!a.quittungen.every((q) => q && istHex(q.anfrageHash, 64) && Number.isInteger(q.at))) grund = "Eine Quittung in der Liste ist unvollständig";
      if (grund) probleme.push(`${a?.hueter ?? "?"}: ${grund}`);
      else gueltig.set(a.hueter, a);
    }
    const noetig = n - k + 1;
    add("auskuenfte", `${gueltig.size} von mindestens ${noetig} nötigen Auskünften der ${n} festgelegten Hüter sind gültig (bei Schwelle ${k} von ${n} bleiben dann höchstens ${k - 1} Hüter ohne Auskunft)`, gueltig.size >= noetig, probleme.join("; "));

    const proAnfrage = new Map();
    for (const [name, a] of gueltig) {
      for (const q of a.quittungen) {
        const menge = proAnfrage.get(q.anfrageHash) ?? new Set();
        menge.add(name);
        proAnfrage.set(q.anfrageHash, menge);
      }
    }
    const unterschlagen = [];
    for (const q of Array.isArray(doc.weitereQuittungen) ? doc.weitereQuittungen.slice(0, MAX_QUITTUNGEN) : []) {
      if (!q || q.schema !== QUITTUNG_SCHEMA || q.objektId !== doc.objektId || !istHex(q.anfrageHash, 64) || !(await signiertPruefen(q, hueter))) continue;
      const auskunft = gueltig.get(q.hueter);
      if (auskunft && !auskunft.quittungen.some((x) => x.anfrageHash === q.anfrageHash)) unterschlagen.push(q.hueter);
      if (!auskunft) {
        const menge = proAnfrage.get(q.anfrageHash) ?? new Set();
        menge.add(q.hueter);
        proAnfrage.set(q.anfrageHash, menge);
      }
    }
    if (Array.isArray(doc.weitereQuittungen) && doc.weitereQuittungen.length > 0) add("widerspruch", "Keine Auskunft verschweigt eine Quittung, die derselbe Hüter selbst unterschrieben hat", unterschlagen.length === 0, unterschlagen.length ? `Auskunft von ${[...new Set(unterschlagen)].join(", ")} widerspricht der eigenen Quittung` : "");
    const ohneAuskunft = n - gueltig.size;
    const freigaben = [];
    for (const [anfrageHash, menge] of proAnfrage) {
      const bekannt = menge.size;
      freigaben.push({ anfrageHash, hueter: [...menge], sicher: bekannt >= k, moeglich: bekannt + ohneAuskunft >= k });
    }
    const ausgeschlossen = gueltig.size >= noetig && freigaben.every((f) => !f.moeglich);
    add("schluss", ausgeschlossen ? `Für „${doc.objektId}“ konnte kein Schlüssel freigegeben werden: Weniger als ${k} Hüter können eine Quittung ausgestellt haben` : `Für „${doc.objektId}“ ist eine Freigabe nicht ausgeschlossen`, true, ausgeschlossen ? "" : `${freigaben.filter((f) => f.sicher).length} Anfragen haben Quittungen von mindestens ${k} Hütern, ${freigaben.filter((f) => !f.sicher && f.moeglich).length} weitere sind möglich.`);

    if (doc.aussage) {
      const aussage = await aussagePruefen(doc.aussage, { ...opts, hueter: undefined });
      for (const c of aussage.checks.filter((x) => !x.ok)) add(`aussage_${c.id}`, c.label, false, c.detail);
      add("aussage", "Die Aussage über das Protokoll zu diesem Objekt besteht", aussage.ok, aussage.ok ? "" : "Die Aussage ist nicht gültig.");
      const imProtokoll = new Set();
      for (const a of doc.aussage.aussagen ?? []) for (const h of a.ereignisse ?? []) imProtokoll.add(h);
      const fehlend = freigaben.filter((f) => !imProtokoll.has(f.anfrageHash));
      add("protokolliert", `Jede Quittung gehört zu einem Ereignis, das im Protokoll steht (${freigaben.length - fehlend.length} von ${freigaben.length})`, fehlend.length === 0, fehlend.map((f) => `${f.anfrageHash.slice(0, 16)}…`).join(", "));
    } else if (opts.aussageVerlangen) add("aussage", "Dem Bericht liegt eine Aussage über das Protokoll bei, wie verlangt", false, "Die Aussage fehlt.");
    else if (freigaben.length > 0) warnungen.push("Dem Bericht liegt keine Aussage über das Protokoll bei. Es wurde nicht geprüft, ob zu jeder Quittung ein Ereignis im Protokoll steht.");

    warnungen.push("Die Auskünfte sind Zusagen der Hüter. Ein Hüter, der eine falsche Auskunft unterschreibt, ist daran erkennbar, sobald jemand mit einer Quittung dagegenhält. Der Schluss gilt nur, wenn weniger als die Schwelle der Hüter zusammenarbeiten.");
    warnungen.push("Ausgeschlossen ist die Freigabe über diesen Weg. Wer Klartext schon vor Einführung der Hüter hatte oder ihn auf anderem Weg beschafft hat, wird davon nicht erfasst.");
    const ok = checks.every((c) => c.ok);
    return { ok, checks, warnungen, stufe: ok ? 1 : 0, stufeText: ok ? "Hüter festgelegt" : "Nicht bestanden", ausgeschlossen: ok && ausgeschlossen, freigaben, hueterAntwortete: [...gueltig.keys()], n, k };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}

export { hex };
