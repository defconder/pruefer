import { hex, unhex, sha256Bytes, verifyInclusion } from "./merkle.js";
import { sha256Sync } from "./sha256sync.js";
import { notizLesen, pruefpunktLesen, base64Decode } from "./note.js";
import { ereignisHashPruefen, auszugPruefen } from "./ereignis.js";
import { bitcoinKopfPruefen, STANDARD_MINDESTARBEIT_BITS } from "./zeitanker.js";
import { zeitbeweisPruefen, ZEITBEWEIS_SCHEMA } from "./zeitbeweis.js";
import { entscheidungPruefen } from "./entscheidung.js";
import { pruefpunktPruefen } from "./pruefer-kern.js";
import { stufeBestimmen, schluesselVon, schluesselHash, blattPruefen, indexZeileLesen } from "./aussage.js";

export const STICHPROBE_SCHEMA = "defconder-stichprobe-1";
export const MAX_ZIEHUNGEN = 100000;
export const MAX_VERSCHIEDENE = 5000;
export const ENTSCHEIDUNGSTYPEN = ["AccessDenied", "FederatedQueryExecuted"];
export const PRUEFUNGEN = ["kette", "index", "entscheidung"];
const GENESIS = "0".repeat(64);
const encoder = new TextEncoder();
const GRENZE = 2n ** 64n;

function u64(wert) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(wert), false);
  return out;
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

export function ziehen({ wurzelHex, groesse, beaconHex, anzahl }) {
  if (!Number.isInteger(groesse) || groesse < 1 || !Number.isInteger(anzahl) || anzahl < 1 || anzahl > MAX_ZIEHUNGEN) throw new Error("Ungültige Angaben zur Ziehung.");
  const saat = sha256Sync(verbinden(encoder.encode(`${STICHPROBE_SCHEMA}\u0000`), unhex(wurzelHex), unhex(beaconHex), u64(groesse), u64(anzahl)));
  const n = BigInt(groesse);
  const grenze = (GRENZE / n) * n;
  const ergebnis = [];
  for (let zaehler = 0; ergebnis.length < anzahl; zaehler += 1) {
    const roh = sha256Sync(verbinden(saat, u64(zaehler)));
    const wert = new DataView(roh.buffer, roh.byteOffset, 8).getBigUint64(0, false);
    if (wert >= grenze) continue;
    ergebnis.push(Number(wert % n));
  }
  return ergebnis;
}

export function obergrenze(anzahl, konfidenz) {
  return 1 - Math.exp(Math.log(1 - konfidenz) / anzahl);
}

function prozent(anteil) {
  const wert = Math.ceil(anteil * 1e6) / 1e4;
  return `${wert.toLocaleString("de-DE", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} %`;
}

async function kopfKetteTesten(koepfe, ersterKopfHex, abstand, mindestArbeitBits, add) {
  if (!Array.isArray(koepfe) || koepfe.length !== abstand || koepfe.length > 1000) {
    add("zufall_koepfe", "Die Blockköpfe für den Zufall liegen vollständig bei", false, `Erwartet sind ${abstand} Blockköpfe.`);
    return null;
  }
  let vorher = await bitcoinKopfPruefen(ersterKopfHex, { mindestArbeitBits });
  if (!vorher.blockHash) return null;
  let letzter = vorher;
  for (let i = 0; i < koepfe.length; i += 1) {
    const r = await bitcoinKopfPruefen(koepfe[i], { mindestArbeitBits });
    if (!r.ok) {
      add("zufall_kette", `Blockkopf ${i + 1} nach dem bestätigten Block ist gültig`, false, r.grund);
      return null;
    }
    const zurueck = hex(Uint8Array.from(unhex(koepfe[i]).slice(4, 36)).reverse());
    if (zurueck !== letzter.blockHash) {
      add("zufall_kette", `Blockkopf ${i + 1} nach dem bestätigten Block schließt an seinen Vorgänger an`, false, "Der Vorgänger im Blockkopf ist ein anderer Block.");
      return null;
    }
    letzter = r;
  }
  return letzter;
}

export async function stichprobePruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form der Stichprobe", false, text);
    return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht prüfbar", stichprobe: null };
  };
  try {
    if (!doc || doc.schema !== STICHPROBE_SCHEMA) return abbruch("Unbekanntes Format.");
    const regel = doc.regel;
    if (!regel || !Number.isInteger(regel.anzahl) || regel.anzahl < 1 || regel.anzahl > MAX_ZIEHUNGEN || !Number.isInteger(regel.abstand) || regel.abstand < 1 || regel.abstand > 1000 || typeof regel.konfidenz !== "number" || !(regel.konfidenz > 0 && regel.konfidenz < 1)) return abbruch("Die Regel der Stichprobe ist unvollständig oder unzulässig.");
    if (!Array.isArray(regel.pruefungen) || regel.pruefungen.length === 0 || regel.pruefungen.some((p) => !PRUEFUNGEN.includes(p)) || !regel.pruefungen.includes("kette")) return abbruch("Die geprüften Eigenschaften sind unzulässig. Die Kette gehört immer dazu.");
    if (typeof doc.notiz !== "string" || !doc.zeitbeweis || typeof doc.zeitbeweis !== "object" || !doc.zufall || !Array.isArray(doc.zufall.koepfe) || !Array.isArray(doc.proben) || doc.proben.length > MAX_VERSCHIEDENE) return abbruch("Prüfpunkt, Zeitbeweis, Zufall oder Proben fehlen.");
    if (Number.isInteger(opts.mindestAnzahl) && regel.anzahl < opts.mindestAnzahl) add("mindestanzahl", `Mindestens ${opts.mindestAnzahl} Ziehungen verlangt`, false, `Die Stichprobe hat nur ${regel.anzahl}.`);
    if (Number.isInteger(opts.mindestAbstand) && regel.abstand < opts.mindestAbstand) add("mindestabstand", `Mindestens ${opts.mindestAbstand} Blöcke Abstand für den Zufall verlangt`, false, `Die Stichprobe nutzt ${regel.abstand}.`);
    if (regel.abstand < 6) warnungen.push("Der Zufall stammt aus einem Block, der weniger als sechs Blöcke nach der Bestätigung liegt. Ein Block kann in seltenen Fällen noch verworfen werden. Üblich sind mindestens sechs.");

    const festgelegt = Boolean(opts.logSchluessel);
    const logSchluessel = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof logSchluessel !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const zeit = await zeitbeweisPruefen({ ...doc.zeitbeweis, schema: ZEITBEWEIS_SCHEMA, notiz: doc.notiz, logSchluessel: doc.logSchluessel }, { ...opts, logSchluessel });
    for (const c of zeit.checks) add(`zeit_${c.id}`, c.label, c.ok, c.detail);
    if (!zeit.punkt) return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", stichprobe: null };
    const punktErgebnis = await pruefpunktPruefen(doc.notiz, { ...opts, logSchluessel });
    const punkt = punktErgebnis.punkt;

    const mindestArbeitBits = opts.mindestArbeitBits ?? STANDARD_MINDESTARBEIT_BITS;
    let beacon = null;
    let hoehe = null;
    if (zeit.bitcoin) {
      hoehe = zeit.bitcoin.hoehe;
      const ersterKopf = doc.zeitbeweis.koepfe?.[String(hoehe)];
      if (typeof ersterKopf === "string") {
        beacon = await kopfKetteTesten(doc.zufall.koepfe, ersterKopf, regel.abstand, mindestArbeitBits, add);
        if (beacon) add("zufall", `Der Zufall stammt aus dem Bitcoin-Block ${beacon.blockHash.slice(0, 16)}… (${regel.abstand} Blöcke nach dem bestätigten Block ${hoehe})`, true, "Dieser Block war beim Festschreiben des Prüfpunkts noch nicht gefunden.");
      }
    }
    if (!beacon) add("zufall", "Der Zufall aus einem späteren Bitcoin-Block ist nachweisbar", false, "Es fehlt ein bestätigter Zeitbeweis oder die Kette der Blockköpfe.");

    let gezogen = [];
    if (beacon) {
      gezogen = ziehen({ wurzelHex: punkt.wurzelHex, groesse: punkt.groesse, beaconHex: beacon.blockHash, anzahl: regel.anzahl });
      const verschieden = [...new Set(gezogen)].sort((a, b) => a - b);
      const vorgelegt = doc.proben.map((p) => p?.seq);
      const gleich = vorgelegt.length === verschieden.length && vorgelegt.every((s, i) => s === verschieden[i]);
      add("ziehung", `Die ${regel.anzahl} Ziehungen (${verschieden.length} verschiedene Ereignisse) wurden aus Prüfpunkt und Blockprüfsumme nachgerechnet und sind genau die vorgelegten`, gleich, gleich ? "" : "Die vorgelegten Ereignisse sind nicht die gezogenen.");
      if (!gleich) return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", stichprobe: null, punkt };
    }

    let index = null;
    if (regel.pruefungen.includes("index")) {
      try {
        index = indexZeileLesen(punkt.erweiterungen);
      } catch (err) {
        add("index_zeile", "Der Prüfpunkt bindet einen Index", false, String(err.message));
      }
    }

    const fehler = { kette: [], index: [], entscheidung: [] };
    let entscheidungenGeprueft = 0;
    let offeneEreignisse = 0;
    for (const probe of doc.proben) {
      if (!probe || !Number.isInteger(probe.seq) || probe.seq < 0 || probe.seq >= punkt.groesse || typeof probe.pfad !== "object" || !Array.isArray(probe.pfad) || (probe.event && probe.auszug) || !(probe.event || probe.auszug)) {
        fehler.kette.push(`Probe ${probe?.seq}: unvollständig`);
        continue;
      }
      let ereignis = probe.event;
      let hashOk;
      if (probe.auszug) {
        const a = await auszugPruefen(probe.auszug);
        hashOk = a.ok;
        const offen = {};
        for (const o of a.offene ?? []) offen[o.name] = o.wert;
        const k = probe.auszug.kopf;
        ereignis = { ...offen, seq: k.seq, type: k.type, at: k.at, hv: k.hv, prevHash: k.prevHash, hash: k.hash };
      } else {
        hashOk = (await ereignisHashPruefen(ereignis)).ok;
      }
      const drin = hashOk && ereignis.seq === probe.seq && (await verifyInclusion({ index: probe.seq, treeSize: punkt.groesse, eventHash: ereignis.hash, path: probe.pfad, rootHash: punkt.wurzelHex }));
      let verkettet = false;
      if (drin) {
        if (probe.seq === 0) verkettet = ereignis.prevHash === GENESIS;
        else {
          const v = probe.vorgaenger;
          verkettet = Boolean(v) && typeof v.hash === "string" && v.hash === ereignis.prevHash && Array.isArray(v.pfad) && (await verifyInclusion({ index: probe.seq - 1, treeSize: punkt.groesse, eventHash: v.hash, path: v.pfad, rootHash: punkt.wurzelHex }));
        }
      }
      if (!drin || !verkettet) fehler.kette.push(`Ereignis ${probe.seq}: ${!drin ? "Prüfsumme oder Einschluss ungültig" : "Vorgänger nicht belegt"}`);

      if (regel.pruefungen.includes("index")) {
        let ok = Boolean(index) && !probe.auszug;
        let grund = probe.auszug ? "liegt nur als Auszug vor" : index ? "" : "kein Index";
        if (ok) {
          const belege = Array.isArray(probe.indexBelege) ? probe.indexBelege : [];
          for (const schluessel of schluesselVon(ereignis, index.regeln)) {
            const b = belege.find((x) => x?.schluessel === schluessel);
            const keyHash = hex(await schluesselHash(schluessel, index.regeln));
            const leafOk = b && keyHash === b.keyHash && Number.isSafeInteger(b.anzahl) && b.anzahl >= 1 && (await blattPruefen(b, index.anzahl, index.wurzelHex));
            if (!leafOk) {
              ok = false;
              grund = `Schlüssel „${schluessel}“ ist nicht im Index belegt`;
              break;
            }
          }
        }
        if (!ok) fehler.index.push(`Ereignis ${probe.seq}: ${grund}`);
      }

      if (regel.pruefungen.includes("entscheidung") && ENTSCHEIDUNGSTYPEN.includes(ereignis.type)) {
        offeneEreignisse += 1;
        let ok = false;
        let grund = "";
        if (!Array.isArray(ereignis.belege)) grund = probe.auszug ? "Belege sind verdeckt" : "Ein Entscheidungsereignis trägt keine Belege";
        else if (!probe.entscheidung || !Array.isArray(probe.entscheidung.ereignisse)) grund = "Der Entscheidungsnachweis fehlt";
        else {
          const r = await entscheidungPruefen({ schema: "defconder-entscheidung-1", notiz: doc.notiz, logSchluessel, seq: probe.seq, ereignisse: probe.entscheidung.ereignisse }, { ...opts, logSchluessel, vorgepruefterPunkt: punktErgebnis });
          ok = r.ok;
          grund = r.ok ? "" : r.checks.filter((c) => !c.ok && !c.id.startsWith("punkt_")).map((c) => c.label).slice(0, 2).join("; ");
          if (ok) entscheidungenGeprueft += 1;
        }
        if (!ok) fehler.entscheidung.push(`Ereignis ${probe.seq}: ${grund}`);
      }
    }

    const verschiedene = doc.proben.length;
    add("proben_kette", `Prüfsumme, Einschluss im Protokoll und Verkettung stimmen bei allen ${verschiedene} gezogenen Ereignissen`, fehler.kette.length === 0, fehler.kette.slice(0, 3).join("; "));
    if (regel.pruefungen.includes("index")) add("proben_index", `Alle Schlüssel aller gezogenen Ereignisse stehen im Index des Prüfpunkts`, fehler.index.length === 0, fehler.index.slice(0, 3).join("; "));
    if (regel.pruefungen.includes("entscheidung")) add("proben_entscheidung", `Alle gezogenen Entscheidungsereignisse (${offeneEreignisse}) tragen Belege, die zur veröffentlichten Regel passen`, fehler.entscheidung.length === 0, fehler.entscheidung.slice(0, 3).join("; "));

    const alleOk = fehler.kette.length === 0 && fehler.index.length === 0 && fehler.entscheidung.length === 0;
    const grenze = obergrenze(regel.anzahl, regel.konfidenz);
    if (alleOk && beacon) add("schranke", `Bei ${regel.anzahl} Ziehungen ohne Verstoß liegt der Anteil verletzender Ereignisse mit ${Math.round(regel.konfidenz * 1000) / 10} % Sicherheit unter ${prozent(grenze)}`, true, "Rechnung: Wäre der Anteil p, bliebe eine Stichprobe dieser Größe nur mit Wahrscheinlichkeit (1 minus p) hoch Anzahl ohne Fund.");

    warnungen.push("Eine Stichprobe findet seltene einzelne Verstöße nicht. Sie ergänzt die Beweise und ersetzt sie nicht.");
    warnungen.push("Der Zufall stützt sich darauf, dass der Betreiber den Prüfpunkt festgeschrieben hat, bevor der Block mit dem Zufall gefunden wurde. Das gilt nur, wenn der Prüfpunkt von unabhängigen Zeugen bestätigt ist, sonst hätte er mehrere Prüfpunkte vorbereiten und den günstigen später vorlegen können.");
    if (!festgelegt) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Die Stichprobe zeigt nur, dass sie in sich stimmig ist.");
    const intern = checks.every((c) => c.ok);
    const { stufe, stufeText } = stufeBestimmen(intern, festgelegt, punktErgebnis);
    if (intern && stufe < 2) warnungen.push("Der Prüfpunkt ist nicht von festgelegten, unabhängigen Zeugen bestätigt. Die Aussage der Stichprobe gilt dann nur unter der Annahme, dass der Betreiber nicht mehrere Prüfpunkte vorbereitet hat.");
    if (intern && Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    const ok = checks.every((c) => c.ok);
    const ergebnis = { gezogen: regel.anzahl, verschieden: verschiedene, konfidenz: regel.konfidenz, obergrenze: alleOk ? grenze : null, beacon: beacon?.blockHash ?? null, hoehe, groesse: punkt.groesse, einzelverstossUnentdeckt: punkt.groesse > 0 ? 1 - Math.min(1, verschiedene / punkt.groesse) : null, entscheidungenGeprueft, fehler };
    return { ok, checks, warnungen, stufe, stufeText: ok ? stufeText : "Nicht bestanden", stichprobe: ergebnis, pq: punktErgebnis.pq, spaetestens: zeit.spaetestens, fruehestens: zeit.fruehestens, punkt };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}

export { notizLesen, pruefpunktLesen, base64Decode, sha256Bytes };
