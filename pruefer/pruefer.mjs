import { readFileSync } from "node:fs";
import { verifyPackage, verifyConsistency, pruefpunktPruefen } from "./pruefer-kern.js";
import { aussagePruefen } from "./aussage.js";
import { entscheidungPruefen } from "./entscheidung.js";
import { widerspruchPruefen } from "./widerspruch.js";
import { berichtErzeugen, berichtText } from "./bericht.js";
import { notizLesen, pruefpunktLesen, schluesselLesen, signaturenPruefen } from "./note.js";

const HILFE = `Aufruf:
  node pruefer.mjs [paket] <beweispaket.json> [originaldatei] [Optionen]
  node pruefer.mjs aussage <aussage.json> [Optionen]
  node pruefer.mjs entscheidung <nachweis.json> [Optionen]
  node pruefer.mjs widerspruch <beweis.json> [--log-schluessel <Schluessel>]
  node pruefer.mjs pruefpunkt <pruefpunkt.txt> --log-schluessel <Schluessel> [--zeuge <Schluessel>]... [--schwelle N]
  node pruefer.mjs konsistenz <alt.txt> <neu.txt> <beweis.json> --log-schluessel <Schluessel>

Die Dokumentart wird an der Angabe schema erkannt, der Befehl kann auch weggelassen werden.

Optionen:
  --vertraue-schluessel <Kennung>   Kennung des Schlüssels, dem das Paket gehören muss (mehrfach möglich)
  --log-schluessel <Schluessel>     Schlüssel des Protokolls, Form Name+Kennung+Daten
  --zeuge <Schluessel>              Schlüssel eines unabhängigen Zeugen (mehrfach möglich)
  --zeugen-datei <Datei>            Datei mit einem Zeugenschlüssel je Zeile
  --schwelle N                      Zahl der Gegenzeichnungen, die mindestens gültig sein müssen
  --wechsel <Datei>                 signierte Schlüsselwechsel des Betreibers (Datei mit einer Aussage oder einer Liste)
  --mindestarbeit N                 Mindestarbeit eines Zeitankers in Bit (Voreinstellung 64)
  --mindeststufe N                  verlangt mindestens Vertrauensstufe N (0, 1 oder 2), sonst gilt die Prüfung als nicht bestanden
  --bericht                         zusätzlich einen Bericht in Klartext ausgeben`;

function optionen(argumente) {
  const positional = [];
  const opts = { pinnedKeyIds: [], zeugen: [], bericht: false };
  for (let i = 0; i < argumente.length; i += 1) {
    const a = argumente[i];
    if (a === "--vertraue-schluessel") opts.pinnedKeyIds.push(argumente[(i += 1)]);
    else if (a === "--log-schluessel") opts.logSchluessel = argumente[(i += 1)];
    else if (a === "--zeuge") opts.zeugen.push(argumente[(i += 1)]);
    else if (a === "--zeugen-datei") opts.zeugen.push(...readFileSync(argumente[(i += 1)], "utf8").split(/\r?\n/).map((z) => z.trim()).filter((z) => z && !z.startsWith("#")));
    else if (a === "--schwelle") opts.schwelle = Number(argumente[(i += 1)]);
    else if (a === "--mindestarbeit") opts.mindestArbeitBits = Number(argumente[(i += 1)]);
    else if (a === "--mindeststufe") opts.mindestStufe = Number(argumente[(i += 1)]);
    else if (a === "--wechsel") opts.wechsel = JSON.parse(readFileSync(argumente[(i += 1)], "utf8"));
    else if (a === "--bericht") opts.bericht = true;
    else if (a.startsWith("--")) {
      console.log(`Unbekannte Option ${a}\n\n${HILFE}`);
      process.exit(2);
    } else positional.push(a);
  }
  return { positional, opts };
}

function zeile(ok, text, detail) {
  console.log(`${ok ? "BESTANDEN" : "FEHLER   "} ${text}${detail ? `\n          ${detail}` : ""}`);
}

function ausgeben(ergebnis, art, opts, okText, schlechtText) {
  for (const c of ergebnis.checks) zeile(c.ok, c.label, c.detail);
  for (const w of ergebnis.warnungen ?? []) console.log(`WARNUNG   ${w}`);
  for (const a of ergebnis.aussagen ?? []) console.log(`AUSSAGE   ${a.text}`);
  console.log(ergebnis.ok ? `\nErgebnis: ${okText}` : `\nErgebnis: ${schlechtText}`);
  if (ergebnis.stufe !== undefined) console.log(`Vertrauensstufe: ${ergebnis.stufe} von 2, ${ergebnis.stufeText}`);
  if (opts.bericht && art) console.log(`\n${berichtText(berichtErzeugen(art, ergebnis))}`);
  return ergebnis.ok ? 0 : 1;
}

async function pruefpunktBefehl(positional, opts) {
  if (!positional[0]) {
    console.log(HILFE);
    return 2;
  }
  const r = await pruefpunktPruefen(readFileSync(positional[0], "utf8"), opts);
  for (const c of r.checks) zeile(c.ok, c.label, c.detail);
  if (!(opts.zeugen ?? []).length) console.log("HINWEIS   Keine Zeugen festgelegt, die Gegenzeichnungen wurden nicht bewertet.");
  if (opts.bericht) console.log(`\n${berichtText(berichtErzeugen("pruefpunkt", { ...r, stufe: r.ok && opts.logSchluessel ? ((opts.zeugen ?? []).length && r.zeugenGueltig >= r.schwelle ? 2 : 1) : 0, stufeText: `${r.zeugenGueltig} gültige Gegenzeichnungen` }))}`);
  return r.ok ? 0 : 1;
}

async function konsistenzBefehl(positional, opts) {
  if (positional.length < 3 || !opts.logSchluessel) {
    console.log(HILFE);
    return 2;
  }
  const log = await schluesselLesen(opts.logSchluessel);
  const lesen = async (datei) => {
    const notiz = notizLesen(readFileSync(datei, "utf8"));
    const punkt = pruefpunktLesen(notiz.koerper);
    const sig = await signaturenPruefen(notiz, [log]);
    return { punkt, ok: sig.gueltig.length === 1 && log.name === punkt.origin };
  };
  const alt = await lesen(positional[0]);
  const neu = await lesen(positional[1]);
  zeile(alt.ok, "Alter Prüfpunkt trägt die Signatur des Protokolls", `Baumgröße ${alt.punkt.groesse}`);
  zeile(neu.ok, "Neuer Prüfpunkt trägt die Signatur des Protokolls", `Baumgröße ${neu.punkt.groesse}`);
  const beweis = JSON.parse(readFileSync(positional[2], "utf8"));
  const ok = await verifyConsistency({ oldSize: alt.punkt.groesse, newSize: neu.punkt.groesse, oldRoot: alt.punkt.wurzelHex, newRoot: neu.punkt.wurzelHex, proof: beweis.pfad ?? beweis });
  zeile(ok, "Das Protokoll ist vom alten zum neuen Prüfpunkt nur gewachsen, nichts wurde verändert oder entfernt", "");
  return alt.ok && neu.ok && ok ? 0 : 1;
}

async function dokumentBefehl(positional, opts, erwartet = null) {
  const [pfad, originalPfad] = positional;
  if (!pfad) {
    console.log(HILFE);
    return 2;
  }
  const doc = JSON.parse(readFileSync(pfad, "utf8"));
  const schema = doc?.schema;
  if (erwartet && schema !== erwartet) {
    console.log(`Das Dokument hat nicht das erwartete Format ${erwartet}.`);
    return 2;
  }
  if (schema === "defconder-aussage-1") return ausgeben(await aussagePruefen(doc, opts), "aussage", opts, "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen. Der Aussage ist nicht zu trauen.");
  if (schema === "defconder-entscheidung-1") return ausgeben(await entscheidungPruefen(doc, opts), "entscheidung", opts, "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen. Dem Nachweis ist nicht zu trauen.");
  if (schema === "defconder-widerspruch-1") {
    const r = await widerspruchPruefen(doc, opts);
    for (const c of r.checks) zeile(c.ok, c.label, c.detail);
    for (const w of r.warnungen ?? []) console.log(`WARNUNG   ${w}`);
    console.log(`\nErgebnis: ${r.text}`);
    return r.bewiesen ? 0 : 1;
  }
  const original = originalPfad ? new Uint8Array(readFileSync(originalPfad)) : null;
  const ergebnis = await verifyPackage(doc, { ...opts, originalBytes: original });
  const code = ausgeben(ergebnis, "paket", opts, "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen. Dem Paket ist nicht zu trauen.");
  console.log(`Schlüsselkennung des Betreibers: ${ergebnis.keyId ?? "keine"} (bitte auf anderem Weg mit der Angabe des Betreibers vergleichen)`);
  return code;
}

const [, , ersteres, ...rest] = process.argv;
if (!ersteres) {
  console.log(HILFE);
  process.exit(2);
}
const befehle = new Set(["paket", "aussage", "entscheidung", "widerspruch", "pruefpunkt", "konsistenz"]);
const befehl = befehle.has(ersteres) ? ersteres : "paket";
const { positional, opts } = optionen(befehle.has(ersteres) ? rest : [ersteres, ...rest]);
const erwartetesSchema = { aussage: "defconder-aussage-1", entscheidung: "defconder-entscheidung-1", widerspruch: "defconder-widerspruch-1" }[befehl] ?? null;
try {
  const code = befehl === "pruefpunkt" ? await pruefpunktBefehl(positional, opts) : befehl === "konsistenz" ? await konsistenzBefehl(positional, opts) : await dokumentBefehl(positional, opts, erwartetesSchema);
  process.exit(code);
} catch (err) {
  console.log(`Die Prüfung konnte nicht durchgeführt werden: ${err.message ?? err}`);
  process.exit(2);
}
