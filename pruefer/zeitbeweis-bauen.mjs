import { readFileSync, writeFileSync } from "node:fs";
import { notizLesen, base64Encode } from "./note.js";
import { otsAuswerten, ZEITBEWEIS_SCHEMA } from "./zeitbeweis.js";
import { bitcoinKopfPruefen } from "./zeitanker.js";

const HILFE = `Aufruf:
  node zeitbeweis-bauen.mjs koerper <pruefpunkt.txt> --ausgabe <koerper.txt>
      schreibt den signierten Text des Prüfpunkts in eine Datei, die Sie mit dem Werkzeug ots stempeln
      (ots stamp koerper.txt, nach einigen Stunden ots upgrade koerper.txt.ots)
  node zeitbeweis-bauen.mjs dokument <pruefpunkt.txt> <koerper.txt.ots> --ausgabe <zeitbeweis.json> [--quelle <Basisadresse>] [--log-schluessel <Schluessel>]
      holt die Blockköpfe, auf die der Beweis verweist, und baut das prüfbare Dokument
Voreinstellung für --quelle: https://blockstream.info/api`;

export async function holeText(url) {
  const antwort = await fetch(url, { signal: AbortSignal.timeout(10000), headers: { Accept: "text/plain" } });
  if (!antwort.ok) throw new Error(`${url} antwortete mit ${antwort.status}`);
  return (await antwort.text()).trim();
}

export async function koepfeHolen(ots, { quelle = "https://blockstream.info/api", mindestArbeitBits = 64, holen = holeText } = {}) {
  const auswertung = await otsAuswerten(ots);
  const koepfe = {};
  for (const a of auswertung.attestierungen) {
    if (a.art !== "bitcoin" || koepfe[a.hoehe]) continue;
    const blockHash = await holen(`${quelle}/block-height/${a.hoehe}`);
    if (!/^[0-9a-f]{64}$/.test(blockHash)) throw new Error(`Unerwartete Antwort für die Blockhöhe ${a.hoehe}.`);
    const kopf = await holen(`${quelle}/block/${blockHash}/header`);
    const r = await bitcoinKopfPruefen(kopf, { mindestArbeitBits });
    if (!r.ok) throw new Error(`Blockkopf zu Höhe ${a.hoehe} ist ungültig: ${r.grund}`);
    if (r.blockHash !== blockHash) throw new Error(`Die Prüfsumme des Blockkopfs zu Höhe ${a.hoehe} passt nicht zur genannten Blockprüfsumme.`);
    koepfe[a.hoehe] = kopf;
  }
  if (Object.keys(koepfe).length === 0) throw new Error("Der Beweis enthält noch keine Bestätigung durch Bitcoin. Rüsten Sie ihn nach einigen Stunden mit ots upgrade auf.");
  return koepfe;
}

export async function dokumentBauen({ pruefpunkt, ots, quelle = "https://blockstream.info/api", logSchluessel = null, mindestArbeitBits = 64, holen = holeText }) {
  notizLesen(pruefpunkt);
  const koepfe = await koepfeHolen(ots, { quelle, mindestArbeitBits, holen });
  return { schema: ZEITBEWEIS_SCHEMA, ...(logSchluessel ? { logSchluessel } : {}), notiz: pruefpunkt, ots: base64Encode(ots), koepfe };
}

if (process.argv[1]?.endsWith("zeitbeweis-bauen.mjs")) {
  const [, , befehl, ...rest] = process.argv;
  const opt = { positional: [] };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--ausgabe") opt.ausgabe = rest[(i += 1)];
    else if (rest[i] === "--quelle") opt.quelle = rest[(i += 1)];
    else if (rest[i] === "--log-schluessel") opt.logSchluessel = rest[(i += 1)];
    else opt.positional.push(rest[i]);
  }
  try {
    if (befehl === "koerper" && opt.positional[0] && opt.ausgabe) {
      writeFileSync(opt.ausgabe, notizLesen(readFileSync(opt.positional[0], "utf8")).koerper);
      console.log(`Der signierte Text steht in ${opt.ausgabe}. Stempeln Sie ihn jetzt mit: ots stamp ${opt.ausgabe}`);
    } else if (befehl === "dokument" && opt.positional.length === 2 && opt.ausgabe) {
      const doc = await dokumentBauen({ pruefpunkt: readFileSync(opt.positional[0], "utf8"), ots: new Uint8Array(readFileSync(opt.positional[1])), quelle: opt.quelle, logSchluessel: opt.logSchluessel });
      writeFileSync(opt.ausgabe, JSON.stringify(doc, null, 1));
      console.log(`Das Dokument steht in ${opt.ausgabe}. Prüfen Sie es mit: node pruefer.mjs zeitbeweis ${opt.ausgabe} --log-schluessel <Schluessel>`);
    } else {
      console.log(HILFE);
      process.exit(2);
    }
  } catch (err) {
    console.log(`Das Dokument konnte nicht gebaut werden: ${err.message ?? err}`);
    process.exit(1);
  }
}
