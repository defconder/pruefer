import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { rootOfLeaves, leafHash, verifyConsistency, hex } from "../merkle.js";
import { pruefpunktPruefen } from "../pruefer-kern.js";
import { ereignisHashPruefen, auszugPruefen } from "../ereignis.js";
import { aussagePruefen, indexAufbauen } from "../aussage.js";
import { bitcoinKopfPruefen } from "../zeitanker.js";
import { belegPruefen } from "../regeln.js";

const here = dirname(fileURLToPath(import.meta.url));
const vektoren = JSON.parse(readFileSync(join(here, "testvektoren.json"), "utf8"));
let fehler = 0;
function pruefe(name, bedingung, detail = "") {
  if (!bedingung) {
    fehler += 1;
    console.log(`FEHLER ${name} ${detail}`);
  }
}

const blaetter = await Promise.all(vektoren.merkle.blaetter.map((h) => leafHash(h)));
let wurzeln = 0;
for (const [groesse, erwartet] of Object.entries(vektoren.merkle.wurzeln)) {
  const ist = hex(await rootOfLeaves(blaetter.slice(0, Number(groesse))));
  pruefe(`Wurzel für Größe ${groesse}`, ist === erwartet, `${ist} statt ${erwartet}`);
  wurzeln += 1;
}
let konsistenz = 0;
for (const v of vektoren.merkle.konsistenz) {
  const ok = await verifyConsistency({ oldSize: v.alt, newSize: v.neu, oldRoot: vektoren.merkle.wurzeln[String(v.alt)], newRoot: vektoren.merkle.wurzeln[String(v.neu)], proof: v.pfad });
  pruefe(`Konsistenz ${v.alt} nach ${v.neu}`, ok);
  konsistenz += 1;
}
let notizen = 0;
for (const f of vektoren.notizen.faelle) {
  const r = await pruefpunktPruefen(f.text, { logSchluessel: vektoren.notizen.logSchluessel, zeugen: vektoren.notizen.zeugen, schwelle: f.schwelle });
  if (f.erwartet.lesbar === false) {
    pruefe(`Prüfpunkt "${f.name}" wird als unlesbar abgelehnt`, r.punkt === null && r.ok === false);
  } else {
    pruefe(`Prüfpunkt "${f.name}": Ergebnis`, r.ok === f.erwartet.bestanden, JSON.stringify(r.checks));
    pruefe(`Prüfpunkt "${f.name}": Zahl der gültigen Zeugen`, r.zeugenGueltig === f.erwartet.zeugenGueltig || !r.punkt || !f.erwartet.logGueltig, String(r.zeugenGueltig));
    pruefe(`Prüfpunkt "${f.name}": Baumgröße`, r.punkt?.groesse === f.erwartet.groesse);
  }
  notizen += 1;
}

let ereignisse = 0;
let auszuege = 0;
let aussagen = 0;
let anker = 0;
let belege = 0;
if (vektoren.ereignis) {
  for (const f of vektoren.ereignis.faelle) {
    const r = await ereignisHashPruefen(f.event);
    pruefe(`Ereignis "${f.name}"`, r.ok === f.erwartet, r.grund);
    ereignisse += 1;
  }
  for (const f of vektoren.ereignis.auszuege) {
    const r = await auszugPruefen(f.auszug);
    pruefe(`Auszug "${f.name}": Ergebnis`, r.ok === f.erwartet.ok, r.grund);
    if (f.erwartet.ok) {
      pruefe(`Auszug "${f.name}": Prüfsumme`, r.hash === f.erwartet.hash);
      pruefe(`Auszug "${f.name}": offene Felder`, JSON.stringify(r.offene.map((o) => o.name).sort()) === JSON.stringify(f.erwartet.offene));
      pruefe(`Auszug "${f.name}": verdeckte Felder`, r.verdeckt === f.erwartet.verdeckt);
    }
    auszuege += 1;
  }
  const index = await indexAufbauen(vektoren.aussage.ereignisse);
  pruefe("Indexwurzel über die Ereignisse", index.wurzel === vektoren.aussage.indexWurzel, index.wurzel);
  pruefe("Zahl der Indexeinträge", index.anzahl === vektoren.aussage.indexAnzahl);
  for (const f of vektoren.aussage.faelle) {
    const r = await aussagePruefen(f.doc, { logSchluessel: vektoren.aussage.logSchluessel, zeugen: vektoren.aussage.zeugen, schwelle: f.schwelle });
    pruefe(`Aussage "${f.name}": Ergebnis`, r.ok === f.erwartet.ok, JSON.stringify(r.checks.filter((c) => !c.ok)));
    if (f.erwartet.ok) {
      pruefe(`Aussage "${f.name}": Stufe`, r.stufe === f.erwartet.stufe, String(r.stufe));
      pruefe(`Aussage "${f.name}": Anzahlen`, JSON.stringify(r.aussagen.map((a) => (a.art === "vorhanden" ? a.anzahl : null))) === JSON.stringify(f.erwartet.anzahlen));
    }
    aussagen += 1;
  }
  for (const f of vektoren.anker) {
    const r = await bitcoinKopfPruefen(f.kopf, { mindestArbeitBits: f.mindestarbeit });
    pruefe(`Zeitanker "${f.name}": Ergebnis`, r.ok === f.erwartet.ok, r.grund);
    if (f.erwartet.ok) {
      pruefe(`Zeitanker "${f.name}": Blockprüfsumme`, r.blockHash === f.erwartet.blockHash);
      pruefe(`Zeitanker "${f.name}": Blockzeit`, r.blockZeit === f.erwartet.blockZeit);
      pruefe(`Zeitanker "${f.name}": Arbeit`, r.arbeitBits === f.erwartet.arbeitBits);
    }
    anker += 1;
  }
  const regelstaende = new Map(Object.entries(vektoren.regeln.regelstaende));
  for (const f of vektoren.regeln.belege) {
    const r = await belegPruefen(f.beleg, regelstaende);
    pruefe(`Beleg "${f.name}"`, r.ok === f.erwartet, r.grund);
    belege += 1;
  }
}
console.log(fehler === 0 ? `Alle Testvektoren bestanden (${wurzeln} Wurzeln, ${konsistenz} Konsistenzbeweise, ${notizen} Prüfpunkte, ${ereignisse} Ereignisse, ${auszuege} Auszüge, ${aussagen} Aussagen, ${anker} Zeitanker, ${belege} Belege).` : `${fehler} Abweichung(en).`);
process.exit(fehler === 0 ? 0 : 1);
