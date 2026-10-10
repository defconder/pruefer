import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { rootOfLeaves, leafHash, verifyConsistency, hex } from "../merkle.js";
import { pruefpunktPruefen } from "../pruefer-kern.js";
import { ereignisHashPruefen, auszugPruefen } from "../ereignis.js";
import { aussagePruefen, indexAufbauen, schluesselVon } from "../aussage.js";
import { bitcoinKopfPruefen } from "../zeitanker.js";
import { belegPruefen } from "../regeln.js";
import { slhPruefen } from "../slhdsa.js";
import { base64Decode } from "../note.js";
import { otsAuswerten, merkleWurzelAusKopf } from "../zeitbeweis.js";
import { ripemd160 } from "../ripemd160.js";
import { ziehen, obergrenze } from "../stichprobe.js";
import { unhex } from "../merkle.js";

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
let hashbasiert = 0;
let zeitbeweise = 0;
let stichproben = 0;
let zaehlvektoren = 0;
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
if (vektoren.hashbasiert) {
  for (const f of vektoren.hashbasiert.signaturen) {
    const oeffentlich = base64Decode(f.oeffentlich);
    const nachricht = new Uint8Array(f.nachricht.match(/../g).map((h) => parseInt(h, 16)));
    const signatur = base64Decode(f.signatur);
    pruefe(`Hashbasierte Signatur "${f.name}"`, slhPruefen(f.verfahren, oeffentlich, nachricht, signatur, f.kontext) === f.erwartet);
    if (f.erwartet) {
      for (const stelle of [0, 15, 16, 100, Math.floor(signatur.length / 2), signatur.length - 1]) {
        const kaputt = Uint8Array.from(signatur);
        kaputt[stelle] ^= 1;
        pruefe(`Hashbasierte Signatur "${f.name}": Veränderung an Stelle ${stelle} wird erkannt`, slhPruefen(f.verfahren, oeffentlich, nachricht, kaputt, f.kontext) === false);
      }
      pruefe(`Hashbasierte Signatur "${f.name}": andere Nachricht wird erkannt`, slhPruefen(f.verfahren, oeffentlich, Uint8Array.of(...nachricht, 1), signatur, f.kontext) === false);
      pruefe(`Hashbasierte Signatur "${f.name}": abgeschnittene Signatur wird erkannt`, slhPruefen(f.verfahren, oeffentlich, nachricht, signatur.slice(0, -1), f.kontext) === false);
    }
    hashbasiert += 1;
  }
  for (const f of vektoren.hashbasiert.pruefpunkte) {
    const r = await pruefpunktPruefen(f.text, { logSchluessel: f.logSchluessel, zeugen: f.zeugen, schwelle: f.schwelle, ...(f.logSchluesselPq ? { logSchluesselPq: f.logSchluesselPq } : {}) });
    pruefe(`Hashbasierter Prüfpunkt "${f.name}": Ergebnis`, r.ok === f.erwartet.bestanden, JSON.stringify(r.checks.filter((c) => !c.ok)));
    pruefe(`Hashbasierter Prüfpunkt "${f.name}": Zustand der hashbasierten Signatur`, r.pq === f.erwartet.pq, String(r.pq));
    hashbasiert += 1;
  }
}
if (vektoren.zeitbeweis) {
  for (const f of vektoren.zeitbeweis.ripemd160) {
    pruefe("RIPEMD-160", hex(ripemd160(unhex(f.eingabe))) === f.erwartet);
    zeitbeweise += 1;
  }
  for (const f of vektoren.zeitbeweis.faelle) {
    let r = null;
    let ok = true;
    try {
      r = await otsAuswerten(base64Decode(f.ots));
    } catch {
      ok = false;
    }
    pruefe(`Zeitbeweis "${f.name}": Ergebnis`, ok === f.erwartet.ok);
    if (ok && f.erwartet.ok) {
      pruefe(`Zeitbeweis "${f.name}": Prüfsumme`, hex(r.digest) === f.erwartet.digest);
      const ist = r.attestierungen.map((a) => (a.art === "bitcoin" ? { art: "bitcoin", hoehe: a.hoehe, nachricht: hex(a.nachricht) } : { art: a.art }));
      pruefe(`Zeitbeweis "${f.name}": Bestätigungen`, JSON.stringify(ist) === JSON.stringify(f.erwartet.attestierungen));
      if (f.kopf) pruefe(`Zeitbeweis "${f.name}": Wurzel im Blockkopf`, hex(merkleWurzelAusKopf(f.kopf.hex)) === ist[0].nachricht);
    }
    zeitbeweise += 1;
  }
}
if (vektoren.stichprobe) {
  for (const f of vektoren.stichprobe.ziehungen) {
    pruefe(`Ziehung aus ${f.groesse} Ereignissen mit ${f.anzahl} Ziehungen`, JSON.stringify(ziehen({ wurzelHex: f.wurzelHex, groesse: f.groesse, beaconHex: f.beaconHex, anzahl: f.anzahl })) === JSON.stringify(f.ergebnis));
    stichproben += 1;
  }
  for (const f of vektoren.stichprobe.schranken) {
    pruefe(`Obergrenze für ${f.anzahl} Ziehungen bei ${f.konfidenz}`, Math.abs(obergrenze(f.anzahl, f.konfidenz) - f.obergrenze) <= 1e-12 * Math.max(1, Math.abs(f.obergrenze)));
    stichproben += 1;
  }
}
if (vektoren.zaehlbeweis) {
  const z = vektoren.zaehlbeweis;
  for (const [i, e] of z.ereignisse.entries()) {
    pruefe(`Schlüsselmenge des Ereignisses ${i} unter den Indexregeln 1`, JSON.stringify([...schluesselVon(e)].sort()) === JSON.stringify(z.schluesselmengen[i].regeln1));
    pruefe(`Schlüsselmenge des Ereignisses ${i} unter den Indexregeln 2`, JSON.stringify([...schluesselVon(e, "indexregeln-2")].sort()) === JSON.stringify(z.schluesselmengen[i].regeln2));
    zaehlvektoren += 2;
  }
  const i1 = await indexAufbauen(z.ereignisse);
  const i2 = await indexAufbauen(z.ereignisse, "indexregeln-2");
  pruefe("Indexwurzel unter den Indexregeln 1", i1.wurzel === z.indexWurzel1 && i1.anzahl === z.indexAnzahl1);
  pruefe("Indexwurzel unter den Indexregeln 2", i2.wurzel === z.indexWurzel2 && i2.anzahl === z.indexAnzahl2);
  for (const f of z.faelle) {
    const r = await aussagePruefen(f.doc, { logSchluessel: z.logSchluessel, zeugen: z.zeugen, schwelle: f.schwelle });
    pruefe(`Zählprotokoll "${f.name}": Ergebnis`, r.ok === f.erwartet.ok, JSON.stringify(r.checks.filter((c) => !c.ok)));
    if (f.erwartet.ok) {
      pruefe(`Zählprotokoll "${f.name}": Stufe`, r.stufe === f.erwartet.stufe);
      pruefe(`Zählprotokoll "${f.name}": Anzahlen`, JSON.stringify(r.aussagen.map((a) => (a.art === "vorhanden" ? a.anzahl : null))) === JSON.stringify(f.erwartet.anzahlen));
    }
    zaehlvektoren += 1;
  }
  zaehlvektoren += 2;
}
console.log(fehler === 0 ? `Alle Testvektoren bestanden (${wurzeln} Wurzeln, ${konsistenz} Konsistenzbeweise, ${notizen} Prüfpunkte, ${ereignisse} Ereignisse, ${auszuege} Auszüge, ${aussagen} Aussagen, ${anker} Zeitanker, ${belege} Belege, ${hashbasiert} hashbasierte Signaturen und Prüfpunkte, ${zeitbeweise} Zeitbeweise, ${stichproben} Ziehungen und Schranken, ${zaehlvektoren} Vektoren zu den Indexregeln 2).` : `${fehler} Abweichung(en).`);
process.exit(fehler === 0 ? 0 : 1);
