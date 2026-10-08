import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { notizLesen, pruefpunktLesen, schluesselLesen } from "../pruefer/note.js";
import { verifyConsistency, rootOfLeaves, leafHash, hex } from "../pruefer/merkle.js";
import { pruefpunktPruefen } from "../pruefer/pruefer-kern.js";
import { ereignisHashPruefen } from "../pruefer/ereignis.js";
import { indexAufbauen, indexZeileLesen } from "../pruefer/aussage.js";
import { widerspruchPruefen } from "../pruefer/widerspruch.js";

const GENESIS = "0".repeat(64);
const ZEITLIMIT_MS = 15000;

async function standardHolen(url) {
  const antwort = await fetch(url, { signal: AbortSignal.timeout(ZEITLIMIT_MS) });
  return { status: antwort.status, text: await antwort.text() };
}

function sicher(text) {
  return String(text).replace(/token=[^&\s]+/g, "token=…");
}

export async function nachrechnen(logText, punktText) {
  const notiz = notizLesen(punktText);
  const punkt = pruefpunktLesen(notiz.koerper);
  const ereignisse = logText.split("\n").filter((z) => z.trim().length > 0).map((z) => JSON.parse(z));
  const alarme = [];
  const befunde = [];
  if (ereignisse.length < punkt.groesse) {
    alarme.push({ art: "log-zu-kurz", text: `Das mitgelieferte Protokoll hat nur ${ereignisse.length} Ereignisse, der Prüfpunkt deckt ${punkt.groesse}.` });
    return { alarme, befunde };
  }
  const deckung = ereignisse.slice(0, punkt.groesse);
  let vorher = GENESIS;
  for (const [i, e] of deckung.entries()) {
    const r = await ereignisHashPruefen(e);
    if (e.seq !== i || e.prevHash !== vorher || !r.ok) {
      alarme.push({ art: "kette", text: `Ereignis ${i}: Verkettung oder Prüfsumme stimmt nicht (${r.grund || "Vorgänger oder Folgenummer"}).` });
      return { alarme, befunde };
    }
    vorher = e.hash;
  }
  befunde.push(`Die Verkettung und die Prüfsumme aller ${deckung.length} Ereignisse stimmen.`);
  const blaetter = [];
  for (const e of deckung) blaetter.push(await leafHash(e.hash));
  const wurzel = hex(await rootOfLeaves(blaetter));
  if (wurzel !== punkt.wurzelHex) alarme.push({ art: "wurzel", text: `Die Wurzel aus den Ereignissen (${wurzel.slice(0, 16)}…) weicht von der Wurzel des Prüfpunkts (${punkt.wurzelHex.slice(0, 16)}…) ab.` });
  else befunde.push("Die Baumwurzel aus den Ereignissen entspricht der Wurzel im Prüfpunkt.");
  let indexZeile = null;
  try {
    indexZeile = indexZeileLesen(punkt.erweiterungen);
  } catch {
    befunde.push("Der Prüfpunkt enthält keinen Index, der Index wurde nicht geprüft.");
  }
  if (indexZeile) {
    const index = await indexAufbauen(deckung);
    if (index.wurzel !== indexZeile.wurzelHex || index.anzahl !== indexZeile.anzahl) alarme.push({ art: "index", text: `Der Index im Prüfpunkt lässt sich nicht aus dem Protokoll ableiten: berechnet ${index.anzahl} Einträge, Wurzel ${index.wurzel.slice(0, 16)}…, im Prüfpunkt ${indexZeile.anzahl} Einträge, Wurzel ${indexZeile.wurzelHex.slice(0, 16)}….` });
    else befunde.push(`Der Index mit ${index.anzahl} Einträgen wurde vollständig aus dem Protokoll nachgerechnet und stimmt mit dem Prüfpunkt überein.`);
  }
  return { alarme, befunde };
}

export async function beobachte({ quelle, logSchluessel, zeugen = [], schwelle, dir, holen = standardHolen, token = null, jetzt = () => Date.now(), feedPruefen = false, logDatei = null, mindestArbeitBits }) {
  const verzeichnis = resolve(dir);
  if (!existsSync(verzeichnis)) mkdirSync(verzeichnis, { recursive: true });
  const zustandPfad = join(verzeichnis, "zustand.json");
  const verlaufPfad = join(verzeichnis, "punkte.jsonl");
  const alarmPfad = join(verzeichnis, "alarme.jsonl");
  const basis = quelle.replace(/\/$/, "");
  const url = (pfad, abfrage = "") => {
    const teile = [];
    if (abfrage) teile.push(abfrage.slice(1));
    if (token) teile.push(`token=${encodeURIComponent(token)}`);
    return `${basis}${pfad}${teile.length ? `?${teile.join("&")}` : ""}`;
  };
  const alarme = [];
  const befunde = [];
  const schluessel = await schluesselLesen(logSchluessel);

  const alarm = (art, text, beweis = null) => {
    const eintrag = { at: jetzt(), art, text, ...(beweis ? { beweis } : {}) };
    alarme.push(eintrag);
    appendFileSync(alarmPfad, `${JSON.stringify(eintrag)}\n`);
  };

  const antwort = await holen(url("/transparenz/pruefpunkt"));
  if (antwort.status !== 200) throw new Error(`Der Prüfpunkt war nicht abrufbar (${antwort.status}).`);
  const neuText = antwort.text;
  const pruefung = await pruefpunktPruefen(neuText, { logSchluessel, zeugen, schwelle, mindestArbeitBits });
  if (!pruefung.punkt) throw new Error("Der Prüfpunkt ist unlesbar.");
  const logOk = pruefung.checks.find((c) => c.id === "log")?.ok;
  if (!logOk) {
    alarm("signatur", "Der Prüfpunkt trägt keine gültige Signatur des festgelegten Protokollschlüssels.", { pruefpunkt: sicher(neuText) });
    return { ok: false, alarme, befunde, punkt: pruefung.punkt };
  }
  const neu = pruefung.punkt;
  befunde.push(`Prüfpunkt Größe ${neu.groesse}, Wurzel ${neu.wurzelHex.slice(0, 16)}…, Signatur des Protokolls gültig.`);
  if (zeugen.length > 0) {
    const zeugenCheck = pruefung.checks.find((c) => c.id === "zeugen");
    befunde.push(zeugenCheck?.ok ? `Gegenzeichnung: ${zeugenCheck.label}.` : "Die verlangten Gegenzeichnungen der Zeugen liegen für diesen Prüfpunkt nicht vollständig vor.");
    if (!zeugenCheck?.ok) alarm("zeugen", "Zu wenige gültige Gegenzeichnungen der festgelegten Zeugen.", { pruefpunkt: neuText });
  }
  const zeitCheck = pruefung.checks.find((c) => c.id === "zeitanker");
  if (zeitCheck && !zeitCheck.ok) alarm("zeitanker", `Der Zeitanker im Prüfpunkt ist nicht annehmbar: ${zeitCheck.detail}`, { pruefpunkt: neuText });

  const verlauf = existsSync(verlaufPfad) ? readFileSync(verlaufPfad, "utf8").split("\n").filter(Boolean).map((z) => JSON.parse(z)) : [];
  for (const alt of verlauf) {
    if (alt.groesse === neu.groesse && alt.wurzelHex !== neu.wurzelHex) {
      const beweis = { schema: "defconder-widerspruch-1", logSchluessel, a: alt.text, b: neuText };
      const geprueft = await widerspruchPruefen(beweis, { logSchluessel });
      alarm("zwei-wahrheiten", `Für die Baumgröße ${neu.groesse} wurden zwei verschiedene Wurzeln unterschrieben. ${geprueft.bewiesen ? "Das ist kryptografisch bewiesen." : "Der Beweis ließ sich nicht bestätigen."}`, beweis);
    }
  }

  const zustand = existsSync(zustandPfad) ? JSON.parse(readFileSync(zustandPfad, "utf8")) : null;
  let neuerStand = true;
  if (zustand) {
    if (neu.groesse < zustand.groesse) {
      alarm("ruecksetzung", `Der Prüfpunkt ist kleiner (${neu.groesse}) als ein früher gesehener (${zustand.groesse}). Das Protokoll wurde zurückgesetzt oder verkürzt.`, { frueher: zustand.text, jetzt: neuText });
      neuerStand = false;
    } else if (neu.groesse === zustand.groesse) {
      neuerStand = false;
      if (neu.wurzelHex === zustand.wurzelHex) befunde.push("Seit der letzten Beobachtung hat sich nichts geändert.");
    } else {
      const k = await holen(url("/transparenz/konsistenz", `?von=${zustand.groesse}&bis=${neu.groesse}`));
      let ok = false;
      if (k.status === 200) {
        try {
          const antwortK = JSON.parse(k.text);
          ok = await verifyConsistency({ oldSize: zustand.groesse, newSize: neu.groesse, oldRoot: zustand.wurzelHex, newRoot: neu.wurzelHex, proof: antwortK.pfad });
        } catch {
          ok = false;
        }
      }
      if (ok) befunde.push(`Der neue Stand (${neu.groesse}) setzt den früher gesehenen (${zustand.groesse}) lückenlos fort. Konsistenzbeweis gültig.`);
      else {
        alarm("konsistenz", `Der neue Stand (${neu.groesse}) lässt sich nicht aus dem früher gesehenen (${zustand.groesse}) ableiten. Das Protokoll wurde verändert oder lieferte keinen gültigen Beweis.`, { frueher: zustand.text, jetzt: neuText, antwort: sicher(k.text.slice(0, 2000)) });
        neuerStand = false;
      }
    }
  } else befunde.push("Erste Beobachtung. Ab jetzt wird jeder neue Stand gegen diesen geprüft.");

  if (!verlauf.some((v) => v.groesse === neu.groesse && v.wurzelHex === neu.wurzelHex)) appendFileSync(verlaufPfad, `${JSON.stringify({ groesse: neu.groesse, wurzelHex: neu.wurzelHex, text: neuText, gesehen: jetzt() })}\n`);

  if (feedPruefen) {
    const feed = await holen(url("/transparenz/feed"));
    if (feed.status === 200) {
      const eintraege = feed.text.split("\n").filter(Boolean).map((z) => JSON.parse(z));
      let vorheriger = null;
      let geprueft = 0;
      for (const e of eintraege) {
        const p = pruefpunktLesen(notizLesen(e.notiz).koerper);
        const sig = await pruefpunktPruefen(e.notiz, { logSchluessel });
        if (!sig.checks.find((c) => c.id === "log")?.ok) {
          alarm("feed-signatur", `Ein Eintrag der veröffentlichten Liste (Größe ${p.groesse}) trägt keine gültige Signatur.`, { eintrag: e.notiz });
          continue;
        }
        if (vorheriger && p.groesse > vorheriger.groesse) {
          const k = await holen(url("/transparenz/konsistenz", `?von=${vorheriger.groesse}&bis=${p.groesse}`));
          let ok = false;
          if (k.status === 200) {
            try {
              ok = await verifyConsistency({ oldSize: vorheriger.groesse, newSize: p.groesse, oldRoot: vorheriger.wurzelHex, newRoot: p.wurzelHex, proof: JSON.parse(k.text).pfad });
            } catch {
              ok = false;
            }
          }
          if (!ok) alarm("feed-konsistenz", `In der veröffentlichten Liste folgt Größe ${p.groesse} nicht lückenlos auf Größe ${vorheriger.groesse}.`, { a: vorheriger.text, b: e.notiz });
        } else if (vorheriger && p.groesse === vorheriger.groesse && p.wurzelHex !== vorheriger.wurzelHex) {
          alarm("feed-widerspruch", `In der veröffentlichten Liste stehen für Größe ${p.groesse} zwei verschiedene Wurzeln.`, { schema: "defconder-widerspruch-1", logSchluessel, a: vorheriger.text, b: e.notiz });
        }
        vorheriger = { ...p, text: e.notiz };
        geprueft += 1;
      }
      befunde.push(`Die veröffentlichte Liste mit ${geprueft} Prüfpunkten wurde Eintrag für Eintrag auf Signatur und Fortsetzung geprüft.`);
    } else befunde.push(`Die veröffentlichte Liste war nicht abrufbar (${feed.status}).`);
  }

  if (logDatei) {
    const r = await nachrechnen(readFileSync(logDatei, "utf8"), neuText);
    befunde.push(...r.befunde);
    for (const a of r.alarme) alarm(a.art, a.text, { pruefpunkt: neuText });
  }

  if (neuerStand && alarme.length === 0) {
    const temp = `${zustandPfad}.neu`;
    writeFileSync(temp, JSON.stringify({ groesse: neu.groesse, wurzelHex: neu.wurzelHex, text: neuText, gesehen: jetzt() }));
    renameSync(temp, zustandPfad);
  }
  return { ok: alarme.length === 0, alarme, befunde, punkt: neu };
}

function argumente(liste) {
  const opts = { zeugen: [], dir: "./beobachter-daten", intervall: 300, einmal: false, feedPruefen: false, tlsPruefungAus: false };
  for (let i = 0; i < liste.length; i += 1) {
    const a = liste[i];
    if (a === "--quelle") opts.quelle = liste[(i += 1)];
    else if (a === "--log") opts.logSchluessel = liste[(i += 1)];
    else if (a === "--zeuge") opts.zeugen.push(liste[(i += 1)]);
    else if (a === "--schwelle") opts.schwelle = Number(liste[(i += 1)]);
    else if (a === "--dir") opts.dir = liste[(i += 1)];
    else if (a === "--token") opts.token = liste[(i += 1)];
    else if (a === "--intervall") opts.intervall = Number(liste[(i += 1)]);
    else if (a === "--nachrechnen") opts.logDatei = liste[(i += 1)];
    else if (a === "--einmal") opts.einmal = true;
    else if (a === "--feed-pruefen") opts.feedPruefen = true;
    else if (a === "--tls-pruefung-aus") opts.tlsPruefungAus = true;
    else {
      console.log("Aufruf: node beobachter.mjs --quelle <Adresse des Betreibers> --log <Schluessel des Protokolls> [--zeuge <Schluessel> ...] [--schwelle N] [--dir ./beobachter-daten] [--intervall Sekunden] [--einmal] [--feed-pruefen] [--nachrechnen <event-log.jsonl>] [--token <Sitzungstoken>] [--tls-pruefung-aus]");
      process.exit(2);
    }
  }
  if (!opts.quelle || !opts.logSchluessel) {
    console.log("Es fehlen --quelle und --log.");
    process.exit(2);
  }
  return opts;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"))) {
  const opts = argumente(process.argv.slice(2));
  if (opts.tlsPruefungAus) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    console.log("Warnung: Die Prüfung des TLS-Zertifikats ist abgeschaltet. Nur für lokale Versuche.");
  }
  const durchgang = async () => {
    try {
      const r = await beobachte(opts);
      console.log(`${new Date().toISOString()} ${r.ok ? "in Ordnung" : "ALARM"}`);
      for (const b of r.befunde) console.log(`  ${b}`);
      for (const a of r.alarme) console.log(`  ALARM ${a.art}: ${a.text}`);
      return r.ok ? 0 : 1;
    } catch (err) {
      console.log(`${new Date().toISOString()} Fehler: ${sicher(err.message)}`);
      return 2;
    }
  };
  if (opts.einmal) process.exit(await durchgang());
  await durchgang();
  setInterval(durchgang, Math.max(10, opts.intervall) * 1000);
}
