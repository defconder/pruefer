import { verifyInclusion } from "./merkle.js";
import { ereignisHashPruefen, auszugPruefen } from "./ereignis.js";
import { belegPruefen } from "./regeln.js";
import { pruefpunktPruefen } from "./pruefer-kern.js";
import { stufeBestimmen } from "./aussage.js";

const MAX_EINTRAEGE = 400;

async function ereignisLesen(eintrag) {
  if (eintrag.event && eintrag.auszug) return { ok: false, grund: "Ereignis und Auszug zugleich." };
  if (eintrag.auszug) {
    const a = await auszugPruefen(eintrag.auszug);
    if (!a.ok) return { ok: false, grund: a.grund };
    const offen = {};
    for (const o of a.offene) offen[o.name] = o.wert;
    const { seq, type, at, prevHash, hash } = eintrag.auszug.kopf;
    return { ok: true, ereignis: { ...offen, seq, type, at, prevHash, hash }, auszug: true };
  }
  const r = await ereignisHashPruefen(eintrag.event);
  return r.ok ? { ok: true, ereignis: eintrag.event, auszug: false } : { ok: false, grund: r.grund };
}

export async function entscheidungPruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form des Entscheidungsnachweises", false, text);
    return { ok: false, checks, warnungen, belege: [], stufe: 0, stufeText: "Nicht prüfbar" };
  };
  try {
    if (!doc || doc.schema !== "defconder-entscheidung-1") return abbruch("Unbekanntes Format.");
    if (typeof doc.notiz !== "string" || !Array.isArray(doc.ereignisse) || doc.ereignisse.length === 0 || doc.ereignisse.length > MAX_EINTRAEGE || !Number.isInteger(doc.seq)) return abbruch("Prüfpunkt, Ereignisse oder Folgenummer fehlen.");
    const festgelegt = Boolean(opts.logSchluessel);
    const logSchluessel = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof logSchluessel !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const punktErgebnis = await pruefpunktPruefen(doc.notiz, { ...opts, logSchluessel });
    for (const c of punktErgebnis.checks) add(`punkt_${c.id}`, c.label, c.ok, c.detail);
    if (!punktErgebnis.punkt) return { ok: false, checks, warnungen, belege: [], stufe: 0, stufeText: "Nicht bestanden" };
    const punkt = punktErgebnis.punkt;

    const ereignisse = new Map();
    let fehler = 0;
    const meldungen = [];
    for (const eintrag of doc.ereignisse) {
      if (!eintrag || typeof eintrag !== "object" || !Array.isArray(eintrag.pfad)) {
        fehler += 1;
        meldungen.push("Ein Eintrag hat nicht die erwartete Form.");
        continue;
      }
      const gelesen = await ereignisLesen(eintrag);
      if (!gelesen.ok) {
        fehler += 1;
        meldungen.push(gelesen.grund);
        continue;
      }
      const e = gelesen.ereignis;
      const drin = Number.isInteger(e.seq) && e.seq < punkt.groesse && (await verifyInclusion({ index: e.seq, treeSize: punkt.groesse, eventHash: e.hash, path: eintrag.pfad, rootHash: punkt.wurzelHex }));
      if (!drin || ereignisse.has(e.seq)) {
        fehler += 1;
        meldungen.push(`Ereignis ${e.seq}: Einschlussbeweis ungültig oder doppelt.`);
        continue;
      }
      ereignisse.set(e.seq, e);
    }
    add("ereignisse", `Prüfsumme und Einschluss der ${doc.ereignisse.length} Ereignisse im Protokoll des Prüfpunkts`, fehler === 0, meldungen.slice(0, 3).join(" "));

    const entscheidung = ereignisse.get(doc.seq);
    add("entscheidung", "Das Ereignis der Entscheidung liegt dem Nachweis bei", Boolean(entscheidung), entscheidung ? `${entscheidung.type}, Folgenummer ${entscheidung.seq}` : "Es fehlt.");
    const regelstaende = new Map();
    for (const e of ereignisse.values()) {
      if (e.type === "RegelstandVeroeffentlicht" && typeof e.regelstand === "string" && e.regel && e.seq < doc.seq) regelstaende.set(e.regelstand, e.regel);
    }
    const belege = [];
    if (entscheidung) {
      const liste = entscheidung.belege;
      add("belege", "Die Entscheidung trägt Belege", Array.isArray(liste) && liste.length > 0, Array.isArray(liste) ? "" : "Das Feld belege fehlt oder ist verdeckt.");
      if (Array.isArray(liste)) {
        for (const b of liste) {
          const r = await belegPruefen(b, regelstaende);
          let ok = r.ok;
          let detail = r.ok ? `${r.regel}: ${r.ergebnis}` : r.grund;
          if (ok && b.endgueltig !== undefined) {
            if (b.endgueltig !== "verweigert" || (b.grund !== "freigabestufe" && b.grund !== "formale-pruefung")) {
              ok = false;
              detail = "Endgültige Entscheidung oder Grund sind unbekannt.";
            } else if (b.grund === "freigabestufe" && r.ergebnis !== "verweigert") {
              ok = false;
              detail = "Als Grund steht die Freigabestufe, die Regel erlaubt aber.";
            } else if (b.grund === "formale-pruefung" && r.ergebnis !== "erlaubt") {
              ok = false;
              detail = "Als Grund steht die formale Prüfung, die Regel verweigert aber selbst.";
            } else if (b.grund === "formale-pruefung") {
              detail += " (die Regel erlaubt, die endgültige Verweigerung stammt aus der formalen Prüfung der Anwendung und lässt sich hier nicht nachrechnen)";
            }
          }
          if (ok && b.anzahl !== undefined && (!Number.isInteger(b.anzahl) || b.anzahl < 1)) {
            ok = false;
            detail = "Die Anzahl der Fälle ist ungültig.";
          }
          add("beleg", `Beleg zur Regel „${b?.regel ?? "?"}“ stimmt mit der veröffentlichten Regel überein${b?.anzahl ? ` (${b.anzahl} Fälle)` : ""}`, ok, detail);
          if (r.ok && r.eigenschaften) add("regel", `Regel „${r.regel}“ ist in sich stimmig`, r.eigenschaften.ok, r.eigenschaften.text);
          belege.push({ regel: b?.regel, ergebnis: b?.ergebnis, eingaben: b?.eingaben, anzahl: b?.anzahl, ok, detail });
        }
      }
    }
    warnungen.push("Der Nachweis zeigt, dass die Entscheidung der im Protokoll veröffentlichten Regel entspricht. Er zeigt nicht, dass die Eingaben (zum Beispiel die Freigabestufe eines Nutzers) richtig erfasst waren, und nicht, dass die Regel fachlich richtig ist.");
    if (!festgelegt) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Der Nachweis beweist nur, dass er in sich stimmig ist.");
    const intern = checks.every((c) => c.ok);
    const { stufe, stufeText } = stufeBestimmen(intern, festgelegt, punktErgebnis);
    if (intern && Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    return { ok: checks.every((c) => c.ok), checks, warnungen, belege, stufe, stufeText: checks.every((c) => c.ok) ? stufeText : "Nicht bestanden", punkt };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}
