import { sha256Bytes, hex } from "./merkle.js";
import { canonicalJson } from "./ereignis.js";

const encoder = new TextEncoder();
const MAX_STUFEN = 32;
const MAX_ZWECKE = 200;
const MAX_KATEGORIEN = 500;

export const REGELSPRACHE = "regeln-1";

function istTextListe(liste, max) {
  return Array.isArray(liste) && liste.length <= max && liste.every((t) => typeof t === "string" && t.length >= 1 && t.length <= 100) && new Set(liste).size === liste.length;
}

export function regelFormPruefen(regel) {
  if (!regel || typeof regel !== "object" || Array.isArray(regel)) return "Die Regel ist kein Objekt.";
  if (regel.sprache !== REGELSPRACHE) return "Unbekannte Regelsprache.";
  if (typeof regel.id !== "string" || regel.id.length === 0 || regel.id.length > 60) return "Die Regel hat keine Kennung.";
  if (regel.art === "stufen") {
    if (!Array.isArray(regel.stufen) || regel.stufen.length < 1 || regel.stufen.length > MAX_STUFEN) return "Die Stufen fehlen oder sind zu viele.";
    const ids = new Set();
    const tone = new Set();
    for (const s of regel.stufen) {
      if (!s || typeof s.id !== "string" || !Number.isInteger(s.ton)) return "Eine Stufe ist ungültig.";
      if (ids.has(s.id) || tone.has(s.ton)) return "Stufen oder Töne kommen doppelt vor.";
      ids.add(s.id);
      tone.add(s.ton);
    }
    return null;
  }
  if (regel.art === "matrix") {
    if (!regel.erlaubt || typeof regel.erlaubt !== "object" || Array.isArray(regel.erlaubt)) return "Die Zuordnung fehlt.";
    const zwecke = Object.keys(regel.erlaubt);
    if (zwecke.length > MAX_ZWECKE) return "Zu viele Zwecke.";
    for (const z of zwecke) if (!istTextListe(regel.erlaubt[z], MAX_KATEGORIEN)) return `Die Kategorien für den Zweck ${z} sind ungültig.`;
    if (!istTextListe(regel.immerErlaubt ?? [], MAX_KATEGORIEN)) return "Die Liste der immer erlaubten Kategorien ist ungültig.";
    return null;
  }
  return "Unbekannte Art der Regel.";
}

export function regelAuswerten(regel, eingaben) {
  const fehler = regelFormPruefen(regel);
  if (fehler) throw new Error(fehler);
  if (regel.art === "stufen") {
    const toene = new Set(regel.stufen.map((s) => s.ton));
    if (!eingaben || !toene.has(eingaben.nutzer) || !toene.has(eingaben.objekt)) throw new Error("Die Eingaben nennen keine bekannte Stufe.");
    const abstand = Math.max(0, eingaben.nutzer - eingaben.objekt);
    return { ergebnis: abstand === 0 ? "erlaubt" : "verweigert", abstand };
  }
  if (!eingaben || typeof eingaben.zweck !== "string") throw new Error("Die Eingaben nennen keinen Zweck.");
  const kategorie = eingaben.kategorie;
  if (kategorie === undefined || kategorie === null || kategorie === "" || (regel.immerErlaubt ?? []).includes(kategorie)) return { ergebnis: "erlaubt" };
  if (typeof kategorie !== "string") throw new Error("Die Kategorie ist ungültig.");
  return { ergebnis: (regel.erlaubt[eingaben.zweck] ?? []).includes(kategorie) ? "erlaubt" : "verweigert" };
}

export function regelEigenschaftenPruefen(regel) {
  const fehler = regelFormPruefen(regel);
  if (fehler) return { ok: false, grund: fehler, faelle: 0 };
  if (regel.art === "stufen") {
    const toene = regel.stufen.map((s) => s.ton);
    let faelle = 0;
    for (const nutzer of toene) {
      for (const objekt of toene) {
        const r = regelAuswerten(regel, { nutzer, objekt });
        faelle += 1;
        if (nutzer === objekt && r.ergebnis !== "erlaubt") return { ok: false, grund: "Dieselbe Stufe wird nicht erlaubt.", faelle };
        for (const mehr of toene.filter((t) => t <= nutzer)) {
          if (r.ergebnis === "erlaubt" && regelAuswerten(regel, { nutzer: mehr, objekt }).ergebnis !== "erlaubt") return { ok: false, grund: "Eine höhere Freigabe erlaubt weniger als eine niedrigere.", faelle };
        }
        for (const flacher of toene.filter((t) => t >= objekt)) {
          if (r.ergebnis === "erlaubt" && regelAuswerten(regel, { nutzer, objekt: flacher }).ergebnis !== "erlaubt") return { ok: false, grund: "Ein weniger geheimes Objekt wird verweigert, obwohl ein geheimeres erlaubt ist.", faelle };
        }
      }
    }
    return { ok: true, faelle, text: `Alle ${faelle} Kombinationen von Freigabe und Einstufung durchgerechnet: dieselbe Stufe ist erlaubt, eine höhere Freigabe erlaubt nie weniger, ein weniger geheimes Objekt wird nie strenger behandelt.` };
  }
  let faelle = 0;
  for (const zweck of Object.keys(regel.erlaubt)) {
    for (const kategorie of regel.erlaubt[zweck]) {
      faelle += 1;
      if (regelAuswerten(regel, { zweck, kategorie }).ergebnis !== "erlaubt") return { ok: false, grund: "Eine aufgeführte Kategorie wird nicht erlaubt.", faelle };
    }
    for (const kategorie of regel.immerErlaubt ?? []) {
      faelle += 1;
      if (regelAuswerten(regel, { zweck, kategorie }).ergebnis !== "erlaubt") return { ok: false, grund: "Eine immer erlaubte Kategorie wird verweigert.", faelle };
    }
  }
  return { ok: true, faelle, text: `Alle ${faelle} aufgeführten Zweck- und Kategorie-Paare durchgerechnet: jedes aufgeführte Paar ist erlaubt, jedes nicht aufgeführte wird verweigert.` };
}

export async function regelstandHash(regel) {
  return hex(await sha256Bytes(encoder.encode(canonicalJson(regel))));
}

export async function belegPruefen(beleg, regelstaende) {
  try {
    if (!beleg || typeof beleg !== "object") throw new Error("Der Beleg ist kein Objekt.");
    const regel = regelstaende.get(beleg.regelstand);
    if (!regel) throw new Error("Der Regelstand des Belegs ist nicht im Protokoll veröffentlicht.");
    if ((await regelstandHash(regel)) !== beleg.regelstand) throw new Error("Die Prüfsumme der Regel passt nicht zum Regelstand.");
    if (regel.id !== beleg.regel) throw new Error("Die Kennung der Regel passt nicht.");
    const eigenschaften = regelEigenschaftenPruefen(regel);
    if (!eigenschaften.ok) throw new Error(`Die Regel ist in sich nicht stimmig: ${eigenschaften.grund}`);
    const r = regelAuswerten(regel, beleg.eingaben);
    if (r.ergebnis !== beleg.ergebnis) throw new Error(`Die Regel ergibt ${r.ergebnis}, der Beleg behauptet ${beleg.ergebnis}.`);
    if (regel.art === "stufen" && r.abstand !== beleg.abstand) throw new Error("Der Abstand der Stufen passt nicht.");
    return { ok: true, regel: regel.id, ergebnis: r.ergebnis, eigenschaften };
  } catch (err) {
    return { ok: false, grund: String(err?.message ?? err) };
  }
}
