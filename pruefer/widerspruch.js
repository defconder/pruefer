import { notizLesen, pruefpunktLesen, schluesselLesen, signaturenPruefen, TYP_ED25519 } from "./note.js";

export async function widerspruchPruefen(doc, opts = {}) {
  const checks = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form des Widerspruchsbeweises", false, text);
    return { ok: false, bewiesen: false, checks, text: "Nicht prüfbar." };
  };
  try {
    if (!doc || doc.schema !== "defconder-widerspruch-1") return abbruch("Unbekanntes Format.");
    if (typeof doc.a !== "string" || typeof doc.b !== "string") return abbruch("Es fehlen zwei Prüfpunkte.");
    const festgelegt = Boolean(opts.logSchluessel);
    const schluesselText = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof schluesselText !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const schluessel = await schluesselLesen(schluesselText);
    if (schluessel.typ !== TYP_ED25519) return abbruch("Der Schlüssel des Protokolls hat nicht den Typ Ed25519.");
    const lesen = async (text, name) => {
      const notiz = notizLesen(text);
      const punkt = pruefpunktLesen(notiz.koerper);
      const sig = await signaturenPruefen(notiz, [schluessel]);
      const ok = punkt.origin === schluessel.name && sig.gueltig.length === 1 && sig.fehlerhaft.length === 0;
      add(`signatur_${name}`, `Der Prüfpunkt ${name.toUpperCase()} trägt eine gültige Signatur des Protokolls`, ok, `Baumgröße ${punkt.groesse}, Wurzel ${punkt.wurzelHex.slice(0, 16)}…`);
      return punkt;
    };
    const a = await lesen(doc.a, "a");
    const b = await lesen(doc.b, "b");
    const gleicheGroesse = a.groesse === b.groesse;
    const verschiedeneWurzel = a.wurzelHex !== b.wurzelHex;
    add("widerspruch", "Beide Prüfpunkte haben dieselbe Baumgröße, aber verschiedene Wurzeln", gleicheGroesse && verschiedeneWurzel, gleicheGroesse ? (verschiedeneWurzel ? `Zwei verschiedene Wurzeln für Größe ${a.groesse}` : "Die Wurzeln sind gleich, es liegt kein Widerspruch vor.") : "Die Baumgrößen sind verschieden, das allein ist kein Widerspruch.");
    const signaturenOk = checks.filter((c) => c.id.startsWith("signatur_")).every((c) => c.ok);
    const bewiesen = signaturenOk && gleicheGroesse && verschiedeneWurzel;
    const warnungen = [];
    if (!festgelegt) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Der Beweis zeigt nur, dass zwei Prüfpunkte mit dem mitgelieferten Schlüssel unterschrieben wurden.");
    return {
      ok: checks.every((c) => c.ok),
      bewiesen,
      checks,
      warnungen,
      text: bewiesen ? `Bewiesen: Das Protokoll hat für die Baumgröße ${a.groesse} zwei verschiedene Wurzeln unterschrieben. Es erzählt verschiedenen Beobachtern verschiedene Wahrheiten.` : "Der Widerspruch ist nicht bewiesen.",
    };
  } catch (err) {
    return abbruch(String(err?.message ?? err));
  }
}
