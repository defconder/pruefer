import { createHash } from "node:crypto";
import { canonicalJson } from "../pruefer/pruefer-kern.js";
import { schluesselLesen } from "../pruefer/note.js";
import { ohneSignatur } from "../pruefer/freigabe.js";
import { huellenSchluessel, anteilMitSchluessel } from "./umschlag.mjs";

export const LIEFERUNG_SCHEMA = "defconder-lieferung-1";
const ANTEIL_KENNUNG = "defconder-anteil-1";
const MAX_TEILMENGEN = 5000;

const sha256Hex = (daten) => createHash("sha256").update(daten).digest("hex");

export function huellenHash(huelle) {
  return sha256Hex(Buffer.from(canonicalJson(huelle), "utf8"));
}

export function anteilPruefsumme(objektId, anteil) {
  return sha256Hex(Buffer.concat([Buffer.from(`${ANTEIL_KENNUNG}\0${objektId}\0`, "utf8"), Buffer.from(anteil)]));
}

export function pruefsummenErzeugen(objektId, anteile) {
  return Object.fromEntries(anteile.map((a) => [String(a[0]), anteilPruefsumme(objektId, a)]));
}

export async function lieferungPruefen(lieferung, huelle, hueterSchluesselText) {
  if (!lieferung || lieferung.schema !== LIEFERUNG_SCHEMA || typeof lieferung.signatur !== "string") return false;
  if (lieferung.huelle !== huellenHash(huelle)) return false;
  const s = await schluesselLesen(hueterSchluesselText);
  if (s.name !== lieferung.hueter) return false;
  try {
    const key = await globalThis.crypto.subtle.importKey("raw", s.publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(lieferung.signatur, "hex"), Buffer.from(canonicalJson(ohneSignatur(lieferung)), "utf8"));
  } catch {
    return false;
  }
}

export function anteileEmpfangen({ antworten, privat, anfrageHash, objektId, pruefsummen = null }) {
  const gut = [];
  const schlecht = [];
  for (const a of antworten) {
    const hueter = a?.daten?.quittung?.hueter ?? a?.hueter ?? "unbekannt";
    const { anteil: huelle, lieferung } = a?.daten ?? {};
    if (!huelle) {
      schlecht.push({ hueter, grund: "keine Hülle geliefert", beweisbar: false });
      continue;
    }
    let schluessel;
    let anteil;
    try {
      schluessel = huellenSchluessel(huelle, privat, anfrageHash);
      anteil = anteilMitSchluessel(huelle, schluessel, anfrageHash);
    } catch {
      schlecht.push({ hueter, grund: "Hülle nicht entschlüsselbar", beweisbar: false });
      continue;
    }
    if (pruefsummen) {
      const erwartet = pruefsummen[String(anteil[0])];
      if (!erwartet || erwartet !== anteilPruefsumme(objektId, anteil)) {
        schlecht.push({ hueter, grund: "Anteil passt nicht zur festgelegten Prüfsumme", beweisbar: Boolean(lieferung), beleg: lieferung ? { lieferung, huelle, schluessel, anfrageHash, objektId, index: anteil[0], erwartetePruefsumme: erwartet ?? null } : null });
        continue;
      }
    }
    gut.push({ hueter, anteil });
  }
  return { gut, schlecht };
}

export async function fehlverhaltenPruefen(beleg, hueterSchluesselText, { pruefsummen = null } = {}) {
  if (!beleg || !beleg.lieferung || !beleg.huelle) return { ok: false, grund: "Der Beleg ist unvollständig." };
  if (!(await lieferungPruefen(beleg.lieferung, beleg.huelle, hueterSchluesselText))) return { ok: false, grund: "Die Lieferung ist nicht vom Hüter unterschrieben oder gehört nicht zu dieser Hülle." };
  if (beleg.lieferung.anfrageHash !== beleg.anfrageHash || beleg.lieferung.objektId !== beleg.objektId) return { ok: false, grund: "Die Lieferung gehört zu einer anderen Anfrage." };
  let anteil;
  try {
    anteil = anteilMitSchluessel(beleg.huelle, beleg.schluessel, beleg.anfrageHash);
  } catch {
    return { ok: false, grund: "Mit dem genannten Schlüssel lässt sich die Hülle nicht öffnen. Das beweist nichts gegen den Hüter, denn der Schlüssel könnte falsch genannt sein." };
  }
  if (pruefsummen && pruefsummen[String(beleg.index)] !== beleg.erwartetePruefsumme) return { ok: false, grund: "Die im Beleg genannte Prüfsumme ist nicht die festgelegte." };
  if (anteil[0] !== beleg.index) return { ok: true, grund: "Der Hüter hat einen Anteil mit einer anderen Nummer geliefert, als er festgelegt war." };
  if (anteilPruefsumme(beleg.objektId, anteil) === beleg.erwartetePruefsumme) return { ok: false, grund: "Der Anteil stimmt mit der festgelegten Prüfsumme überein. Der Hüter hat richtig geliefert." };
  return { ok: true, grund: "Der Hüter hat unterschrieben, diese Hülle geliefert zu haben. Sie enthält einen Anteil, der nicht zur festgelegten Prüfsumme passt." };
}

function teilmengen(liste, k) {
  const ergebnis = [];
  const aktuell = [];
  const rekursiv = (start) => {
    if (ergebnis.length >= MAX_TEILMENGEN) return;
    if (aktuell.length === k) {
      ergebnis.push(aktuell.slice());
      return;
    }
    for (let i = start; i < liste.length; i += 1) {
      aktuell.push(liste[i]);
      rekursiv(i + 1);
      aktuell.pop();
    }
  };
  rekursiv(0);
  return ergebnis;
}

export function schluesselFinden({ anteile, schwelle, zusammensetzen, pruefe }) {
  for (const menge of teilmengen(anteile, schwelle)) {
    let geheimnis;
    try {
      geheimnis = zusammensetzen(menge.map((m) => m.anteil));
      if (pruefe(geheimnis)) {
        const benutzt = new Set(menge.map((m) => m.hueter));
        return { geheimnis, benutzt: [...benutzt], uebrig: anteile.filter((a) => !benutzt.has(a.hueter)).map((a) => a.hueter) };
      }
    } catch {}
  }
  return null;
}
