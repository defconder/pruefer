import { unhex, sha256Bytes, hex } from "./merkle.js";
import { schluesselLesen, TYP_ED25519, TYP_SLH } from "./note.js";
import { slhPruefen } from "./slhdsa.js";
import { canonicalJson } from "./pruefer-kern.js";

export const RELEASE_SCHEMA = "defconder-pruefer-release-1";
export const RELEASE_KONTEXT = "defconder-release-1";
const encoder = new TextEncoder();

async function signaturPruefen(schluessel, nachricht, signaturHex) {
  try {
    if (typeof signaturHex !== "string" || !/^[0-9a-f]+$/.test(signaturHex) || signaturHex.length % 2 !== 0) return false;
    const signatur = unhex(signaturHex);
    if (schluessel.typ === TYP_SLH) return slhPruefen(schluessel.verfahren, schluessel.publicKey, nachricht, signatur, RELEASE_KONTEXT);
    const key = await globalThis.crypto.subtle.importKey("raw", schluessel.publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, signatur, nachricht);
  } catch {
    return false;
  }
}

export async function releasePruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form der Veröffentlichungsangaben", false, text);
    return { ok: false, checks, warnungen, version: null };
  };
  try {
    const m = doc?.manifest;
    if (!m || m.schema !== RELEASE_SCHEMA || !Array.isArray(doc.signaturen) || doc.signaturen.length === 0 || doc.signaturen.length > 8) return abbruch("Unbekanntes Format.");
    if (!Array.isArray(opts.schluessel) || opts.schluessel.length === 0) return abbruch("Es ist kein Schlüssel der Veröffentlichung festgelegt. Ohne einen festgelegten Schlüssel beweist die Prüfung nichts.");
    const nachricht = encoder.encode(canonicalJson(m));
    const gesehen = new Set();
    for (const text of opts.schluessel) {
      const s = await schluesselLesen(text);
      if (s.typ !== TYP_ED25519 && s.typ !== TYP_SLH) throw new Error("Unzulässiger Schlüsseltyp.");
      const art = s.typ === TYP_SLH ? `hashbasiert (${s.verfahren})` : "Ed25519";
      const eintrag = doc.signaturen.find((x) => x?.schluessel === text.trim());
      const ok = Boolean(eintrag) && !gesehen.has(s.kennung) && (await signaturPruefen(s, nachricht, eintrag.signatur));
      gesehen.add(s.kennung);
      add(`signatur_${s.kennung}`, `Die Veröffentlichung trägt eine gültige ${art}-Signatur des festgelegten Schlüssels ${s.name}`, ok, ok ? "" : eintrag ? "Die Signatur ist ungültig." : "Es gibt keine Signatur dieses Schlüssels.");
    }
    if (opts.dateiBytes) {
      const h = hex(await sha256Bytes(opts.dateiBytes));
      add("datei", "Die Prüfsumme der vorliegenden Datei stimmt mit der unterschriebenen überein", h === m.htmlSha256, `berechnet ${h.slice(0, 16)}…, unterschrieben ${String(m.htmlSha256).slice(0, 16)}…`);
    }
    if (opts.summenBytes) {
      const h = hex(await sha256Bytes(opts.summenBytes));
      add("summen", "Die Liste der Prüfsummen aller Dateien stimmt mit der unterschriebenen überein", h === m.summenSha256, `berechnet ${h.slice(0, 16)}…, unterschrieben ${String(m.summenSha256).slice(0, 16)}…`);
    }
    if (!opts.dateiBytes && !opts.summenBytes) warnungen.push("Es wurde keine Datei zum Vergleichen angegeben. Geprüft ist nur, dass die Angaben unterschrieben sind.");
    const hybrid = opts.schluessel.length >= 2;
    if (!hybrid) warnungen.push("Es ist nur ein Schlüssel festgelegt. Mit einem Ed25519-Schlüssel und einem hashbasierten Schlüssel zugleich bleibt die Veröffentlichung auch gegenüber einem künftigen Quantencomputer geschützt.");
    warnungen.push("Die Unterschrift zeigt, dass die Veröffentlichung vom Inhaber der Schlüssel stammt. Dass der Quelltext in Ordnung ist, zeigt sie nicht, dafür gibt es die Quelle, die Testvektoren und den reproduzierbaren Bau.");
    return { ok: checks.every((c) => c.ok), checks, warnungen, version: m.version ?? null, hybrid };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}
