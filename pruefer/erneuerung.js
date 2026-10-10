import { unhex, sha256Bytes, hex } from "./merkle.js";
import { schluesselLesen, notizLesen, base64Decode, TYP_ED25519, TYP_SLH } from "./note.js";
import { slhPruefen } from "./slhdsa.js";
import { bitcoinKopfPruefen, STANDARD_MINDESTARBEIT_BITS } from "./zeitanker.js";
import { otsAuswerten, merkleWurzelAusKopf } from "./zeitbeweis.js";
import { pruefpunktPruefen, canonicalJson } from "./pruefer-kern.js";
import { stufeBestimmen } from "./aussage.js";

export const ERNEUERUNG_SCHEMA = "defconder-erneuerung-1";
export const GLIED_SCHEMA = "defconder-erneuerungsglied-1";
export const ERNEUERUNG_KONTEXT = "defconder-erneuerung-1";
const encoder = new TextEncoder();
const MAX_GLIEDER = 64;
const ZWEI_STUNDEN_MS = 2 * 60 * 60 * 1000;

export function gliedKern(glied) {
  const kopie = { ...glied };
  delete kopie.signatur;
  delete kopie.zeitbeweis;
  return kopie;
}

export async function gliedDigest(glied) {
  const ohneZeit = { ...glied };
  delete ohneZeit.zeitbeweis;
  return sha256Bytes(encoder.encode(canonicalJson(ohneZeit)));
}

export function verfahrenVon(schluessel) {
  return schluessel.typ === TYP_SLH ? `slh-dsa-${schluessel.verfahren}` : "ed25519";
}

async function signaturPruefen(schluessel, nachricht, signaturHex) {
  try {
    if (typeof signaturHex !== "string" || !/^[0-9a-f]+$/.test(signaturHex) || signaturHex.length % 2 !== 0) return false;
    const signatur = unhex(signaturHex);
    if (schluessel.typ === TYP_SLH) return slhPruefen(schluessel.verfahren, schluessel.publicKey, nachricht, signatur, ERNEUERUNG_KONTEXT);
    const key = await globalThis.crypto.subtle.importKey("raw", schluessel.publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, signatur, nachricht);
  } catch {
    return false;
  }
}

async function zeitFuer(digest, glied, opts) {
  const z = glied.zeitbeweis;
  if (!z || typeof z.ots !== "string" || typeof z.koepfe !== "object" || z.koepfe === null) return { fehlt: true };
  const ots = await otsAuswerten(base64Decode(z.ots));
  if (hex(ots.digest) !== hex(digest)) return { fehler: "Der Zeitbeweis bezieht sich nicht auf dieses Glied." };
  let bester = null;
  for (const a of ots.attestierungen) {
    if (a.art !== "bitcoin") continue;
    const kopfHex = z.koepfe[String(a.hoehe)];
    if (typeof kopfHex !== "string") continue;
    const kopf = await bitcoinKopfPruefen(kopfHex, { mindestArbeitBits: opts.mindestArbeitBits ?? STANDARD_MINDESTARBEIT_BITS });
    if (!kopf.ok || hex(merkleWurzelAusKopf(kopfHex)) !== hex(a.nachricht)) continue;
    if (!bester || kopf.blockZeit < bester.blockZeit) bester = { hoehe: a.hoehe, blockZeit: kopf.blockZeit };
  }
  if (!bester) return { fehler: "Keine gültige Bestätigung durch Bitcoin." };
  return { spaetestens: bester.blockZeit + ZWEI_STUNDEN_MS, hoehe: bester.hoehe };
}

export async function erneuerungPruefen(doc, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const abbruch = (text) => {
    add("format", "Form der Beweiserneuerung", false, text);
    return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht prüfbar", glieder: [] };
  };
  try {
    if (!doc || doc.schema !== ERNEUERUNG_SCHEMA) return abbruch("Unbekanntes Format.");
    if (typeof doc.notiz !== "string" || !Array.isArray(doc.glieder) || doc.glieder.length === 0 || doc.glieder.length > MAX_GLIEDER) return abbruch("Prüfpunkt oder Glieder fehlen.");
    const festgelegt = Boolean(opts.logSchluessel);
    const logSchluessel = opts.logSchluessel ?? doc.logSchluessel;
    if (typeof logSchluessel !== "string") return abbruch("Es steht kein Schlüssel des Protokolls zur Verfügung.");
    const punktErgebnis = await pruefpunktPruefen(doc.notiz, { ...opts, logSchluessel });
    for (const c of punktErgebnis.checks) add(`punkt_${c.id}`, c.label, c.ok, c.detail);
    if (!punktErgebnis.punkt) return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht bestanden", glieder: [] };

    const vertraut = new Map();
    for (const text of [opts.logSchluessel, opts.logSchluesselPq, ...(opts.erneuerungsSchluessel ?? [])]) {
      if (typeof text !== "string") continue;
      const s = await schluesselLesen(text);
      vertraut.set(`${s.name}|${s.kennung}`, s);
    }
    const gebunden = (opts.erneuerungsSchluessel ?? []).length > 0 || Boolean(opts.logSchluesselPq);

    let vorher = hex(await sha256Bytes(encoder.encode(notizLesen(doc.notiz).koerper)));
    let letzteZeit = -1;
    const ergebnisse = [];
    for (const [i, g] of doc.glieder.entries()) {
      const name = `Glied ${i + 1}`;
      if (!g || g.schema !== GLIED_SCHEMA || typeof g.schluessel !== "string" || !Number.isInteger(g.zeit) || typeof g.vorher !== "string") {
        add("glied", `${name} hat die erwartete Form`, false, "");
        break;
      }
      const verkettet = g.vorher === vorher;
      add("glied_kette", `${name} nennt die Prüfsumme des ${i === 0 ? "ursprünglichen Prüfpunkttextes" : "vorigen Gliedes"}`, verkettet, verkettet ? "" : "Die Kette ist unterbrochen.");
      let schluessel = null;
      try {
        schluessel = await schluesselLesen(g.schluessel);
      } catch (err) {
        add("glied_schluessel", `${name}: Der Schlüssel ist lesbar`, false, String(err.message ?? err));
      }
      const bekannt = schluessel && vertraut.has(`${schluessel.name}|${schluessel.kennung}`);
      if (schluessel) add("glied_schluessel", `${name}: Der Schlüssel (${verfahrenVon(schluessel)}) gehört zu den festgelegten Schlüsseln`, bekannt || !gebunden, bekannt ? "" : "Der Schlüssel ist nicht festgelegt.");
      const sigOk = schluessel ? await signaturPruefen(schluessel, encoder.encode(canonicalJson(gliedKern(g))), g.signatur) : false;
      add("glied_signatur", `${name}: Die Signatur ist gültig`, sigOk, "");
      const steigend = g.zeit > letzteZeit;
      add("glied_zeit", `${name}: Die genannte Zeit liegt nach der des vorigen Gliedes`, steigend, "");
      letzteZeit = g.zeit;
      let spaetestens = null;
      try {
        const z = await zeitFuer(await gliedDigest(g), g, opts);
        if (z.fehlt) warnungen.push(`${name} trägt keinen Zeitbeweis. Ohne ihn lässt sich nicht zeigen, dass die Erneuerung rechtzeitig geschah.`);
        else if (z.fehler) add("glied_zeitbeweis", `${name}: Der Zeitbeweis ist gültig`, false, z.fehler);
        else {
          spaetestens = z.spaetestens;
          add("glied_zeitbeweis", `${name} bestand spätestens am ${new Date(z.spaetestens).toISOString()} (Bitcoin-Block ${z.hoehe})`, true, "");
          if (g.zeit > z.spaetestens) add("glied_zeitpassung", `${name}: Die genannte Zeit liegt nicht nach dem bestätigten Zeitpunkt`, false, "Die genannte Zeit ist später als der Beweis zulässt.");
        }
      } catch (err) {
        add("glied_zeitbeweis", `${name}: Der Zeitbeweis ist lesbar`, false, String(err.message ?? err));
      }
      ergebnisse.push({ verfahren: schluessel ? verfahrenVon(schluessel) : null, zeit: g.zeit, spaetestens });
      vorher = hex(await gliedDigest(g));
    }

    if (opts.bruchAnnahme && typeof opts.bruchAnnahme === "object") {
      const verfahrenGebrochen = (v, zeitpunkt) => {
        const grenze = opts.bruchAnnahme[v];
        return grenze !== undefined && zeitpunkt >= grenze;
      };
      for (const [alt, grenze] of Object.entries(opts.bruchAnnahme)) {
        const schutz = ergebnisse.find((e) => e.verfahren && e.verfahren !== alt && e.spaetestens !== null && e.spaetestens <= grenze && !verfahrenGebrochen(e.verfahren, e.spaetestens));
        add("bruchfest", `Der Prüfpunkt war vor dem angenommenen Bruch von ${alt} (${new Date(grenze).toISOString().slice(0, 10)}) durch ein Glied anderer Art gesichert`, Boolean(schutz), schutz ? `${schutz.verfahren}, bestätigt spätestens ${new Date(schutz.spaetestens).toISOString()}` : "Kein Glied mit Zeitbeweis vor diesem Zeitpunkt.");
      }
    } else warnungen.push("Es wurde kein Zeitpunkt für den Bruch eines Verfahrens angenommen. Die Prüfung zeigt dann nur, dass die Kette in sich stimmt (Option --bruch).");

    warnungen.push("Die Erneuerung schützt davor, dass jemand nach dem Bruch eines Verfahrens einen Prüfpunkt rückdatiert. Sie zeigt nicht, dass der Inhalt des Prüfpunkts wahr ist.");
    if (!gebunden) warnungen.push("Es sind keine Schlüssel für die Erneuerung festgelegt. Die Kette zeigt nur, dass sie in sich stimmig ist, nicht, dass der Betreiber sie unterschrieben hat.");
    const intern = checks.every((c) => c.ok);
    let { stufe, stufeText } = stufeBestimmen(intern, festgelegt, punktErgebnis);
    if (!gebunden && stufe > 1) {
      stufe = 1;
      stufeText = "Prüfpunkt gebunden, Erneuerungsschlüssel nicht festgelegt";
    }
    if (intern && Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    const ok = checks.every((c) => c.ok);
    return { ok, checks, warnungen, stufe, stufeText: ok ? stufeText : "Nicht bestanden", glieder: ergebnisse, pq: punktErgebnis.pq, punkt: punktErgebnis.punkt };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}

export { TYP_ED25519 };
