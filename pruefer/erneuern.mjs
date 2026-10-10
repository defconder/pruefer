import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { notizLesen, schluesselLesen, slhSchluesselText, TYP_SLH } from "./note.js";
import { slhNeuesSchluesselpaar, slhSignierenSchnell } from "./slhdsa-node.mjs";
import { canonicalJson } from "./pruefer-kern.js";
import { sha256Bytes, hex } from "./merkle.js";
import { ERNEUERUNG_SCHEMA, GLIED_SCHEMA, ERNEUERUNG_KONTEXT, gliedKern, gliedDigest } from "./erneuerung.js";
import { koepfeHolen } from "./zeitbeweis-bauen.mjs";
import { base64Encode } from "./note.js";

const HILFE = `Aufruf:
  node erneuern.mjs schluessel <Name> <sha2-128s|sha2-128f> --ausgabe <schluessel.json>
      erzeugt ein neues hashbasiertes Schlüsselpaar für Erneuerungen (die Datei enthält den geheimen Schlüssel, gut aufbewahren)
  node erneuern.mjs glied <pruefpunkt.txt> --schluessel-datei <schluessel.json> --ausgabe <erneuerung.json> [--erneuerung <bisherige.json>]
      hängt ein neues, signiertes Glied an (oder beginnt die Kette)
  node erneuern.mjs zeit <erneuerung.json> --glied <Nummer ab 1> --ots <datei.ots> [--quelle <Basisadresse>] --ausgabe <erneuerung.json>
      trägt den Zeitbeweis (nach ots stamp und ots upgrade über die Prüfsumme des Gliedes) ein
  node erneuern.mjs datei <erneuerung.json> --glied <Nummer ab 1> --ausgabe <glied.txt>
      schreibt den zu stempelnden Text des Gliedes in eine Datei, die Sie mit dem Werkzeug ots stempeln (ots stamp glied.txt, nach einigen Stunden ots upgrade glied.txt.ots)`;

export async function gliedErzeugen({ doc, pruefpunkt, schluesselDatei, zeit = Date.now() }) {
  const neu = doc ?? { schema: ERNEUERUNG_SCHEMA, notiz: pruefpunkt, glieder: [] };
  const vorher = neu.glieder.length === 0 ? hex(await sha256Bytes(new TextEncoder().encode(notizLesen(neu.notiz).koerper))) : hex(await gliedDigest(neu.glieder[neu.glieder.length - 1]));
  const glied = { schema: GLIED_SCHEMA, vorher, zeit, verfahren: schluesselDatei.verfahren, schluessel: schluesselDatei.vkey };
  const nachricht = Buffer.from(canonicalJson(gliedKern(glied)), "utf8");
  if (schluesselDatei.art === "slh") glied.signatur = Buffer.from(slhSignierenSchnell(schluesselDatei.verfahren, new Uint8Array(Buffer.from(schluesselDatei.geheim, "base64")), nachricht, ERNEUERUNG_KONTEXT)).toString("hex");
  else glied.signatur = cryptoSign(null, nachricht, createPrivateKey(schluesselDatei.pem)).toString("hex");
  neu.glieder.push(glied);
  return neu;
}

export async function neuerSchluessel(name, verfahren) {
  const paar = slhNeuesSchluesselpaar(verfahren);
  return { art: "slh", verfahren, vkey: await slhSchluesselText(name, verfahren, paar.oeffentlich), geheim: Buffer.from(paar.geheim).toString("base64") };
}

export async function zeitEintragen({ doc, nummer, ots, quelle, holen, mindestArbeitBits }) {
  const glied = doc.glieder[nummer - 1];
  if (!glied) throw new Error("Dieses Glied gibt es nicht.");
  const koepfe = await koepfeHolen(ots, { quelle, holen, mindestArbeitBits });
  glied.zeitbeweis = { ots: base64Encode(ots), koepfe };
  return doc;
}

if (process.argv[1]?.endsWith("erneuern.mjs")) {
  const [, , befehl, ...rest] = process.argv;
  const opt = { positional: [] };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--ausgabe") opt.ausgabe = rest[(i += 1)];
    else if (rest[i] === "--schluessel-datei") opt.schluesselDatei = rest[(i += 1)];
    else if (rest[i] === "--erneuerung") opt.erneuerung = rest[(i += 1)];
    else if (rest[i] === "--glied") opt.glied = Number(rest[(i += 1)]);
    else if (rest[i] === "--ots") opt.ots = rest[(i += 1)];
    else if (rest[i] === "--quelle") opt.quelle = rest[(i += 1)];
    else opt.positional.push(rest[i]);
  }
  try {
    if (befehl === "schluessel" && opt.positional.length === 2 && opt.ausgabe) {
      writeFileSync(opt.ausgabe, JSON.stringify(await neuerSchluessel(opt.positional[0], opt.positional[1]), null, 1), { mode: 0o600 });
      console.log(`Das Schlüsselpaar steht in ${opt.ausgabe}. Der öffentliche Schlüssel zum Festlegen beim Prüfen steht in der Datei unter vkey.`);
    } else if (befehl === "glied" && opt.positional[0] && opt.schluesselDatei && opt.ausgabe) {
      const doc = opt.erneuerung ? JSON.parse(readFileSync(opt.erneuerung, "utf8")) : null;
      const neu = await gliedErzeugen({ doc, pruefpunkt: readFileSync(opt.positional[0], "utf8"), schluesselDatei: JSON.parse(readFileSync(opt.schluesselDatei, "utf8")) });
      writeFileSync(opt.ausgabe, JSON.stringify(neu, null, 1));
      console.log(`Glied ${neu.glieder.length} steht in ${opt.ausgabe}. Stempeln Sie als Nächstes seine Prüfsumme (Befehl digest, dann ots stamp).`);
    } else if (befehl === "datei" && opt.positional[0] && opt.glied && opt.ausgabe) {
      const doc = JSON.parse(readFileSync(opt.positional[0], "utf8"));
      const glied = { ...doc.glieder[opt.glied - 1] };
      delete glied.zeitbeweis;
      writeFileSync(opt.ausgabe, canonicalJson(glied));
      console.log(`Der zu stempelnde Text steht in ${opt.ausgabe}. Stempeln Sie ihn mit: ots stamp ${opt.ausgabe}`);
    } else if (befehl === "zeit" && opt.positional[0] && opt.glied && opt.ots && opt.ausgabe) {
      const doc = JSON.parse(readFileSync(opt.positional[0], "utf8"));
      await zeitEintragen({ doc, nummer: opt.glied, ots: new Uint8Array(readFileSync(opt.ots)), quelle: opt.quelle });
      writeFileSync(opt.ausgabe, JSON.stringify(doc, null, 1));
      console.log(`Der Zeitbeweis steht an Glied ${opt.glied} in ${opt.ausgabe}.`);
    } else {
      console.log(HILFE);
      process.exit(2);
    }
  } catch (err) {
    console.log(`Das hat nicht geklappt: ${err.message ?? err}`);
    process.exit(1);
  }
}

export { schluesselLesen, TYP_SLH };
