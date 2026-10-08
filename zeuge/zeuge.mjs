import { createServer } from "node:http";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { notizLesen, pruefpunktLesen, schluesselLesen, signaturenPruefen, base64Decode, TYP_ED25519, TYP_KOSIGNATUR } from "../pruefer/note.js";
import { verifyConsistency, hex } from "../pruefer/merkle.js";

const EM_DASH = "\u2014";
const MAX_ANFRAGE = 200000;

function argumente(liste) {
  const opts = { logs: [], port: 8801, dir: "./zeuge-daten", name: null, host: "127.0.0.1" };
  for (let i = 0; i < liste.length; i += 1) {
    const a = liste[i];
    if (a === "--name") opts.name = liste[(i += 1)];
    else if (a === "--port") opts.port = Number(liste[(i += 1)]);
    else if (a === "--host") opts.host = liste[(i += 1)];
    else if (a === "--dir") opts.dir = liste[(i += 1)];
    else if (a === "--log") opts.logs.push(liste[(i += 1)]);
    else {
      console.log("Aufruf: node zeuge.mjs --name <Name des Zeugen> --log <Schluessel des Protokolls> [--log ...] [--port 8801] [--host 127.0.0.1] [--dir ./zeuge-daten]");
      process.exit(2);
    }
  }
  return opts;
}

export async function starteZeugen({ name, logs, dir, port, host = "127.0.0.1", jetzt = () => Math.floor(Date.now() / 1000) }) {
  if (!name || logs.length === 0) throw new Error("Name und mindestens ein Protokollschlüssel sind erforderlich.");
  const verzeichnis = resolve(dir);
  if (!existsSync(verzeichnis)) mkdirSync(verzeichnis, { recursive: true });
  const privPfad = join(verzeichnis, "zeuge.key");
  if (!existsSync(privPfad)) {
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(privPfad, privateKey.export({ type: "pkcs8", format: "pem" }));
    try {
      chmodSync(privPfad, 0o600);
    } catch {}
  }
  const privateKey = createPrivateKey(readFileSync(privPfad, "utf8"));
  const rawPub = createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32);
  const kennung = createHash("sha256").update(Buffer.concat([Buffer.from(name, "utf8"), Buffer.from([0x0a, TYP_KOSIGNATUR]), rawPub])).digest().subarray(0, 4);
  const vkey = `${name}+${kennung.toString("hex")}+${Buffer.concat([Buffer.from([TYP_KOSIGNATUR]), rawPub]).toString("base64")}`;

  const vertraute = new Map();
  for (const l of logs) {
    const s = await schluesselLesen(l);
    if (s.typ !== TYP_ED25519) throw new Error("Der Schlüssel eines Protokolls muss den Typ Ed25519 haben.");
    vertraute.set(s.name, s);
  }
  const zustandPfad = join(verzeichnis, "zustand.json");
  const zustand = existsSync(zustandPfad) ? JSON.parse(readFileSync(zustandPfad, "utf8")) : {};
  const speichern = () => {
    const temp = `${zustandPfad}.neu`;
    writeFileSync(temp, JSON.stringify(zustand));
    renameSync(temp, zustandPfad);
  };

  let sperre = Promise.resolve();
  const antworten = (res, status, text, typ = "text/plain; charset=utf-8") => {
    res.writeHead(status, { "Content-Type": typ });
    res.end(text);
  };

  async function verarbeiten(text) {
    const trennung = text.indexOf("\n\n");
    if (trennung < 0) return [400, "Anfrage ist unvollständig.\n"];
    const kopf = text.slice(0, trennung).split("\n");
    const altMatch = /^old (0|[1-9][0-9]*)$/.exec(kopf[0] ?? "");
    if (!altMatch) return [400, "Die erste Zeile muss old <Größe> lauten.\n"];
    const alt = Number(altMatch[1]);
    if (!Number.isSafeInteger(alt)) return [400, "Größe zu groß.\n"];
    const beweisZeilen = kopf.slice(1);
    if (beweisZeilen.length > 63) return [400, "Zu viele Beweiselemente.\n"];
    let beweis;
    try {
      beweis = beweisZeilen.map((z) => {
        const b = base64Decode(z);
        if (b.length !== 32) throw new Error("Hashlänge");
        return hex(b);
      });
    } catch {
      return [400, "Ein Beweiselement ist kein gültiges Base64 von 32 Byte.\n"];
    }
    let notiz;
    let punkt;
    try {
      notiz = notizLesen(text.slice(trennung + 2));
      punkt = pruefpunktLesen(notiz.koerper);
    } catch (err) {
      return [400, `Der Prüfpunkt ist ungültig: ${err.message}\n`];
    }
    const log = vertraute.get(punkt.origin);
    if (!log) return [404, "Dieses Protokoll ist unbekannt.\n"];
    const sig = await signaturenPruefen(notiz, [log]);
    if (sig.gueltig.length !== 1) return [403, "Keine gültige Signatur des Protokolls.\n"];
    if (alt > punkt.groesse) return [400, "Die alte Größe ist größer als die neue.\n"];
    const bekannt = zustand[punkt.origin] ?? { groesse: 0, wurzel: null };
    if (alt !== bekannt.groesse) return [409, `${bekannt.groesse}\n`, "text/x.tlog.size"];
    if (alt === 0) {
      if (beweis.length !== 0) return [422, "Bei alter Größe 0 ist kein Beweis erlaubt.\n"];
    } else {
      const ok = await verifyConsistency({ oldSize: alt, newSize: punkt.groesse, oldRoot: bekannt.wurzel, newRoot: punkt.wurzelHex, proof: beweis });
      if (!ok) return [422, "Der Konsistenzbeweis ist ungültig.\n"];
    }
    zustand[punkt.origin] = { groesse: punkt.groesse, wurzel: punkt.wurzelHex, zeit: jetzt() };
    speichern();
    const zeit = BigInt(jetzt());
    const nachricht = Buffer.from(`cosignature/v1\ntime ${zeit}\n${notiz.koerper}`, "utf8");
    const signatur = cryptoSign(null, nachricht, privateKey);
    const zeitBytes = Buffer.alloc(8);
    zeitBytes.writeBigUInt64BE(zeit);
    return [200, `${EM_DASH} ${name} ${Buffer.concat([kennung, zeitBytes, signatur]).toString("base64")}\n`];
  }

  const server = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/schluessel") return antworten(res, 200, `${vkey}\n`);
    if (req.method !== "POST" || !req.url?.endsWith("/add-checkpoint")) return antworten(res, 404, "Unbekannter Endpunkt.\n");
    const stuecke = [];
    let groesse = 0;
    req.on("data", (c) => {
      groesse += c.length;
      if (groesse > MAX_ANFRAGE) {
        antworten(res, 413, "Anfrage zu groß.\n");
        req.destroy();
      } else stuecke.push(c);
    });
    req.on("end", () => {
      sperre = sperre.then(async () => {
        try {
          const [status, text, typ] = await verarbeiten(Buffer.concat(stuecke).toString("utf8"));
          antworten(res, status, text, typ);
        } catch (err) {
          antworten(res, 500, `Interner Fehler: ${err.message}\n`);
        }
      });
    });
  });
  await new Promise((fertig) => server.listen(port, host, fertig));
  return { vkey, port: server.address().port, schliessen: () => new Promise((fertig) => server.close(fertig)), zustand };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"))) {
  const opts = argumente(process.argv.slice(2));
  const z = await starteZeugen(opts);
  console.log(`Zeuge ${opts.name} läuft auf ${opts.host}:${z.port}`);
  console.log(`Öffentlicher Schlüssel (an Prüfer und Betreiber weitergeben):\n${z.vkey}`);
}
