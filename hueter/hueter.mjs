import { createServer } from "node:http";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { verifyInclusion } from "../pruefer/merkle.js";
import { pruefpunktPruefen, canonicalJson } from "../pruefer/pruefer-kern.js";
import { ereignisLesen, QUITTUNG_SCHEMA, AUSKUNFT_SCHEMA } from "../pruefer/freigabe.js";
import { anteilVerschluesseln } from "./umschlag.mjs";

const MAX_ANFRAGE = 400000;
const STANDARD_TYPEN = ["ZugriffAngefragt"];

function argumente(liste) {
  const opts = { zeugen: [], typen: [], anteile: [], port: 8811, dir: "./hueter-daten", name: null, host: "127.0.0.1", zeugenSchwelle: null };
  for (let i = 0; i < liste.length; i += 1) {
    const a = liste[i];
    if (a === "--name") opts.name = liste[(i += 1)];
    else if (a === "--port") opts.port = Number(liste[(i += 1)]);
    else if (a === "--host") opts.host = liste[(i += 1)];
    else if (a === "--dir") opts.dir = liste[(i += 1)];
    else if (a === "--log") opts.logSchluessel = liste[(i += 1)];
    else if (a === "--zeuge") opts.zeugen.push(liste[(i += 1)]);
    else if (a === "--zeugen-schwelle") opts.zeugenSchwelle = Number(liste[(i += 1)]);
    else if (a === "--typ") opts.typen.push(liste[(i += 1)]);
    else if (a === "--mindestarbeit") opts.mindestArbeitBits = Number(liste[(i += 1)]);
    else if (a === "--anteil") opts.anteile.push(liste[(i += 1)]);
    else {
      console.log("Aufruf: node hueter.mjs --name <Name> --log <Schluessel des Protokolls> --zeuge <Schluessel> [--zeuge ...] --zeugen-schwelle N --anteil <Objekt>=<Anteil in Base64> [--anteil ...] [--typ ZugriffAngefragt] [--mindestarbeit 64] [--port 8811] [--host 127.0.0.1] [--dir ./hueter-daten]");
      process.exit(2);
    }
  }
  return opts;
}

export async function starteHueter({ name, logSchluessel, zeugen, zeugenSchwelle, anteile, dir, port, host = "127.0.0.1", erlaubteTypen = STANDARD_TYPEN, mindestArbeitBits, jetzt = () => Date.now() }) {
  if (!name || !logSchluessel || !Array.isArray(zeugen) || zeugen.length === 0 || !Number.isInteger(zeugenSchwelle) || zeugenSchwelle < 1) throw new Error("Name, Protokollschlüssel, Zeugen und deren Schwelle sind erforderlich. Ein Hüter, der keine bezeugten Prüfpunkte verlangt, schützt nichts.");
  const verzeichnis = resolve(dir);
  if (!existsSync(verzeichnis)) mkdirSync(verzeichnis, { recursive: true });
  const privPfad = join(verzeichnis, "hueter.key");
  if (!existsSync(privPfad)) {
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(privPfad, privateKey.export({ type: "pkcs8", format: "pem" }));
    try {
      chmodSync(privPfad, 0o600);
    } catch {}
  }
  const privateKey = createPrivateKey(readFileSync(privPfad, "utf8"));
  const rawPub = createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32);
  const kennung = createHash("sha256").update(Buffer.concat([Buffer.from(name, "utf8"), Buffer.from([0x0a, 0x01]), rawPub])).digest().subarray(0, 4);
  const vkey = `${name}+${kennung.toString("hex")}+${Buffer.concat([Buffer.from([0x01]), rawPub]).toString("base64")}`;
  const buchPfad = join(verzeichnis, "quittungen.jsonl");
  const quittungen = existsSync(buchPfad) ? readFileSync(buchPfad, "utf8").split("\n").filter(Boolean).map((z) => JSON.parse(z)) : [];
  const meineAnteile = new Map(Object.entries(anteile ?? {}).map(([objekt, text]) => [objekt, new Uint8Array(Buffer.from(text, "base64"))]));

  const signieren = (objekt) => ({ ...objekt, signatur: cryptoSign(null, Buffer.from(canonicalJson(objekt), "utf8"), privateKey).toString("hex") });
  let sperre = Promise.resolve();

  async function freigeben(koerper) {
    const { anfrage, notiz } = koerper ?? {};
    if (!anfrage || typeof notiz !== "string") return [400, { fehler: "Anfrage oder Prüfpunkt fehlen." }];
    const punktErgebnis = await pruefpunktPruefen(notiz, { logSchluessel, zeugen, schwelle: zeugenSchwelle, mindestArbeitBits });
    if (!punktErgebnis.ok || !punktErgebnis.punkt || punktErgebnis.zeugenGueltig < zeugenSchwelle) return [403, { fehler: "Der Prüfpunkt ist nicht von genug festgelegten Zeugen bestätigt." }];
    const punkt = punktErgebnis.punkt;
    const gelesen = await ereignisLesen(anfrage);
    if (!gelesen.ok) return [403, { fehler: `Die Anfrage ist kein gültiges Ereignis: ${gelesen.grund}` }];
    const e = gelesen.ereignis;
    const drin = Number.isInteger(e.seq) && e.seq < punkt.groesse && Array.isArray(anfrage.pfad) && (await verifyInclusion({ index: e.seq, treeSize: punkt.groesse, eventHash: e.hash, path: anfrage.pfad, rootHash: punkt.wurzelHex }));
    if (!drin) return [403, { fehler: "Die Anfrage steht nicht im Protokoll des bezeugten Prüfpunkts." }];
    if (!erlaubteTypen.includes(e.type)) return [403, { fehler: `Ein Ereignis vom Typ ${String(e.type).slice(0, 40)} gilt nicht als Anfrage.` }];
    if (typeof e.objectId !== "string" || typeof e.empfaengerSchluessel !== "string") return [403, { fehler: "Die Anfrage nennt kein Objekt oder keinen Empfängerschlüssel." }];
    const anteil = meineAnteile.get(e.objectId);
    if (!anteil) return [404, { fehler: "Zu diesem Objekt hält dieser Hüter keinen Anteil." }];
    let quittung = quittungen.find((q) => q.anfrageHash === e.hash && q.objektId === e.objectId);
    if (!quittung) {
      quittung = signieren({ schema: QUITTUNG_SCHEMA, hueter: name, anfrageHash: e.hash, seq: e.seq, objektId: e.objectId, nutzerId: typeof e.userId === "string" ? e.userId : null, groesse: punkt.groesse, wurzel: punkt.wurzelHex, at: jetzt(), anteil: anteil[0] });
      appendFileSync(buchPfad, `${JSON.stringify(quittung)}\n`);
      quittungen.push(quittung);
    }
    let huelle;
    try {
      huelle = anteilVerschluesseln(Buffer.from(anteil), e.empfaengerSchluessel, e.hash);
    } catch (err) {
      return [403, { fehler: `Der Empfängerschlüssel ist unbrauchbar: ${err.message}` }];
    }
    return [200, { quittung, anteil: huelle }];
  }

  function auskunft(objektId) {
    const liste = quittungen.filter((q) => q.objektId === objektId).map((q) => ({ anfrageHash: q.anfrageHash, at: q.at }));
    return signieren({ schema: AUSKUNFT_SCHEMA, hueter: name, objektId, quittungen: liste, bis: jetzt(), anzahlGesamt: quittungen.length });
  }

  const server = createServer((req, res) => {
    const antwort = (status, objekt) => {
      res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(objekt));
    };
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && url.pathname === "/auskunft") {
      const objekt = url.searchParams.get("objekt");
      if (!objekt || objekt.length > 200) return antwort(400, { fehler: "Objekt fehlt." });
      return antwort(200, auskunft(objekt));
    }
    if (req.method === "GET" && url.pathname === "/schluessel") return antwort(200, { vkey });
    if (req.method !== "POST" || url.pathname !== "/freigabe") return antwort(404, { fehler: "Unbekannter Pfad." });
    const teile = [];
    let laenge = 0;
    req.on("data", (t) => {
      laenge += t.length;
      if (laenge > MAX_ANFRAGE) {
        antwort(413, { fehler: "Anfrage zu groß." });
        req.destroy();
      } else teile.push(t);
    });
    req.on("end", () => {
      if (laenge > MAX_ANFRAGE) return;
      sperre = sperre.then(async () => {
        try {
          const [status, objekt] = await freigeben(JSON.parse(Buffer.concat(teile).toString("utf8")));
          antwort(status, objekt);
        } catch (err) {
          antwort(400, { fehler: `Anfrage nicht lesbar: ${String(err.message ?? err).slice(0, 100)}` });
        }
      });
    });
  });
  await new Promise((ok) => server.listen(port, host, ok));
  return { port: server.address().port, vkey, freigeben, auskunft, quittungen: () => quittungen.slice(), schliessen: () => new Promise((ok) => server.close(ok)) };
}

if (process.argv[1] && process.argv[1].endsWith("hueter.mjs")) {
  const o = argumente(process.argv.slice(2));
  const anteile = Object.fromEntries(o.anteile.map((a) => [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)]));
  const h = await starteHueter({ name: o.name, logSchluessel: o.logSchluessel, zeugen: o.zeugen, zeugenSchwelle: o.zeugenSchwelle, anteile, dir: o.dir, port: o.port, host: o.host, erlaubteTypen: o.typen.length ? o.typen : STANDARD_TYPEN, mindestArbeitBits: o.mindestArbeitBits });
  console.log(`Hüter ${o.name} läuft auf Port ${h.port}.\nSchlüssel: ${h.vkey}`);
}
