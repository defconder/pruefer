import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { canonicalJson } from "./pruefer-kern.js";
import { RELEASE_SCHEMA, RELEASE_KONTEXT } from "./release-pruefen.js";
import { slhNeuesSchluesselpaar, slhSignierenSchnell } from "./slhdsa-node.mjs";
import { slhSchluesselText } from "./note.js";

const here = dirname(fileURLToPath(import.meta.url));
const argumente = process.argv.slice(2);
const wert = (name) => (argumente.includes(name) ? argumente[argumente.indexOf(name) + 1] : null);
const ausgabe = resolve(wert("--ausgabe") ?? join(here, "release"));
const schluesselOrdner = resolve(wert("--schluessel") ?? join(here, "release"));
const NAME = "defconder-pruefer-release";
mkdirSync(ausgabe, { recursive: true });
mkdirSync(schluesselOrdner, { recursive: true });

const bau = spawnSync(process.execPath, [join(here, "bauen-html.mjs")], { encoding: "utf8" });
if (bau.status !== 0) {
  console.log(bau.stdout + bau.stderr);
  process.exit(1);
}
const sha = (buffer) => createHash("sha256").update(buffer).digest("hex");

function dateien(verzeichnis) {
  const liste = [];
  for (const name of readdirSync(verzeichnis).sort()) {
    if (["release", "ausgabe", "node_modules", ".git", "target", "bilder", "__pycache__"].includes(name)) continue;
    const pfad = join(verzeichnis, name);
    if (statSync(pfad).isDirectory()) liste.push(...dateien(pfad));
    else liste.push(pfad);
  }
  return liste;
}

const inhalt = dateien(here).map((pfad) => ({ pfad: relative(here, pfad).replace(/\\/g, "/"), sha256: sha(readFileSync(pfad)) }));
const version = JSON.parse(readFileSync(join(here, "package.json"), "utf8")).version ?? "0.0.0";
const summen = inhalt.map((d) => `${d.sha256}  ${d.pfad}`).join("\n") + "\n";
writeFileSync(join(ausgabe, "SHA256SUMS"), summen);

const sperrPfad = join(here, "rust", "Cargo.lock");
const rustKomponenten = [];
if (existsSync(sperrPfad)) {
  const text = readFileSync(sperrPfad, "utf8");
  for (const block of text.split("[[package]]").slice(1)) {
    const name = block.match(/name = "([^"]+)"/)?.[1];
    const ver = block.match(/version = "([^"]+)"/)?.[1];
    if (name && ver && name !== "defconder-pruefer") rustKomponenten.push({ type: "library", name, version: ver, purl: `pkg:cargo/${name}@${ver}`, scope: "optional" });
  }
}
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  metadata: { component: { type: "application", name: "defconder-pruefer", version, licenses: [{ license: { id: "Apache-2.0" } }] } },
  components: rustKomponenten,
  dependencies: [{ ref: "defconder-pruefer", dependsOn: [] }],
  properties: [
    { name: "laufzeitabhaengigkeiten", value: "keine, nur die Browser-Schnittstelle WebCrypto (Node ab 20)" },
    { name: "python-testumsetzung", value: "benötigt das Paket cryptography (Apache-2.0 oder BSD-3-Clause)" },
    { name: "rust-testumsetzung", value: "benötigt die unter components aufgeführten Pakete, nur für die dritte Umsetzung und ihre Tests, nicht für Prüfer, Seite oder Kommandozeile" },
  ],
};
writeFileSync(join(ausgabe, "sbom.cdx.json"), JSON.stringify(sbom, null, 2));

const edPfad = join(schluesselOrdner, "release-schluessel.pem");
let privat;
if (existsSync(edPfad)) privat = createPrivateKey(readFileSync(edPfad, "utf8"));
else {
  privat = generateKeyPairSync("ed25519").privateKey;
  writeFileSync(edPfad, privat.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}
const rohOeffentlich = createPublicKey(privat).export({ type: "spki", format: "der" }).subarray(-32);
const edKennung = createHash("sha256").update(Buffer.concat([Buffer.from(NAME), Buffer.from([0x0a, 0x01]), rohOeffentlich])).digest().subarray(0, 4);
const edVkey = `${NAME}+${edKennung.toString("hex")}+${Buffer.concat([Buffer.from([0x01]), rohOeffentlich]).toString("base64")}`;

const pqPfad = join(schluesselOrdner, "release-pq-schluessel.json");
let pq;
if (existsSync(pqPfad)) pq = JSON.parse(readFileSync(pqPfad, "utf8"));
else {
  const paar = slhNeuesSchluesselpaar("sha2-128s");
  pq = { verfahren: "sha2-128s", oeffentlich: Buffer.from(paar.oeffentlich).toString("base64"), geheim: Buffer.from(paar.geheim).toString("base64") };
  pq.vkey = await slhSchluesselText(NAME, "sha2-128s", paar.oeffentlich);
  writeFileSync(pqPfad, JSON.stringify(pq, null, 1), { mode: 0o600 });
}

const manifest = { schema: RELEASE_SCHEMA, version, htmlSha256: sha(readFileSync(join(here, "pruefer.html"))), summenSha256: sha(Buffer.from(summen)), dateien: inhalt.length };
const nachricht = Buffer.from(canonicalJson(manifest), "utf8");
const signaturen = [
  { verfahren: "ed25519", schluessel: edVkey, signatur: sign(null, nachricht, privat).toString("hex") },
  { verfahren: "slh-dsa-sha2-128s", schluessel: pq.vkey, signatur: Buffer.from(slhSignierenSchnell(pq.verfahren, new Uint8Array(Buffer.from(pq.geheim, "base64")), nachricht, RELEASE_KONTEXT)).toString("hex") },
];
writeFileSync(join(ausgabe, "MANIFEST.json"), JSON.stringify({ manifest, signaturen }, null, 2));
writeFileSync(join(ausgabe, "SCHLUESSEL.txt"), `${edVkey}\n${pq.vkey}\n`);
console.log(`Veröffentlichung ${version}: ${inhalt.length} Dateien, pruefer.html ${manifest.htmlSha256}\nSchlüssel (Ed25519 und hashbasiert) stehen in ${join(ausgabe, "SCHLUESSEL.txt")}`);
