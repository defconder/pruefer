import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const ausgabe = join(here, "release");
mkdirSync(ausgabe, { recursive: true });

const bau = spawnSync(process.execPath, [join(here, "bauen-html.mjs")], { encoding: "utf8" });
if (bau.status !== 0) {
  console.log(bau.stdout + bau.stderr);
  process.exit(1);
}
const sha = (buffer) => createHash("sha256").update(buffer).digest("hex");

function dateien(verzeichnis) {
  const liste = [];
  for (const name of readdirSync(verzeichnis).sort()) {
    if (["release", "node_modules", ".git", "target", "bilder", "__pycache__"].includes(name)) continue;
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

const schluesselPfad = join(ausgabe, "release-schluessel.pem");
let privat;
if (existsSync(schluesselPfad)) privat = createPrivateKey(readFileSync(schluesselPfad, "utf8"));
else {
  const paar = generateKeyPairSync("ed25519");
  privat = paar.privateKey;
  writeFileSync(schluesselPfad, privat.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}
const oeffentlich = createPublicKey(privat).export({ type: "spki", format: "pem" });
const manifest = { schema: "defconder-pruefer-release-1", version, htmlSha256: sha(readFileSync(join(here, "pruefer.html"))), summenSha256: sha(Buffer.from(summen)), dateien: inhalt.length };
const signatur = sign(null, Buffer.from(JSON.stringify(manifest)), privat).toString("hex");
writeFileSync(join(ausgabe, "MANIFEST.json"), JSON.stringify({ manifest, signatur, oeffentlicherSchluessel: oeffentlich }, null, 2));
console.log(`Release ${version}: ${inhalt.length} Dateien, pruefer.html ${manifest.htmlSha256}`);
