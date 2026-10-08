import { createPrivateKey, createPublicKey, createHash, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalJson } from "./pruefer-kern.js";

const [, , altPrivat, altOeffentlich, neuOeffentlich, ...rest] = process.argv;
if (!altPrivat || !altOeffentlich || !neuOeffentlich) {
  console.log("Aufruf: node schluesselwechsel-erzeugen.mjs <alter-privater-schluessel.pem> <alter-oeffentlicher-schluessel.pem> <neuer-oeffentlicher-schluessel.pem> [--behalten]");
  process.exit(2);
}
const kennung = (pem) => createHash("sha256").update(createPublicKey(pem).export({ type: "spki", format: "der" })).digest("hex").slice(0, 32);
const vonPem = readFileSync(altOeffentlich, "utf8");
const nachPem = readFileSync(neuOeffentlich, "utf8");
const aussage = { schema: "defconder-schluesselwechsel-1", von: kennung(vonPem), nach: kennung(nachPem), at: Date.now(), entzieht: !rest.includes("--behalten") };
const signatur = sign(null, Buffer.from(canonicalJson(aussage)), createPrivateKey(readFileSync(altPrivat, "utf8"))).toString("hex");
console.log(JSON.stringify({ ...aussage, vonPem, nachPem, signatur }, null, 2));
