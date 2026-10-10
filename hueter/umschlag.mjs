import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";

const INFO = Buffer.from("defconder-freigabe-1", "utf8");

export function versiegeln(klartext, aad = "") {
  const dek = randomBytes(32);
  const nonce = randomBytes(12);
  const chiffre = createCipheriv("aes-256-gcm", dek, nonce);
  chiffre.setAAD(Buffer.from(aad, "utf8"));
  const text = Buffer.concat([chiffre.update(klartext), chiffre.final()]);
  return { dek, umschlag: { v: 1, aad, nonce: nonce.toString("base64"), text: text.toString("base64"), tag: chiffre.getAuthTag().toString("base64") } };
}

export function oeffnen(umschlag, dek) {
  const dechiffre = createDecipheriv("aes-256-gcm", dek, Buffer.from(umschlag.nonce, "base64"));
  dechiffre.setAAD(Buffer.from(umschlag.aad ?? "", "utf8"));
  dechiffre.setAuthTag(Buffer.from(umschlag.tag, "base64"));
  return Buffer.concat([dechiffre.update(Buffer.from(umschlag.text, "base64")), dechiffre.final()]);
}

export function empfaengerSchluesselpaar() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return { oeffentlich: publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64"), privat: privateKey };
}

function oeffentlichAusRoh(rohBase64) {
  const roh = Buffer.from(rohBase64, "base64");
  if (roh.length !== 32) throw new Error("Der Empfängerschlüssel hat nicht 32 Byte.");
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), roh]), format: "der", type: "spki" });
}

function schluesselAbleiten(gemeinsam, anfrageHash) {
  return Buffer.from(hkdfSync("sha256", gemeinsam, Buffer.from(anfrageHash, "hex"), INFO, 32));
}

export function anteilVerschluesseln(anteil, empfaengerRoh, anfrageHash) {
  const fluechtig = generateKeyPairSync("x25519");
  const gemeinsam = diffieHellman({ privateKey: fluechtig.privateKey, publicKey: oeffentlichAusRoh(empfaengerRoh) });
  const nonce = randomBytes(12);
  const chiffre = createCipheriv("aes-256-gcm", schluesselAbleiten(gemeinsam, anfrageHash), nonce);
  chiffre.setAAD(Buffer.from(anfrageHash, "hex"));
  const text = Buffer.concat([chiffre.update(anteil), chiffre.final()]);
  return { fluechtig: fluechtig.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64"), nonce: nonce.toString("base64"), text: text.toString("base64"), tag: chiffre.getAuthTag().toString("base64") };
}

export function anteilEntschluesseln(huelle, empfaengerPrivat, anfrageHash) {
  const privat = typeof empfaengerPrivat === "string" ? createPrivateKey(empfaengerPrivat) : empfaengerPrivat;
  const gemeinsam = diffieHellman({ privateKey: privat, publicKey: oeffentlichAusRoh(huelle.fluechtig) });
  const dechiffre = createDecipheriv("aes-256-gcm", schluesselAbleiten(gemeinsam, anfrageHash), Buffer.from(huelle.nonce, "base64"));
  dechiffre.setAAD(Buffer.from(anfrageHash, "hex"));
  dechiffre.setAuthTag(Buffer.from(huelle.tag, "base64"));
  return new Uint8Array(Buffer.concat([dechiffre.update(Buffer.from(huelle.text, "base64")), dechiffre.final()]));
}
