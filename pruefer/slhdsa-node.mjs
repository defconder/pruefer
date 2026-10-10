import { createHash, randomBytes } from "node:crypto";
import { slhSchluesselpaar, slhSignieren, slhGroessen } from "./slhdsa.js";

export const NODE_ANBIETER = {
  sha256: (daten) => new Uint8Array(createHash("sha256").update(daten).digest()),
  mitPraefix: (praefix) => {
    const basis = createHash("sha256").update(praefix);
    return (daten) => new Uint8Array(basis.copy().update(daten).digest());
  },
};

export function slhNeuesSchluesselpaar(name) {
  return slhSchluesselpaar(name, new Uint8Array(randomBytes(slhGroessen(name).saat)), NODE_ANBIETER);
}

export function slhSignierenSchnell(name, geheim, nachricht, kontext, zufall = null) {
  return slhSignieren(name, geheim, nachricht, kontext, zufall ?? new Uint8Array(randomBytes(slhGroessen(name).saat / 3)), NODE_ANBIETER);
}
