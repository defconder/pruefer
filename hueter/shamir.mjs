import { randomBytes } from "node:crypto";

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
let x = 1;
for (let i = 0; i < 255; i += 1) {
  EXP[i] = x;
  LOG[x] = i;
  let doppelt = x << 1;
  if (doppelt & 0x100) doppelt ^= 0x11b;
  x = (doppelt ^ x) & 0xff;
}
for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];

function mal(a, b) {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
}

function geteilt(a, b) {
  if (b === 0) throw new Error("Division durch null.");
  return a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255];
}

export function teilen(geheimnis, n, k) {
  if (!(geheimnis instanceof Uint8Array) || geheimnis.length === 0) throw new Error("Das Geheimnis fehlt.");
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > 255) throw new Error("Ungültige Zahl der Anteile oder Schwelle.");
  const anteile = Array.from({ length: n }, (_, i) => new Uint8Array(1 + geheimnis.length).fill(0, 0, 1));
  for (let i = 0; i < n; i += 1) anteile[i][0] = i + 1;
  for (let b = 0; b < geheimnis.length; b += 1) {
    const koeffizienten = new Uint8Array(randomBytes(k));
    koeffizienten[0] = geheimnis[b];
    for (let i = 0; i < n; i += 1) {
      const punkt = i + 1;
      let wert = 0;
      for (let g = k - 1; g >= 0; g -= 1) wert = mal(wert, punkt) ^ koeffizienten[g];
      anteile[i][1 + b] = wert;
    }
  }
  return anteile;
}

export function zusammensetzen(anteile) {
  if (!Array.isArray(anteile) || anteile.length < 2) throw new Error("Es braucht mindestens zwei Anteile.");
  const laenge = anteile[0].length;
  const xs = anteile.map((a) => a[0]);
  if (new Set(xs).size !== xs.length || xs.includes(0) || anteile.some((a) => a.length !== laenge)) throw new Error("Die Anteile sind unbrauchbar.");
  const ergebnis = new Uint8Array(laenge - 1);
  for (let b = 0; b < laenge - 1; b += 1) {
    let summe = 0;
    for (let i = 0; i < anteile.length; i += 1) {
      let zaehler = 1;
      let nenner = 1;
      for (let j = 0; j < anteile.length; j += 1) {
        if (i === j) continue;
        zaehler = mal(zaehler, xs[j]);
        nenner = mal(nenner, xs[i] ^ xs[j]);
      }
      summe ^= mal(anteile[i][1 + b], geteilt(zaehler, nenner));
    }
    ergebnis[b] = summe;
  }
  return ergebnis;
}
