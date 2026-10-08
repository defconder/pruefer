import { hex, unhex, sha256Bytes } from "./merkle.js";

export const ANKERZEILE = "defconder-zeitanker-1";
export const STANDARD_MINDESTARBEIT_BITS = 64;
const ZWEI_STUNDEN_MS = 2 * 60 * 60 * 1000;

export function ankerZeilenLesen(erweiterungen) {
  const anker = [];
  for (const zeile of erweiterungen ?? []) {
    if (!zeile.startsWith(`${ANKERZEILE} `)) continue;
    const teile = zeile.split(" ");
    if (teile.length !== 3) throw new Error("Eine Zeitankerzeile ist ungültig.");
    anker.push({ art: teile[1], kopfHex: teile[2] });
  }
  if (anker.length > 4) throw new Error("Zu viele Zeitanker.");
  return anker;
}

export function ankerZeile(art, kopfHex) {
  return `${ANKERZEILE} ${art} ${kopfHex}`;
}

function bitLaenge(zahl) {
  return zahl === 0n ? 0 : zahl.toString(2).length;
}

export async function bitcoinKopfPruefen(kopfHex, { mindestArbeitBits = STANDARD_MINDESTARBEIT_BITS } = {}) {
  try {
    if (typeof kopfHex !== "string" || !/^[0-9a-f]{160}$/.test(kopfHex)) throw new Error("Der Blockkopf muss aus 80 Byte in Hexschreibweise bestehen.");
    const kopf = unhex(kopfHex);
    const ansicht = new DataView(kopf.buffer, kopf.byteOffset, 80);
    const zeitSekunden = ansicht.getUint32(68, true);
    const bits = ansicht.getUint32(72, true);
    const exponent = bits >>> 24;
    const mantisse = bits & 0x007fffff;
    if ((bits & 0x00800000) !== 0 || mantisse === 0 || exponent < 3 || exponent > 32) throw new Error("Der Zielwert im Blockkopf ist ungültig.");
    const ziel = BigInt(mantisse) * 256n ** BigInt(exponent - 3);
    if (ziel >= 2n ** 256n) throw new Error("Der Zielwert ist zu groß.");
    const doppelt = await sha256Bytes(await sha256Bytes(kopf));
    const blockHash = hex(new Uint8Array([...doppelt].reverse()));
    const wert = BigInt(`0x${blockHash}`);
    if (wert > ziel) throw new Error("Der Blockkopf erfüllt seinen eigenen Zielwert nicht.");
    const arbeit = 2n ** 256n / (ziel + 1n);
    const arbeitBits = bitLaenge(arbeit) - 1;
    const fruehestens = zeitSekunden * 1000 - ZWEI_STUNDEN_MS;
    const genug = arbeitBits >= mindestArbeitBits;
    return { ok: genug, blockHash, blockZeit: zeitSekunden * 1000, fruehestens, arbeitBits, grund: genug ? "" : `Die Rechenarbeit des Blocks (rund 2^${arbeitBits}) liegt unter der geforderten Mindestarbeit 2^${mindestArbeitBits}. Ein so leichter Block lässt sich billig erzeugen und beweist nichts.` };
  } catch (err) {
    return { ok: false, grund: String(err?.message ?? err) };
  }
}

export async function zeitankerPruefen(erweiterungen, opts, add) {
  let anker;
  try {
    anker = ankerZeilenLesen(erweiterungen);
  } catch (err) {
    add("zeitanker", "Zeitanker im Prüfpunkt sind lesbar", false, String(err.message));
    return null;
  }
  let bester = null;
  for (const a of anker) {
    if (a.art !== "bitcoin") {
      add("zeitanker", `Zeitanker der Art ${a.art.slice(0, 20)}`, false, "Unbekannte Art des Zeitankers.");
      continue;
    }
    const r = await bitcoinKopfPruefen(a.kopfHex, { mindestArbeitBits: opts.mindestArbeitBits ?? STANDARD_MINDESTARBEIT_BITS });
    if (r.blockHash) {
      add("zeitanker", `Der Prüfpunkt nennt den Bitcoin-Block ${r.blockHash.slice(0, 16)}… (Blockzeit ${new Date(r.blockZeit).toISOString()}), er ist also frühestens ${new Date(r.fruehestens).toISOString()} entstanden`, r.ok, r.ok ? `Rechenarbeit des Blocks rund 2^${r.arbeitBits}. Vergleichen Sie die Blockprüfsumme mit einer Blockübersicht Ihrer Wahl.` : r.grund);
    } else add("zeitanker", "Bitcoin-Zeitanker ist gültig", false, r.grund);
    if (r.ok && (!bester || r.fruehestens > bester.fruehestens)) bester = r;
  }
  return bester ? { fruehestens: bester.fruehestens, blockHash: bester.blockHash, blockZeit: bester.blockZeit, arbeitBits: bester.arbeitBits } : null;
}
