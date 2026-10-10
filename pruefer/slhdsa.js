import { sha256Sync } from "./sha256sync.js";

const WOTS_HASH = 0;
const WOTS_PK = 1;
const TREE = 2;
const FORS_TREE = 3;
const FORS_ROOTS = 4;
const WOTS_PRF = 5;
const FORS_PRF = 6;

export const SLH_PARAMETER = {
  "sha2-128s": { n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgW: 4 },
  "sha2-128f": { n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lgW: 4 },
};

export const SLH_KONTEXT = "defconder-pruefpunkt-1";

function ableiten(p) {
  const w = 1 << p.lgW;
  const len1 = Math.ceil((8 * p.n) / p.lgW);
  const len2 = Math.floor(Math.log2(len1 * (w - 1)) / p.lgW) + 1;
  const len = len1 + len2;
  const mdBytes = Math.ceil((p.k * p.a) / 8);
  const baumBits = p.h - p.hp;
  const baumBytes = Math.ceil(baumBits / 8);
  const blattBytes = Math.ceil(p.hp / 8);
  const forsBytes = p.k * (p.a + 1) * p.n;
  const xmssBytes = (len + p.hp) * p.n;
  return { ...p, w, len1, len2, len, mdBytes, baumBits, baumBytes, blattBytes, m: mdBytes + baumBytes + blattBytes, forsBytes, xmssBytes, signaturBytes: p.n + forsBytes + p.d * xmssBytes, oeffentlichBytes: 2 * p.n, geheimBytes: 4 * p.n };
}

export function slhGroessen(name) {
  const p = SLH_PARAMETER[name];
  if (!p) throw new Error("Unbekannter SLH-DSA-Parametersatz.");
  const g = ableiten(p);
  return { signatur: g.signaturBytes, oeffentlich: g.oeffentlichBytes, geheim: g.geheimBytes, saat: 3 * p.n };
}

function verbinden(...teile) {
  const out = new Uint8Array(teile.reduce((n, t) => n + t.length, 0));
  let o = 0;
  for (const t of teile) {
    out.set(t, o);
    o += t.length;
  }
  return out;
}

function gleich(a, b) {
  if (a.length !== b.length) return false;
  let rest = 0;
  for (let i = 0; i < a.length; i += 1) rest |= a[i] ^ b[i];
  return rest === 0;
}

function hmacSha256(sha, schluessel, daten) {
  const k = new Uint8Array(64);
  k.set(schluessel.length > 64 ? sha(schluessel) : schluessel);
  const innen = new Uint8Array(64);
  const aussen = new Uint8Array(64);
  for (let i = 0; i < 64; i += 1) {
    innen[i] = k[i] ^ 0x36;
    aussen[i] = k[i] ^ 0x5c;
  }
  return sha(verbinden(aussen, sha(verbinden(innen, daten))));
}

function mgf1(sha, saat, laenge) {
  const teile = [];
  let gesamt = 0;
  for (let zaehler = 0; gesamt < laenge; zaehler += 1) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, zaehler, false);
    const block = sha(verbinden(saat, c));
    teile.push(block);
    gesamt += block.length;
  }
  return verbinden(...teile).subarray(0, laenge);
}

function base2b(x, b, ausgabe) {
  const out = new Array(ausgabe);
  let pos = 0;
  let bits = 0;
  let summe = 0;
  const maske = (1 << b) - 1;
  for (let i = 0; i < ausgabe; i += 1) {
    while (bits < b) {
      summe = ((summe << 8) | x[pos]) >>> 0;
      pos += 1;
      bits += 8;
    }
    bits -= b;
    out[i] = (summe >>> bits) & maske;
    summe &= (1 << bits) - 1;
  }
  return out;
}

function neueAdrs() {
  return new Uint8Array(32);
}

function kopie(adrs) {
  return Uint8Array.from(adrs);
}

function setSchicht(adrs, v) {
  adrs[0] = 0;
  adrs[1] = 0;
  adrs[2] = 0;
  adrs[3] = v;
}

function setBaum(adrs, t) {
  let rest = t;
  for (let i = 15; i >= 4; i -= 1) {
    adrs[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
}

function setTypLeeren(adrs, typ) {
  adrs[16] = 0;
  adrs[17] = 0;
  adrs[18] = 0;
  adrs[19] = typ;
  adrs.fill(0, 20, 32);
}

function setWort(adrs, offset, v) {
  new DataView(adrs.buffer, adrs.byteOffset, 32).setUint32(offset, v, false);
}

function getWort(adrs, offset) {
  return new DataView(adrs.buffer, adrs.byteOffset, 32).getUint32(offset, false);
}

const setSchluesselpaar = (adrs, v) => setWort(adrs, 20, v);
const getSchluesselpaar = (adrs) => getWort(adrs, 20);
const setKette = (adrs, v) => setWort(adrs, 24, v);
const setHash = (adrs, v) => setWort(adrs, 28, v);
const setHoehe = (adrs, v) => setWort(adrs, 24, v);
const setIndex = (adrs, v) => setWort(adrs, 28, v);

function komprimiert(adrs) {
  const out = new Uint8Array(22);
  out[0] = adrs[3];
  out.set(adrs.subarray(8, 16), 1);
  out[9] = adrs[19];
  out.set(adrs.subarray(20, 32), 10);
  return out;
}

function kontextFuer(g, pkSeed, anbieter) {
  const sha = anbieter.sha256;
  const praefix = verbinden(pkSeed, new Uint8Array(64 - g.n));
  const gehasht = anbieter.mitPraefix ? anbieter.mitPraefix(praefix) : (d) => sha(verbinden(praefix, d));
  const kurz = (d) => gehasht(d).subarray(0, g.n);
  return {
    sha,
    F: (adrs, m) => kurz(verbinden(komprimiert(adrs), m)),
    H: (adrs, m) => kurz(verbinden(komprimiert(adrs), m)),
    T: (adrs, m) => kurz(verbinden(komprimiert(adrs), m)),
    PRF: (skSeed, adrs) => kurz(verbinden(komprimiert(adrs), skSeed)),
  };
}

function kette(g, c, x, i, s, adrs) {
  let tmp = x;
  for (let j = i; j < i + s; j += 1) {
    setHash(adrs, j);
    tmp = c.F(adrs, tmp);
  }
  return tmp;
}

function wotsZiffern(g, m) {
  const msg = base2b(m, g.lgW, g.len1);
  let pruef = 0;
  for (const z of msg) pruef += g.w - 1 - z;
  pruef <<= (8 - ((g.len2 * g.lgW) % 8)) % 8;
  const pruefBytes = Math.ceil((g.len2 * g.lgW) / 8);
  const pb = new Uint8Array(pruefBytes);
  for (let i = 0; i < pruefBytes; i += 1) pb[pruefBytes - 1 - i] = (pruef >>> (8 * i)) & 0xff;
  return msg.concat(base2b(pb, g.lgW, g.len2));
}

function wotsPkAusSignatur(g, c, sig, m, pkSeed, adrs) {
  const ziffern = wotsZiffern(g, m);
  const teile = [];
  for (let i = 0; i < g.len; i += 1) {
    setKette(adrs, i);
    teile.push(kette(g, c, sig.subarray(i * g.n, (i + 1) * g.n), ziffern[i], g.w - 1 - ziffern[i], adrs));
  }
  const wotsPk = kopie(adrs);
  setTypLeeren(wotsPk, WOTS_PK);
  setSchluesselpaar(wotsPk, getSchluesselpaar(adrs));
  return c.T(wotsPk, verbinden(...teile));
}

function wotsSchluessel(g, c, skSeed, adrs, i) {
  const skAdrs = kopie(adrs);
  setTypLeeren(skAdrs, WOTS_PRF);
  setSchluesselpaar(skAdrs, getSchluesselpaar(adrs));
  setKette(skAdrs, i);
  setHash(skAdrs, 0);
  return c.PRF(skSeed, skAdrs);
}

function wotsPkErzeugen(g, c, skSeed, adrs) {
  const teile = [];
  for (let i = 0; i < g.len; i += 1) {
    const sk = wotsSchluessel(g, c, skSeed, adrs, i);
    setKette(adrs, i);
    teile.push(kette(g, c, sk, 0, g.w - 1, adrs));
  }
  const wotsPk = kopie(adrs);
  setTypLeeren(wotsPk, WOTS_PK);
  setSchluesselpaar(wotsPk, getSchluesselpaar(adrs));
  return c.T(wotsPk, verbinden(...teile));
}

function wotsSignieren(g, c, m, skSeed, adrs) {
  const ziffern = wotsZiffern(g, m);
  const teile = [];
  for (let i = 0; i < g.len; i += 1) {
    const sk = wotsSchluessel(g, c, skSeed, adrs, i);
    setKette(adrs, i);
    teile.push(kette(g, c, sk, 0, ziffern[i], adrs));
  }
  return verbinden(...teile);
}

function xmssKnoten(g, c, skSeed, i, z, adrs) {
  if (z === 0) {
    setTypLeeren(adrs, WOTS_HASH);
    setSchluesselpaar(adrs, i);
    return wotsPkErzeugen(g, c, skSeed, adrs);
  }
  const links = xmssKnoten(g, c, skSeed, 2 * i, z - 1, adrs);
  const rechts = xmssKnoten(g, c, skSeed, 2 * i + 1, z - 1, adrs);
  setTypLeeren(adrs, TREE);
  setHoehe(adrs, z);
  setIndex(adrs, i);
  return c.H(adrs, verbinden(links, rechts));
}

function xmssSignieren(g, c, m, skSeed, idx, adrs) {
  const auth = [];
  for (let j = 0; j < g.hp; j += 1) auth.push(xmssKnoten(g, c, skSeed, (idx >> j) ^ 1, j, adrs));
  setTypLeeren(adrs, WOTS_HASH);
  setSchluesselpaar(adrs, idx);
  return verbinden(wotsSignieren(g, c, m, skSeed, adrs), ...auth);
}

function xmssPkAusSignatur(g, c, idx, sig, m, pkSeed, adrs) {
  setTypLeeren(adrs, WOTS_HASH);
  setSchluesselpaar(adrs, idx);
  let knoten = wotsPkAusSignatur(g, c, sig.subarray(0, g.len * g.n), m, pkSeed, adrs);
  setTypLeeren(adrs, TREE);
  setIndex(adrs, idx);
  let baumIndex = idx;
  for (let k = 0; k < g.hp; k += 1) {
    setHoehe(adrs, k + 1);
    baumIndex >>= 1;
    setIndex(adrs, baumIndex);
    const nachbar = sig.subarray((g.len + k) * g.n, (g.len + k + 1) * g.n);
    knoten = ((idx >> k) & 1) === 0 ? c.H(adrs, verbinden(knoten, nachbar)) : c.H(adrs, verbinden(nachbar, knoten));
  }
  return knoten;
}

function htSignieren(g, c, m, skSeed, idxBaum, idxBlatt) {
  const adrs = neueAdrs();
  setBaum(adrs, idxBaum);
  const teile = [];
  let sig = xmssSignieren(g, c, m, skSeed, idxBlatt, adrs);
  teile.push(sig);
  let wurzel = xmssPkAusSignatur(g, c, idxBlatt, sig, m, null, adrs);
  let baum = idxBaum;
  for (let j = 1; j < g.d; j += 1) {
    const blatt = Number(baum & BigInt((1 << g.hp) - 1));
    baum >>= BigInt(g.hp);
    setSchicht(adrs, j);
    setBaum(adrs, baum);
    sig = xmssSignieren(g, c, wurzel, skSeed, blatt, adrs);
    teile.push(sig);
    if (j < g.d - 1) wurzel = xmssPkAusSignatur(g, c, blatt, sig, wurzel, null, adrs);
  }
  return verbinden(...teile);
}

function htPruefen(g, c, m, sig, idxBaum, idxBlatt, pkWurzel) {
  const adrs = neueAdrs();
  setBaum(adrs, idxBaum);
  let knoten = xmssPkAusSignatur(g, c, idxBlatt, sig.subarray(0, g.xmssBytes), m, null, adrs);
  let baum = idxBaum;
  for (let j = 1; j < g.d; j += 1) {
    const blatt = Number(baum & BigInt((1 << g.hp) - 1));
    baum >>= BigInt(g.hp);
    setSchicht(adrs, j);
    setBaum(adrs, baum);
    knoten = xmssPkAusSignatur(g, c, blatt, sig.subarray(j * g.xmssBytes, (j + 1) * g.xmssBytes), knoten, null, adrs);
  }
  return gleich(knoten, pkWurzel);
}

function forsSchluessel(g, c, skSeed, adrs, idx) {
  const skAdrs = kopie(adrs);
  setTypLeeren(skAdrs, FORS_PRF);
  setSchluesselpaar(skAdrs, getSchluesselpaar(adrs));
  setIndex(skAdrs, idx);
  return c.PRF(skSeed, skAdrs);
}

function forsKnoten(g, c, skSeed, i, z, adrs) {
  if (z === 0) {
    const sk = forsSchluessel(g, c, skSeed, adrs, i);
    setHoehe(adrs, 0);
    setIndex(adrs, i);
    return c.F(adrs, sk);
  }
  const links = forsKnoten(g, c, skSeed, 2 * i, z - 1, adrs);
  const rechts = forsKnoten(g, c, skSeed, 2 * i + 1, z - 1, adrs);
  setHoehe(adrs, z);
  setIndex(adrs, i);
  return c.H(adrs, verbinden(links, rechts));
}

function forsSignieren(g, c, md, skSeed, adrs) {
  const indizes = base2b(md, g.a, g.k);
  const teile = [];
  for (let i = 0; i < g.k; i += 1) {
    teile.push(forsSchluessel(g, c, skSeed, adrs, i * (1 << g.a) + indizes[i]));
    for (let j = 0; j < g.a; j += 1) {
      const s = (indizes[i] >> j) ^ 1;
      teile.push(forsKnoten(g, c, skSeed, i * (1 << (g.a - j)) + s, j, adrs));
    }
  }
  return verbinden(...teile);
}

function forsPkAusSignatur(g, c, sig, md, adrs) {
  const indizes = base2b(md, g.a, g.k);
  const wurzeln = [];
  const schritt = (g.a + 1) * g.n;
  for (let i = 0; i < g.k; i += 1) {
    const teil = sig.subarray(i * schritt, (i + 1) * schritt);
    setHoehe(adrs, 0);
    let baumIndex = i * (1 << g.a) + indizes[i];
    setIndex(adrs, baumIndex);
    let knoten = c.F(adrs, teil.subarray(0, g.n));
    for (let j = 0; j < g.a; j += 1) {
      setHoehe(adrs, j + 1);
      baumIndex >>= 1;
      setIndex(adrs, baumIndex);
      const nachbar = teil.subarray((j + 1) * g.n, (j + 2) * g.n);
      knoten = ((indizes[i] >> j) & 1) === 0 ? c.H(adrs, verbinden(knoten, nachbar)) : c.H(adrs, verbinden(nachbar, knoten));
    }
    wurzeln.push(knoten);
  }
  const forsPk = kopie(adrs);
  setTypLeeren(forsPk, FORS_ROOTS);
  setSchluesselpaar(forsPk, getSchluesselpaar(adrs));
  return c.T(forsPk, verbinden(...wurzeln));
}

function zerlegen(g, digest) {
  const md = digest.subarray(0, g.mdBytes);
  let baum = 0n;
  for (const b of digest.subarray(g.mdBytes, g.mdBytes + g.baumBytes)) baum = (baum << 8n) | BigInt(b);
  baum &= (1n << BigInt(g.baumBits)) - 1n;
  let blatt = 0;
  for (const b of digest.subarray(g.mdBytes + g.baumBytes, g.mdBytes + g.baumBytes + g.blattBytes)) blatt = blatt * 256 + b;
  blatt %= 1 << g.hp;
  return { md, baum, blatt };
}

function nachrichtVerpacken(nachricht, kontext) {
  const ctx = typeof kontext === "string" ? new TextEncoder().encode(kontext) : kontext;
  if (ctx.length > 255) throw new Error("Der Kontext ist zu lang.");
  return verbinden(Uint8Array.of(0, ctx.length), ctx, nachricht);
}

function parameterFuer(name) {
  const p = SLH_PARAMETER[name];
  if (!p) throw new Error("Unbekannter SLH-DSA-Parametersatz.");
  return ableiten(p);
}

const STANDARD_ANBIETER = { sha256: sha256Sync };

export function slhSchluesselpaar(name, saat, anbieter = STANDARD_ANBIETER) {
  const g = parameterFuer(name);
  if (!(saat instanceof Uint8Array) || saat.length !== 3 * g.n) throw new Error("Die Saat hat die falsche Länge.");
  const skSeed = saat.slice(0, g.n);
  const skPrf = saat.slice(g.n, 2 * g.n);
  const pkSeed = saat.slice(2 * g.n, 3 * g.n);
  const c = kontextFuer(g, pkSeed, anbieter);
  const adrs = neueAdrs();
  setSchicht(adrs, g.d - 1);
  const wurzel = xmssKnoten(g, c, skSeed, 0, g.hp, adrs);
  return { oeffentlich: verbinden(pkSeed, wurzel), geheim: verbinden(skSeed, skPrf, pkSeed, wurzel) };
}

export function slhSignieren(name, geheim, nachricht, kontext = SLH_KONTEXT, zufall = null, anbieter = STANDARD_ANBIETER) {
  const g = parameterFuer(name);
  if (!(geheim instanceof Uint8Array) || geheim.length !== 4 * g.n) throw new Error("Der geheime Schlüssel hat die falsche Länge.");
  const skSeed = geheim.subarray(0, g.n);
  const skPrf = geheim.subarray(g.n, 2 * g.n);
  const pkSeed = geheim.subarray(2 * g.n, 3 * g.n);
  const pkWurzel = geheim.subarray(3 * g.n, 4 * g.n);
  const c = kontextFuer(g, pkSeed, anbieter);
  const m = nachrichtVerpacken(nachricht, kontext);
  const optRand = zufall ?? pkSeed;
  const r = hmacSha256(anbieter.sha256, skPrf, verbinden(optRand, m)).subarray(0, g.n);
  const innen = anbieter.sha256(verbinden(r, pkSeed, pkWurzel, m));
  const digest = mgf1(anbieter.sha256, verbinden(r, pkSeed, innen), g.m);
  const { md, baum, blatt } = zerlegen(g, digest);
  const adrs = neueAdrs();
  setBaum(adrs, baum);
  setTypLeeren(adrs, FORS_TREE);
  setSchluesselpaar(adrs, blatt);
  const forsSig = forsSignieren(g, c, md, skSeed, adrs);
  const forsPk = forsPkAusSignatur(g, c, forsSig, md, adrs);
  const htSig = htSignieren(g, c, forsPk, skSeed, baum, blatt);
  return verbinden(r, forsSig, htSig);
}

export function slhPruefen(name, oeffentlich, nachricht, signatur, kontext = SLH_KONTEXT, anbieter = STANDARD_ANBIETER) {
  try {
    const g = parameterFuer(name);
    if (!(oeffentlich instanceof Uint8Array) || oeffentlich.length !== 2 * g.n) return false;
    if (!(signatur instanceof Uint8Array) || signatur.length !== g.signaturBytes) return false;
    const pkSeed = oeffentlich.subarray(0, g.n);
    const pkWurzel = oeffentlich.subarray(g.n, 2 * g.n);
    const c = kontextFuer(g, pkSeed, anbieter);
    const m = nachrichtVerpacken(nachricht, kontext);
    const r = signatur.subarray(0, g.n);
    const forsSig = signatur.subarray(g.n, g.n + g.forsBytes);
    const htSig = signatur.subarray(g.n + g.forsBytes);
    const innen = anbieter.sha256(verbinden(r, pkSeed, pkWurzel, m));
    const digest = mgf1(anbieter.sha256, verbinden(r, pkSeed, innen), g.m);
    const { md, baum, blatt } = zerlegen(g, digest);
    const adrs = neueAdrs();
    setBaum(adrs, baum);
    setTypLeeren(adrs, FORS_TREE);
    setSchluesselpaar(adrs, blatt);
    const forsPk = forsPkAusSignatur(g, c, forsSig, md, adrs);
    return htPruefen(g, c, forsPk, htSig, baum, blatt, pkWurzel);
  } catch {
    return false;
  }
}
