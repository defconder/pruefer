const R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
const R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
const S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
const S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
const K1 = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const K2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

function rol(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function funktion(j, x, y, z) {
  if (j < 16) return (x ^ y ^ z) >>> 0;
  if (j < 32) return ((x & y) | (~x & z)) >>> 0;
  if (j < 48) return ((x | ~y) ^ z) >>> 0;
  if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
  return (x ^ (y | ~z)) >>> 0;
}

export function ripemd160(daten) {
  const h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  const laenge = daten.length;
  const rest = laenge % 64;
  const auffuellung = rest < 56 ? 64 - rest : 128 - rest;
  const voll = new Uint8Array(laenge + auffuellung);
  voll.set(daten);
  voll[laenge] = 0x80;
  const ansicht = new DataView(voll.buffer);
  const bits = BigInt(laenge) * 8n;
  ansicht.setUint32(voll.length - 8, Number(bits & 0xffffffffn), true);
  ansicht.setUint32(voll.length - 4, Number(bits >> 32n), true);
  const x = new Uint32Array(16);
  for (let o = 0; o < voll.length; o += 64) {
    for (let i = 0; i < 16; i += 1) x[i] = ansicht.getUint32(o + i * 4, true);
    let a1 = h[0];
    let b1 = h[1];
    let c1 = h[2];
    let d1 = h[3];
    let e1 = h[4];
    let a2 = h[0];
    let b2 = h[1];
    let c2 = h[2];
    let d2 = h[3];
    let e2 = h[4];
    for (let j = 0; j < 80; j += 1) {
      const runde = Math.floor(j / 16);
      let t = (rol((a1 + funktion(j, b1, c1, d1) + x[R1[j]] + K1[runde]) >>> 0, S1[j]) + e1) >>> 0;
      a1 = e1;
      e1 = d1;
      d1 = rol(c1, 10);
      c1 = b1;
      b1 = t;
      t = (rol((a2 + funktion(79 - j, b2, c2, d2) + x[R2[j]] + K2[runde]) >>> 0, S2[j]) + e2) >>> 0;
      a2 = e2;
      e2 = d2;
      d2 = rol(c2, 10);
      c2 = b2;
      b2 = t;
    }
    const t = (h[1] + c1 + d2) >>> 0;
    h[1] = (h[2] + d1 + e2) >>> 0;
    h[2] = (h[3] + e1 + a2) >>> 0;
    h[3] = (h[4] + a1 + b2) >>> 0;
    h[4] = (h[0] + b1 + c2) >>> 0;
    h[0] = t;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 5; i += 1) ov.setUint32(i * 4, h[i], true);
  return out;
}
