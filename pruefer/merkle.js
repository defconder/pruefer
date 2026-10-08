const encoder = new TextEncoder();

export const MAX_BAUMGROESSE = 2147483647;

export function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function unhex(text) {
  if (typeof text !== "string" || text.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(text)) throw new Error("Ungültige Hexadezimalzahl.");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256Bytes(data) {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function leafHashOfData(data) {
  return sha256Bytes(concat(Uint8Array.of(0), data));
}

export async function leafHash(eventHash) {
  return leafHashOfData(encoder.encode(eventHash));
}

export async function hashChildren(left, right) {
  return sha256Bytes(concat(Uint8Array.of(1), left, right));
}

export async function emptyRoot() {
  return sha256Bytes(new Uint8Array(0));
}

function largestPowerBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export async function rootOfLeaves(leaves) {
  if (leaves.length === 0) return emptyRoot();
  if (leaves.length === 1) return leaves[0];
  const k = largestPowerBelow(leaves.length);
  return hashChildren(await rootOfLeaves(leaves.slice(0, k)), await rootOfLeaves(leaves.slice(k)));
}

export async function verifyInclusion({ index, treeSize, eventHash, path, rootHash }) {
  if (typeof eventHash !== "string") return false;
  return verifyInclusionOfLeaf({ index, treeSize, leaf: await leafHash(eventHash), path, rootHash });
}

export async function verifyInclusionOfLeaf({ index, treeSize, leaf, path, rootHash }) {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize) || index < 0 || index >= treeSize || treeSize > MAX_BAUMGROESSE) return false;
  if (!Array.isArray(path) || path.length > 64) return false;
  let fn = index;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    const sibling = unhex(p);
    if (sibling.length !== 32) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = await hashChildren(sibling, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = await hashChildren(r, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && hex(r) === rootHash;
}

export async function verifyConsistency({ oldSize, newSize, oldRoot, newRoot, proof }) {
  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize) || oldSize < 0 || newSize < 0 || newSize > MAX_BAUMGROESSE) return false;
  if (!Array.isArray(proof) || proof.length > 64) return false;
  if (oldSize > newSize) return false;
  if (oldSize === 0) return proof.length === 0;
  if (oldSize === newSize) return proof.length === 0 && oldRoot === newRoot;
  if (proof.length === 0) return false;
  const path = proof.map((p) => unhex(p));
  if (path.some((p) => p.length !== 32)) return false;
  if ((oldSize & (oldSize - 1)) === 0) path.unshift(unhex(oldRoot));
  let fn = oldSize - 1;
  let sn = newSize - 1;
  while ((fn & 1) === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i += 1) {
    if (sn === 0) return false;
    const c = path[i];
    if ((fn & 1) === 1 || fn === sn) {
      fr = await hashChildren(c, fr);
      sr = await hashChildren(c, sr);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = await hashChildren(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return hex(fr) === oldRoot && hex(sr) === newRoot && sn === 0;
}
