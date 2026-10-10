use crate::merkle::sha256;

const MAGIE: [u8; 31] = [0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94];
const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const AUSSTEHEND_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const MAX_NACHRICHT: usize = 4096;
const MAX_KNOTEN: usize = 20000;
const MAX_TIEFE: usize = 256;
const MAX_DATEI: usize = 1_000_000;

const R1: [usize; 80] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
const R2: [usize; 80] = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
const S1: [u32; 80] = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
const S2: [u32; 80] = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
const K1: [u32; 5] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xa953_fd4e];
const K2: [u32; 5] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x7a6d_76e9, 0x0000_0000];

fn funktion(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

pub fn ripemd160(daten: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    let laenge = daten.len();
    let rest = laenge % 64;
    let auffuellung = if rest < 56 { 64 - rest } else { 128 - rest };
    let mut voll = daten.to_vec();
    voll.push(0x80);
    voll.extend(std::iter::repeat(0u8).take(auffuellung - 9));
    voll.extend_from_slice(&((laenge as u64) * 8).to_le_bytes());
    for block in voll.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a1, mut b1, mut c1, mut d1, mut e1) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut a2, mut b2, mut c2, mut d2, mut e2) = (h[0], h[1], h[2], h[3], h[4]);
        for j in 0..80 {
            let runde = j / 16;
            let t = a1.wrapping_add(funktion(j, b1, c1, d1)).wrapping_add(x[R1[j]]).wrapping_add(K1[runde]).rotate_left(S1[j]).wrapping_add(e1);
            a1 = e1;
            e1 = d1;
            d1 = c1.rotate_left(10);
            c1 = b1;
            b1 = t;
            let t = a2.wrapping_add(funktion(79 - j, b2, c2, d2)).wrapping_add(x[R2[j]]).wrapping_add(K2[runde]).rotate_left(S2[j]).wrapping_add(e2);
            a2 = e2;
            e2 = d2;
            d2 = c2.rotate_left(10);
            c2 = b2;
            b2 = t;
        }
        let t = h[1].wrapping_add(c1).wrapping_add(d2);
        h[1] = h[2].wrapping_add(d1).wrapping_add(e2);
        h[2] = h[3].wrapping_add(e1).wrapping_add(a2);
        h[3] = h[4].wrapping_add(a1).wrapping_add(b2);
        h[4] = h[0].wrapping_add(b1).wrapping_add(c2);
        h[0] = t;
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

struct Leser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Leser<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let w = *self.b.get(self.pos).ok_or("Die Datei endet zu früh.")?;
        self.pos += 1;
        Ok(w)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.b.len() {
            return Err("Die Datei endet zu früh.".into());
        }
        let out = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn varuint(&mut self) -> Result<u64, String> {
        let mut wert: u64 = 0;
        for i in 0..5 {
            let x = self.byte()?;
            wert += ((x & 0x7f) as u64) << (7 * i);
            if x & 0x80 == 0 {
                return Ok(wert);
            }
        }
        Err("Eine Längenangabe ist zu groß.".into())
    }

    fn varbytes(&mut self, maximum: usize, minimum: usize) -> Result<&'a [u8], String> {
        let n = self.varuint()? as usize;
        if n > maximum || n < minimum {
            return Err("Eine Längenangabe liegt außerhalb des erlaubten Bereichs.".into());
        }
        self.bytes(n)
    }

    fn ende(&self) -> bool {
        self.pos == self.b.len()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Bestaetigung {
    Bitcoin { hoehe: u64, nachricht: Vec<u8> },
    Ausstehend,
    Unbekannt,
}

pub struct Ots {
    pub digest: Vec<u8>,
    pub attestierungen: Vec<Bestaetigung>,
}

fn zweig(l: &mut Leser, nachricht: &[u8], tag: u8, tiefe: usize, attest: &mut Vec<Bestaetigung>, zaehler: &mut usize) -> Result<(), String> {
    *zaehler += 1;
    if *zaehler > MAX_KNOTEN {
        return Err("Der Beweis hat zu viele Knoten.".into());
    }
    if tag == 0x00 {
        let art = l.bytes(8)?.to_vec();
        let nutzlast = l.varbytes(MAX_NACHRICHT, 0)?;
        if art == BITCOIN_TAG {
            let mut inneres = Leser { b: nutzlast, pos: 0 };
            let hoehe = inneres.varuint()?;
            if !inneres.ende() {
                return Err("Die Bestätigung durch Bitcoin hat überzählige Bytes.".into());
            }
            attest.push(Bestaetigung::Bitcoin { hoehe, nachricht: nachricht.to_vec() });
        } else if art == AUSSTEHEND_TAG {
            attest.push(Bestaetigung::Ausstehend);
        } else {
            attest.push(Bestaetigung::Unbekannt);
        }
        return Ok(());
    }
    let neu: Vec<u8> = match tag {
        0x08 => sha256(nachricht).to_vec(),
        0x03 => ripemd160(nachricht).to_vec(),
        0xf0 => {
            let mut v = nachricht.to_vec();
            v.extend_from_slice(l.varbytes(MAX_NACHRICHT, 1)?);
            v
        }
        0xf1 => {
            let mut v = l.varbytes(MAX_NACHRICHT, 1)?.to_vec();
            v.extend_from_slice(nachricht);
            v
        }
        0xf2 => nachricht.iter().rev().cloned().collect(),
        0xf3 => hex::encode(nachricht).into_bytes(),
        _ => return Err("Unbekannte oder nicht unterstützte Operation.".into()),
    };
    if neu.len() > MAX_NACHRICHT || neu.is_empty() {
        return Err("Eine Zwischennachricht ist zu lang.".into());
    }
    baum(l, &neu, tiefe + 1, attest, zaehler)
}

fn baum(l: &mut Leser, nachricht: &[u8], tiefe: usize, attest: &mut Vec<Bestaetigung>, zaehler: &mut usize) -> Result<(), String> {
    if tiefe > MAX_TIEFE {
        return Err("Der Beweis ist zu tief verschachtelt.".into());
    }
    let mut tag = l.byte()?;
    while tag == 0xff {
        let zweig_tag = l.byte()?;
        zweig(l, nachricht, zweig_tag, tiefe, attest, zaehler)?;
        tag = l.byte()?;
    }
    zweig(l, nachricht, tag, tiefe, attest, zaehler)
}

pub fn ots_auswerten(daten: &[u8]) -> Result<Ots, String> {
    if daten.len() > MAX_DATEI {
        return Err("Der Beweis ist zu groß.".into());
    }
    let mut l = Leser { b: daten, pos: 0 };
    if l.bytes(MAGIE.len())? != MAGIE {
        return Err("Das ist keine OpenTimestamps-Datei.".into());
    }
    if l.varuint()? != 1 {
        return Err("Unbekannte Hauptversion des Beweises.".into());
    }
    if l.byte()? != 0x08 {
        return Err("Der Beweis beginnt nicht mit einer SHA-256-Prüfsumme.".into());
    }
    let digest = l.bytes(32)?.to_vec();
    let mut attest = Vec::new();
    let mut zaehler = 0usize;
    baum(&mut l, &digest, 0, &mut attest, &mut zaehler)?;
    if !l.ende() {
        return Err("Nach dem Beweis folgen weitere Daten.".into());
    }
    Ok(Ots { digest, attestierungen: attest })
}

pub fn merkle_wurzel_aus_kopf(kopf_hex: &str) -> Vec<u8> {
    hex::decode(kopf_hex).map(|k| k[36..68].to_vec()).unwrap_or_default()
}
