use crate::merkle::sha256;

const WOTS_HASH: u8 = 0;
const WOTS_PK: u8 = 1;
const TREE: u8 = 2;
const FORS_TREE: u8 = 3;
const FORS_ROOTS: u8 = 4;

pub const KONTEXT: &[u8] = b"defconder-pruefpunkt-1";

#[derive(Clone, Copy)]
struct Parameter {
    n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    lg_w: usize,
}

struct Abgeleitet {
    p: Parameter,
    w: usize,
    len1: usize,
    len2: usize,
    len: usize,
    md_bytes: usize,
    baum_bits: usize,
    baum_bytes: usize,
    blatt_bytes: usize,
    m: usize,
    fors_bytes: usize,
    xmss_bytes: usize,
    signatur_bytes: usize,
}

fn parameter(name: &str) -> Option<Parameter> {
    match name {
        "sha2-128s" => Some(Parameter { n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lg_w: 4 }),
        "sha2-128f" => Some(Parameter { n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lg_w: 4 }),
        _ => None,
    }
}

fn ableiten(p: Parameter) -> Abgeleitet {
    let w = 1usize << p.lg_w;
    let len1 = (8 * p.n + p.lg_w - 1) / p.lg_w;
    let produkt = len1 * (w - 1);
    let log2 = (usize::BITS - 1 - produkt.leading_zeros()) as usize;
    let len2 = log2 / p.lg_w + 1;
    let md_bytes = (p.k * p.a + 7) / 8;
    let baum_bits = p.h - p.hp;
    let baum_bytes = (baum_bits + 7) / 8;
    let blatt_bytes = (p.hp + 7) / 8;
    let fors_bytes = p.k * (p.a + 1) * p.n;
    let xmss_bytes = (len1 + len2 + p.hp) * p.n;
    Abgeleitet { p, w, len1, len2, len: len1 + len2, md_bytes, baum_bits, baum_bytes, blatt_bytes, m: md_bytes + baum_bytes + blatt_bytes, fors_bytes, xmss_bytes, signatur_bytes: p.n + fors_bytes + p.d * xmss_bytes }
}

pub fn oeffentlich_bytes(name: &str) -> Option<usize> {
    parameter(name).map(|p| 2 * p.n)
}

fn mgf1(saat: &[u8], laenge: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(laenge + 32);
    let mut zaehler: u32 = 0;
    while out.len() < laenge {
        let mut roh = saat.to_vec();
        roh.extend_from_slice(&zaehler.to_be_bytes());
        out.extend_from_slice(&sha256(&roh));
        zaehler += 1;
    }
    out.truncate(laenge);
    out
}

fn base_2b(x: &[u8], b: usize, ausgabe: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(ausgabe);
    let mut pos = 0usize;
    let mut bits = 0usize;
    let mut summe: u64 = 0;
    for _ in 0..ausgabe {
        while bits < b {
            summe = (summe << 8) | x[pos] as u64;
            pos += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((summe >> bits) & ((1u64 << b) - 1)) as usize);
        summe &= (1u64 << bits) - 1;
    }
    out
}

type Adrs = [u8; 32];

fn set_baum(adrs: &mut Adrs, t: u128) {
    adrs[4..16].copy_from_slice(&t.to_be_bytes()[4..16]);
}

fn set_typ(adrs: &mut Adrs, typ: u8) {
    adrs[16..20].copy_from_slice(&[0, 0, 0, typ]);
    for b in adrs[20..32].iter_mut() {
        *b = 0;
    }
}

fn wort(adrs: &mut Adrs, offset: usize, v: u32) {
    adrs[offset..offset + 4].copy_from_slice(&v.to_be_bytes());
}

fn get_paar(adrs: &Adrs) -> u32 {
    u32::from_be_bytes(adrs[20..24].try_into().unwrap())
}

struct Kontext {
    n: usize,
    praefix: Vec<u8>,
}

impl Kontext {
    fn th(&self, adrs: &Adrs, m: &[u8]) -> Vec<u8> {
        let mut roh = Vec::with_capacity(self.praefix.len() + 22 + m.len());
        roh.extend_from_slice(&self.praefix);
        roh.push(adrs[3]);
        roh.extend_from_slice(&adrs[8..16]);
        roh.push(adrs[19]);
        roh.extend_from_slice(&adrs[20..32]);
        roh.extend_from_slice(m);
        sha256(&roh)[..self.n].to_vec()
    }
}

fn kette(c: &Kontext, x: &[u8], i: usize, s: usize, adrs: &mut Adrs) -> Vec<u8> {
    let mut tmp = x.to_vec();
    for j in i..i + s {
        wort(adrs, 28, j as u32);
        tmp = c.th(adrs, &tmp);
    }
    tmp
}

fn wots_ziffern(g: &Abgeleitet, m: &[u8]) -> Vec<usize> {
    let mut msg = base_2b(m, g.p.lg_w, g.len1);
    let mut pruef: usize = msg.iter().map(|z| g.w - 1 - z).sum();
    pruef <<= (8 - ((g.len2 * g.p.lg_w) % 8)) % 8;
    let pruef_bytes = (g.len2 * g.p.lg_w + 7) / 8;
    let voll = (pruef as u64).to_be_bytes();
    let pb = &voll[8 - pruef_bytes..];
    msg.extend(base_2b(pb, g.p.lg_w, g.len2));
    msg
}

fn wots_pk_aus_signatur(g: &Abgeleitet, c: &Kontext, sig: &[u8], m: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let ziffern = wots_ziffern(g, m);
    let n = g.p.n;
    let mut alle = Vec::with_capacity(g.len * n);
    for i in 0..g.len {
        wort(adrs, 24, i as u32);
        alle.extend(kette(c, &sig[i * n..(i + 1) * n], ziffern[i], g.w - 1 - ziffern[i], adrs));
    }
    let mut wots_pk = *adrs;
    set_typ(&mut wots_pk, WOTS_PK);
    wort(&mut wots_pk, 20, get_paar(adrs));
    c.th(&wots_pk, &alle)
}

fn xmss_pk_aus_signatur(g: &Abgeleitet, c: &Kontext, idx: usize, sig: &[u8], m: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let n = g.p.n;
    set_typ(adrs, WOTS_HASH);
    wort(adrs, 20, idx as u32);
    let mut knoten = wots_pk_aus_signatur(g, c, &sig[..g.len * n], m, adrs);
    set_typ(adrs, TREE);
    let mut baum_index = idx as u32;
    wort(adrs, 28, baum_index);
    for k in 0..g.p.hp {
        wort(adrs, 24, (k + 1) as u32);
        baum_index >>= 1;
        wort(adrs, 28, baum_index);
        let nachbar = &sig[(g.len + k) * n..(g.len + k + 1) * n];
        let mut paar = Vec::with_capacity(2 * n);
        if (idx >> k) & 1 == 0 {
            paar.extend_from_slice(&knoten);
            paar.extend_from_slice(nachbar);
        } else {
            paar.extend_from_slice(nachbar);
            paar.extend_from_slice(&knoten);
        }
        knoten = c.th(adrs, &paar);
    }
    knoten
}

fn fors_pk_aus_signatur(g: &Abgeleitet, c: &Kontext, sig: &[u8], md: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let n = g.p.n;
    let indizes = base_2b(md, g.p.a, g.p.k);
    let schritt = (g.p.a + 1) * n;
    let mut wurzeln = Vec::with_capacity(g.p.k * n);
    for i in 0..g.p.k {
        let teil = &sig[i * schritt..(i + 1) * schritt];
        wort(adrs, 24, 0);
        let mut baum_index = (i * (1usize << g.p.a) + indizes[i]) as u32;
        wort(adrs, 28, baum_index);
        let mut knoten = c.th(adrs, &teil[..n]);
        for j in 0..g.p.a {
            wort(adrs, 24, (j + 1) as u32);
            baum_index >>= 1;
            wort(adrs, 28, baum_index);
            let nachbar = &teil[(j + 1) * n..(j + 2) * n];
            let mut paar = Vec::with_capacity(2 * n);
            if (indizes[i] >> j) & 1 == 0 {
                paar.extend_from_slice(&knoten);
                paar.extend_from_slice(nachbar);
            } else {
                paar.extend_from_slice(nachbar);
                paar.extend_from_slice(&knoten);
            }
            knoten = c.th(adrs, &paar);
        }
        wurzeln.extend(knoten);
    }
    let mut fors_pk = *adrs;
    set_typ(&mut fors_pk, FORS_ROOTS);
    wort(&mut fors_pk, 20, get_paar(adrs));
    c.th(&fors_pk, &wurzeln)
}

pub fn pruefen(name: &str, oeffentlich: &[u8], nachricht: &[u8], signatur: &[u8], kontext: &[u8]) -> bool {
    let Some(p) = parameter(name) else { return false };
    let g = ableiten(p);
    let n = p.n;
    if oeffentlich.len() != 2 * n || signatur.len() != g.signatur_bytes || kontext.len() > 255 {
        return false;
    }
    let pk_seed = &oeffentlich[..n];
    let pk_wurzel = &oeffentlich[n..];
    let mut praefix = pk_seed.to_vec();
    praefix.extend(std::iter::repeat(0u8).take(64 - n));
    let c = Kontext { n, praefix };
    let mut m = vec![0u8, kontext.len() as u8];
    m.extend_from_slice(kontext);
    m.extend_from_slice(nachricht);
    let r = &signatur[..n];
    let fors_sig = &signatur[n..n + g.fors_bytes];
    let ht_sig = &signatur[n + g.fors_bytes..];
    let mut innen = r.to_vec();
    innen.extend_from_slice(pk_seed);
    innen.extend_from_slice(pk_wurzel);
    innen.extend_from_slice(&m);
    let innen = sha256(&innen);
    let mut saat = r.to_vec();
    saat.extend_from_slice(pk_seed);
    saat.extend_from_slice(&innen);
    let digest = mgf1(&saat, g.m);
    let md = &digest[..g.md_bytes];
    let mut baum: u128 = 0;
    for b in &digest[g.md_bytes..g.md_bytes + g.baum_bytes] {
        baum = (baum << 8) | *b as u128;
    }
    baum &= (1u128 << g.baum_bits) - 1;
    let mut blatt: usize = 0;
    for b in &digest[g.md_bytes + g.baum_bytes..g.md_bytes + g.baum_bytes + g.blatt_bytes] {
        blatt = blatt * 256 + *b as usize;
    }
    blatt %= 1usize << p.hp;
    let mut adrs: Adrs = [0u8; 32];
    set_baum(&mut adrs, baum);
    set_typ(&mut adrs, FORS_TREE);
    wort(&mut adrs, 20, blatt as u32);
    let fors_pk = fors_pk_aus_signatur(&g, &c, fors_sig, md, &mut adrs);
    let mut adrs: Adrs = [0u8; 32];
    set_baum(&mut adrs, baum);
    let mut knoten = xmss_pk_aus_signatur(&g, &c, blatt, &ht_sig[..g.xmss_bytes], &fors_pk, &mut adrs);
    let mut baum = baum;
    for j in 1..p.d {
        let blatt_j = (baum & ((1u128 << p.hp) - 1)) as usize;
        baum >>= p.hp;
        adrs[0..4].copy_from_slice(&[0, 0, 0, j as u8]);
        set_baum(&mut adrs, baum);
        knoten = xmss_pk_aus_signatur(&g, &c, blatt_j, &ht_sig[j * g.xmss_bytes..(j + 1) * g.xmss_bytes], &knoten, &mut adrs);
    }
    knoten == pk_wurzel
}
