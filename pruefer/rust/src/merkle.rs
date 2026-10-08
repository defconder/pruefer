use sha2::{Digest, Sha256};

pub const MAX_BAUMGROESSE: u64 = 2_147_483_647;

pub fn sha256(daten: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(daten);
    h.finalize().into()
}

pub fn blatt_aus_daten(daten: &[u8]) -> [u8; 32] {
    let mut roh = Vec::with_capacity(daten.len() + 1);
    roh.push(0);
    roh.extend_from_slice(daten);
    sha256(&roh)
}

pub fn blatt_hash(ereignis_hash: &str) -> [u8; 32] {
    blatt_aus_daten(ereignis_hash.as_bytes())
}

pub fn knoten_hash(links: &[u8], rechts: &[u8]) -> [u8; 32] {
    let mut roh = Vec::with_capacity(65);
    roh.push(1);
    roh.extend_from_slice(links);
    roh.extend_from_slice(rechts);
    sha256(&roh)
}

fn groesste_potenz_unter(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

pub fn wurzel(blaetter: &[[u8; 32]]) -> [u8; 32] {
    match blaetter.len() {
        0 => sha256(&[]),
        1 => blaetter[0],
        n => {
            let k = groesste_potenz_unter(n);
            knoten_hash(&wurzel(&blaetter[..k]), &wurzel(&blaetter[k..]))
        }
    }
}

fn pfad_lesen(pfad: &[String]) -> Option<Vec<[u8; 32]>> {
    let mut aus = Vec::with_capacity(pfad.len());
    for p in pfad {
        let roh = hex::decode(p).ok()?;
        let feld: [u8; 32] = roh.try_into().ok()?;
        aus.push(feld);
    }
    Some(aus)
}

pub fn einschluss_pruefen(index: u64, groesse: u64, blatt: [u8; 32], pfad: &[String], wurzel_hex: &str) -> bool {
    if index >= groesse || groesse > MAX_BAUMGROESSE || pfad.len() > 64 {
        return false;
    }
    let Some(pfad) = pfad_lesen(pfad) else { return false };
    let mut fn_ = index;
    let mut sn = groesse - 1;
    let mut r = blatt;
    for geschwister in pfad {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = knoten_hash(&geschwister, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = knoten_hash(&r, &geschwister);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && hex::encode(r) == wurzel_hex
}

pub fn konsistenz_pruefen(alt_groesse: u64, neu_groesse: u64, alt_wurzel: &str, neu_wurzel: &str, beweis: &[String]) -> bool {
    if neu_groesse > MAX_BAUMGROESSE || alt_groesse > neu_groesse || beweis.len() > 64 {
        return false;
    }
    if alt_groesse == 0 {
        return beweis.is_empty();
    }
    if alt_groesse == neu_groesse {
        return beweis.is_empty() && alt_wurzel == neu_wurzel;
    }
    if beweis.is_empty() {
        return false;
    }
    let Some(mut pfad) = pfad_lesen(beweis) else { return false };
    if alt_groesse & (alt_groesse - 1) == 0 {
        let Ok(roh) = hex::decode(alt_wurzel) else { return false };
        let Ok(feld) = <[u8; 32]>::try_from(roh) else { return false };
        pfad.insert(0, feld);
    }
    let mut fn_ = alt_groesse - 1;
    let mut sn = neu_groesse - 1;
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = pfad[0];
    let mut sr = pfad[0];
    for c in &pfad[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = knoten_hash(c, &fr);
            sr = knoten_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = knoten_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    hex::encode(fr) == alt_wurzel && hex::encode(sr) == neu_wurzel && sn == 0
}
