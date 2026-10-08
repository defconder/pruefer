use crate::merkle::sha256;

pub struct Ankerergebnis {
    pub ok: bool,
    pub block_hash: String,
    pub block_zeit: u64,
    pub arbeit_bits: u32,
}

fn schlecht() -> Ankerergebnis {
    Ankerergebnis { ok: false, block_hash: String::new(), block_zeit: 0, arbeit_bits: 0 }
}

pub fn bitcoin_kopf_pruefen(kopf_hex: &str, mindest_arbeit_bits: u32) -> Ankerergebnis {
    if kopf_hex.len() != 160 || !kopf_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return schlecht();
    }
    let Ok(kopf) = hex::decode(kopf_hex) else { return schlecht() };
    let zeit = u32::from_le_bytes(kopf[68..72].try_into().unwrap()) as u64;
    let bits = u32::from_le_bytes(kopf[72..76].try_into().unwrap());
    let exponent = (bits >> 24) as usize;
    let mantisse = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantisse == 0 || !(3..=32).contains(&exponent) {
        return schlecht();
    }
    let mut ziel = [0u8; 32];
    let m = mantisse.to_be_bytes();
    for (i, byte) in m[1..].iter().enumerate() {
        let position = 32 - exponent + i;
        if position < 32 {
            ziel[position] = *byte;
        }
    }
    let doppelt = sha256(&sha256(&kopf));
    let mut block = doppelt;
    block.reverse();
    if block > ziel {
        return schlecht();
    }
    let laenge = ziel.iter().position(|b| *b != 0).map(|p| (32 - p) * 8 - ziel[p].leading_zeros() as usize).unwrap_or(0);
    let arbeit_bits = (256 - laenge) as u32;
    Ankerergebnis { ok: arbeit_bits >= mindest_arbeit_bits, block_hash: hex::encode(block), block_zeit: zeit * 1000, arbeit_bits }
}
