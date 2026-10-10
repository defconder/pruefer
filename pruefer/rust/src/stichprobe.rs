use crate::merkle::sha256;

pub const SCHEMA: &str = "defconder-stichprobe-1";
pub const MAX_ZIEHUNGEN: u64 = 100_000;

pub fn ziehen(wurzel_hex: &str, groesse: u64, beacon_hex: &str, anzahl: u64) -> Result<Vec<u64>, String> {
    if groesse < 1 || anzahl < 1 || anzahl > MAX_ZIEHUNGEN {
        return Err("Ungültige Angaben zur Ziehung.".into());
    }
    let mut roh = Vec::new();
    roh.extend_from_slice(SCHEMA.as_bytes());
    roh.push(0);
    roh.extend_from_slice(&hex::decode(wurzel_hex).map_err(|_| "Ungültige Wurzel.".to_string())?);
    roh.extend_from_slice(&hex::decode(beacon_hex).map_err(|_| "Ungültiger Zufall.".to_string())?);
    roh.extend_from_slice(&groesse.to_be_bytes());
    roh.extend_from_slice(&anzahl.to_be_bytes());
    let saat = sha256(&roh);
    let n = groesse as u128;
    let grenze = ((1u128 << 64) / n) * n;
    let mut ergebnis = Vec::with_capacity(anzahl as usize);
    let mut zaehler: u64 = 0;
    while (ergebnis.len() as u64) < anzahl {
        let mut eingabe = saat.to_vec();
        eingabe.extend_from_slice(&zaehler.to_be_bytes());
        zaehler += 1;
        let digest = sha256(&eingabe);
        let wert = u64::from_be_bytes(digest[..8].try_into().unwrap()) as u128;
        if wert >= grenze {
            continue;
        }
        ergebnis.push((wert % n) as u64);
    }
    Ok(ergebnis)
}

pub fn obergrenze(anzahl: u64, konfidenz: f64) -> f64 {
    1.0 - ((1.0 - konfidenz).ln() / anzahl as f64).exp()
}
