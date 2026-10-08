use crate::merkle::{blatt_aus_daten, sha256, wurzel};
use serde_json::{Map, Value};

const RESERVIERT: [&str; 8] = ["seq", "type", "at", "hv", "prevHash", "feldWurzel", "hash", "salze"];

fn feldname_gueltig(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn salz_gueltig(salz: &str) -> bool {
    salz.len() >= 16 && salz.len() <= 64 && salz.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

pub fn kanonisch(wert: &Value) -> Result<String, String> {
    Ok(match wert {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if n.is_f64() {
                return Err("Gleitkommazahlen werden in dieser Umsetzung nicht unterstützt.".into());
            }
            n.to_string()
        }
        Value::String(s) => serde_json::to_string(s).map_err(|e| e.to_string())?,
        Value::Array(liste) => {
            let teile: Result<Vec<String>, String> = liste.iter().map(kanonisch).collect();
            format!("[{}]", teile?.join(","))
        }
        Value::Object(map) => {
            let mut schluessel: Vec<&String> = map.keys().collect();
            schluessel.sort_by_key(|k| utf16(k));
            let mut teile = Vec::new();
            for k in schluessel {
                teile.push(format!("{}:{}", serde_json::to_string(k).map_err(|e| e.to_string())?, kanonisch(&map[k])?));
            }
            format!("{{{}}}", teile.join(","))
        }
    })
}

pub fn sha256_hex(text: &str) -> String {
    hex::encode(sha256(text.as_bytes()))
}

fn inhaltsnamen(ereignis: &Map<String, Value>) -> Vec<String> {
    let mut namen: Vec<String> = ereignis.keys().filter(|k| !RESERVIERT.contains(&k.as_str())).cloned().collect();
    namen.sort_by_key(|n| utf16(n));
    namen
}

fn feld_blatt(name: &str, salz: &str, wert: &Value) -> Result<[u8; 32], String> {
    let mut m = Map::new();
    m.insert("n".into(), Value::String(name.into()));
    m.insert("s".into(), Value::String(salz.into()));
    m.insert("w".into(), wert.clone());
    Ok(blatt_aus_daten(kanonisch(&Value::Object(m))?.as_bytes()))
}

fn feld_wurzel(ereignis: &Map<String, Value>) -> Result<String, String> {
    let namen = inhaltsnamen(ereignis);
    let salze = ereignis.get("salze").and_then(Value::as_object).ok_or("Die Salze fehlen.")?;
    let mut salz_namen: Vec<String> = salze.keys().cloned().collect();
    salz_namen.sort_by_key(|n| utf16(n));
    if salz_namen != namen {
        return Err("Die Salze passen nicht zu den Feldern.".into());
    }
    let mut blaetter = Vec::new();
    for name in &namen {
        let salz = salze[name].as_str().ok_or("Ungültiges Salz.")?;
        if !feldname_gueltig(name) || !salz_gueltig(salz) {
            return Err("Ungültiger Feldname oder ungültiges Salz.".into());
        }
        blaetter.push(feld_blatt(name, salz, &ereignis[name])?);
    }
    Ok(hex::encode(wurzel(&blaetter)))
}

fn kopf_hash(vorgaenger: &str, kopf: &Value) -> Result<String, String> {
    Ok(sha256_hex(&format!("{}{}", vorgaenger, kanonisch(kopf)?)))
}

fn kopf_von(quelle: &Map<String, Value>) -> Result<Value, String> {
    let mut kopf = Map::new();
    for k in ["seq", "type", "at", "hv", "prevHash", "feldWurzel"] {
        kopf.insert(k.into(), quelle.get(k).ok_or("Kopf unvollständig.")?.clone());
    }
    Ok(Value::Object(kopf))
}

pub fn ereignis_hash_pruefen(ereignis: &Value) -> bool {
    let Some(map) = ereignis.as_object() else { return false };
    let Some(hash) = map.get("hash").and_then(Value::as_str) else { return false };
    let mut basis = Map::new();
    for (k, v) in map {
        if k != "hash" {
            basis.insert(k.clone(), v.clone());
        }
    }
    let Some(vorgaenger) = basis.get("prevHash").and_then(Value::as_str).map(str::to_string) else { return false };
    let berechnet = match basis.get("hv") {
        None => match serde_json::to_string(&Value::Object(basis.clone())) {
            Ok(text) => sha256_hex(&format!("{}{}", vorgaenger, text)),
            Err(_) => return false,
        },
        Some(hv) if hv.as_i64() == Some(2) => {
            match feld_wurzel(&basis) {
                Ok(w) if basis.get("feldWurzel").and_then(Value::as_str) == Some(w.as_str()) => {}
                _ => return false,
            }
            match kopf_von(&basis).and_then(|k| kopf_hash(&vorgaenger, &k)) {
                Ok(h) => h,
                Err(_) => return false,
            }
        }
        Some(_) => return false,
    };
    berechnet == hash
}

pub struct AuszugErgebnis {
    pub hash: String,
    pub offene: Vec<String>,
    pub verdeckt: usize,
}

pub fn auszug_pruefen(auszug: &Value) -> Option<AuszugErgebnis> {
    if auszug.get("schema")?.as_str()? != "defconder-auszug-1" {
        return None;
    }
    let kopf = auszug.get("kopf")?.as_object()?;
    if kopf.get("hv")?.as_i64()? != 2 {
        return None;
    }
    let mut blaetter = Vec::new();
    let mut offene: Vec<String> = Vec::new();
    for b in auszug.get("blaetter")?.as_array()? {
        let b = b.as_object()?;
        if let Some(h) = b.get("h").and_then(Value::as_str) {
            let roh = hex::decode(h).ok()?;
            if h.len() != 64 || h.bytes().any(|c| c.is_ascii_uppercase()) {
                return None;
            }
            blaetter.push(<[u8; 32]>::try_from(roh).ok()?);
            continue;
        }
        let name = b.get("n")?.as_str()?;
        let salz = b.get("s")?.as_str()?;
        let wert = b.get("w")?;
        if !feldname_gueltig(name) || RESERVIERT.contains(&name) || !salz_gueltig(salz) {
            return None;
        }
        if let Some(letzter) = offene.last() {
            if utf16(name) <= utf16(letzter) {
                return None;
            }
        }
        blaetter.push(feld_blatt(name, salz, wert).ok()?);
        offene.push(name.to_string());
    }
    if hex::encode(wurzel(&blaetter)) != kopf.get("feldWurzel")?.as_str()? {
        return None;
    }
    let hash = kopf_hash(kopf.get("prevHash")?.as_str()?, &kopf_von(kopf).ok()?).ok()?;
    if hash != kopf.get("hash")?.as_str()? {
        return None;
    }
    let verdeckt = blaetter.len() - offene.len();
    Some(AuszugErgebnis { hash, offene, verdeckt })
}
