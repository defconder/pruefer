use crate::ereignis::ereignis_hash_pruefen;
use crate::merkle::{blatt_aus_daten, blatt_hash, einschluss_pruefen, sha256, wurzel};
use crate::note::{base64_streng, notiz_lesen, pruefpunkt_lesen, schluessel_lesen, signaturen_pruefen, TYP_ED25519};
use serde_json::Value;
use std::collections::HashMap;

const INDEXREGELN: &str = "indexregeln-1";
const INDEXZEILE: &str = "defconder-index-1";
const SCHLUESSELFELDER: [&str; 18] = ["id", "recordId", "userId", "actorId", "createdBy", "executedBy", "publishedBy", "deletedBy", "uploadedBy", "approvedBy", "sha256", "assetId", "entityTypeId", "actionTypeId", "objectId", "username", "purposeId", "apiKeyId"];
const NULL32: [u8; 32] = [0; 32];
const EINS32: [u8; 32] = [255; 32];

pub fn schluessel_von(ereignis: &Value) -> Vec<String> {
    let mut menge: Vec<String> = Vec::new();
    let typ = ereignis.get("type").and_then(Value::as_str);
    if let Some(t) = typ {
        menge.push(format!("typ={}", t));
    }
    for feld in SCHLUESSELFELDER {
        if let Some(wert) = ereignis.get(feld).and_then(Value::as_str) {
            let laenge = wert.encode_utf16().count();
            if (1..=200).contains(&laenge) {
                for s in [format!("{}={}", feld, wert), format!("{}|{}={}", typ.unwrap_or("undefined"), feld, wert)] {
                    if !menge.contains(&s) {
                        menge.push(s);
                    }
                }
            }
        }
    }
    menge
}

fn schluessel_hash(schluessel: &str) -> [u8; 32] {
    sha256(format!("{}\n{}", INDEXREGELN, schluessel).as_bytes())
}

fn kette_plus(kette: &[u8; 32], ereignis_hash_hex: &str) -> [u8; 32] {
    let mut roh = kette.to_vec();
    roh.extend(hex::decode(ereignis_hash_hex).unwrap_or_default());
    sha256(&roh)
}

fn blatt_daten(key_hash: &[u8; 32], anzahl: u64, kette: &[u8; 32]) -> Vec<u8> {
    let mut roh = key_hash.to_vec();
    roh.extend_from_slice(&anzahl.to_be_bytes());
    roh.extend_from_slice(kette);
    roh
}

pub fn index_aufbauen(ereignisse: &[Value]) -> (String, usize) {
    let mut tabelle: HashMap<String, (u64, [u8; 32])> = HashMap::new();
    for e in ereignisse {
        let hash = e.get("hash").and_then(Value::as_str).unwrap_or("");
        for s in schluessel_von(e) {
            let eintrag = tabelle.entry(s).or_insert((0, NULL32));
            eintrag.1 = kette_plus(&eintrag.1, hash);
            eintrag.0 += 1;
        }
    }
    let mut zeilen: Vec<([u8; 32], u64, [u8; 32])> = tabelle.iter().map(|(s, (a, k))| (schluessel_hash(s), *a, *k)).collect();
    zeilen.push((NULL32, 0, NULL32));
    zeilen.push((EINS32, 0, NULL32));
    zeilen.sort_by(|a, b| a.0.cmp(&b.0));
    let blaetter: Vec<[u8; 32]> = zeilen.iter().map(|(k, a, c)| blatt_aus_daten(&blatt_daten(k, *a, c))).collect();
    (hex::encode(wurzel(&blaetter)), zeilen.len())
}

fn index_zeile_lesen(erweiterungen: &[String]) -> Option<(u64, String)> {
    let zeilen: Vec<&String> = erweiterungen.iter().filter(|z| z.starts_with(&format!("{} ", INDEXZEILE))).collect();
    if zeilen.len() != 1 {
        return None;
    }
    let teile: Vec<&str> = zeilen[0].split(' ').collect();
    if teile.len() != 3 || teile[1].is_empty() || !teile[1].bytes().all(|b| b.is_ascii_digit()) || (teile[1].len() > 1 && teile[1].starts_with('0')) {
        return None;
    }
    let anzahl: u64 = teile[1].parse().ok()?;
    let wurzel_bytes = base64_streng(teile[2]).ok()?;
    if anzahl < 2 || wurzel_bytes.len() != 32 {
        return None;
    }
    Some((anzahl, hex::encode(wurzel_bytes)))
}

fn ist_hex64(text: &Value) -> Option<&str> {
    let s = text.as_str()?;
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then_some(s)
}

fn pfad_von(wert: &Value) -> Option<Vec<String>> {
    wert.as_array()?.iter().map(|p| p.as_str().map(str::to_string)).collect()
}

fn blatt_pruefen(b: &Value, anzahl_blaetter: u64, wurzel_hex: &str) -> Option<bool> {
    let key_hash = ist_hex64(b.get("keyHash")?)?;
    let kette = ist_hex64(b.get("kette")?)?;
    let anzahl = b.get("anzahl")?.as_u64()?;
    let index = b.get("index")?.as_u64()?;
    let pfad = pfad_von(b.get("pfad")?)?;
    let kh: [u8; 32] = hex::decode(key_hash).ok()?.try_into().ok()?;
    let k: [u8; 32] = hex::decode(kette).ok()?.try_into().ok()?;
    Some(einschluss_pruefen(index, anzahl_blaetter, blatt_aus_daten(&blatt_daten(&kh, anzahl, &k)), &pfad, wurzel_hex))
}

pub struct Aussageergebnis {
    pub ok: bool,
    pub stufe: u8,
    pub anzahlen: Vec<Option<u64>>,
}

pub fn aussage_pruefen(doc: &Value, log_schluessel: &str, zeugen: &[String], schwelle: usize) -> Aussageergebnis {
    let schlecht = Aussageergebnis { ok: false, stufe: 0, anzahlen: Vec::new() };
    match aussage_intern(doc, log_schluessel, zeugen, schwelle) {
        Some(r) => r,
        None => schlecht,
    }
}

fn aussage_intern(doc: &Value, log_schluessel: &str, zeugen: &[String], schwelle: usize) -> Option<Aussageergebnis> {
    if doc.get("schema")?.as_str()? != "defconder-aussage-1" || doc.get("regeln")?.as_str()? != INDEXREGELN {
        return None;
    }
    let notiz = notiz_lesen(doc.get("notiz")?.as_str()?).ok()?;
    let punkt = pruefpunkt_lesen(&notiz.koerper).ok()?;
    let log = schluessel_lesen(log_schluessel).ok()?;
    let sig = signaturen_pruefen(&notiz, &[log.clone()]);
    if !(log.typ == TYP_ED25519 && log.name == punkt.origin && sig.gueltig.len() == 1 && sig.fehlerhaft.is_empty()) {
        return None;
    }
    let zeugen_schluessel: Vec<_> = zeugen.iter().map(|z| schluessel_lesen(z)).collect::<Result<_, _>>().ok()?;
    let zeugen_sig = signaturen_pruefen(&notiz, &zeugen_schluessel);
    let (index_anzahl, index_wurzel) = index_zeile_lesen(&punkt.erweiterungen)?;
    let mut alle = true;
    let mut anzahlen = Vec::new();
    for a in doc.get("aussagen")?.as_array()? {
        let schluessel = a.get("schluessel")?.as_str()?;
        let k = hex::encode(schluessel_hash(schluessel));
        match a.get("art")?.as_str()? {
            "vorhanden" => {
                let anzahl = a.get("anzahl")?.as_u64()?;
                let leaf = Value::Object(
                    [("keyHash", Value::String(k.clone())), ("anzahl", Value::from(anzahl)), ("kette", a.get("kette")?.clone()), ("index", a.get("index")?.clone()), ("pfad", a.get("pfad")?.clone())]
                        .into_iter()
                        .map(|(n, v)| (n.to_string(), v))
                        .collect(),
                );
                let mut ok = blatt_pruefen(&leaf, index_anzahl, &index_wurzel).unwrap_or(false) && anzahl >= 1;
                if ok {
                    if let Some(liste) = a.get("ereignisse") {
                        let hashes: Option<Vec<&str>> = liste.as_array().map(|l| l.iter().filter_map(ist_hex64).collect());
                        ok = match hashes {
                            Some(h) if h.len() as u64 == anzahl && liste.as_array().map(|l| l.len()) == Some(h.len()) && h.iter().collect::<std::collections::HashSet<_>>().len() == h.len() => {
                                let mut kette = NULL32;
                                for x in &h {
                                    kette = kette_plus(&kette, x);
                                }
                                hex::encode(kette) == a.get("kette")?.as_str()?
                            }
                            _ => false,
                        };
                        if ok {
                            if let Some(belege) = a.get("belege").and_then(Value::as_array) {
                                let h: Vec<&str> = liste.as_array()?.iter().filter_map(ist_hex64).collect();
                                let mut letzte: i64 = -1;
                                for (hash, b) in h.iter().zip(belege) {
                                    let seq = b.get("seq")?.as_i64()?;
                                    let pfad = pfad_von(b.get("pfad")?)?;
                                    if seq <= letzte || seq as u64 >= punkt.groesse || !einschluss_pruefen(seq as u64, punkt.groesse, blatt_hash(hash), &pfad, &punkt.wurzel) {
                                        ok = false;
                                        break;
                                    }
                                    letzte = seq;
                                }
                            }
                        }
                    }
                }
                anzahlen.push(Some(anzahl));
                alle &= ok;
            }
            "abwesend" => {
                let links = a.get("links")?;
                let rechts = a.get("rechts")?;
                let l_ok = blatt_pruefen(links, index_anzahl, &index_wurzel).unwrap_or(false);
                let r_ok = blatt_pruefen(rechts, index_anzahl, &index_wurzel).unwrap_or(false);
                let ok = l_ok && r_ok && rechts.get("index")?.as_u64()? == links.get("index")?.as_u64()? + 1 && links.get("keyHash")?.as_str()? < k.as_str() && k.as_str() < rechts.get("keyHash")?.as_str()?;
                anzahlen.push(None);
                alle &= ok;
            }
            _ => {
                anzahlen.push(None);
                alle = false;
            }
        }
    }
    let zeugen_ok = zeugen_sig.gueltig.len() >= schwelle && schwelle > 0 && zeugen_sig.fehlerhaft.is_empty();
    let ok = alle && (zeugen_schluessel.is_empty() || zeugen_ok);
    Some(Aussageergebnis { ok, stufe: if ok && zeugen_ok { 2 } else if ok { 1 } else { 0 }, anzahlen })
}

pub fn kette_pruefen(ereignisse: &[Value], genesis: &str) -> bool {
    let mut vorher = genesis.to_string();
    for (i, e) in ereignisse.iter().enumerate() {
        if e.get("seq").and_then(Value::as_u64) != Some(i as u64) || e.get("prevHash").and_then(Value::as_str) != Some(vorher.as_str()) || !ereignis_hash_pruefen(e) {
            return false;
        }
        vorher = e.get("hash").and_then(Value::as_str).unwrap_or("").to_string();
    }
    true
}
