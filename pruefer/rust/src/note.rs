use crate::merkle::sha256;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const TYP_ED25519: u8 = 1;
pub const TYP_KOSIGNATUR: u8 = 4;
const GEDANKENSTRICH_UND_LEERZEICHEN: &str = "\u{2014} ";

#[derive(Clone)]
pub struct Schluessel {
    pub name: String,
    pub typ: u8,
    pub oeffentlich: [u8; 32],
    pub kennung: String,
}

pub struct Signatur {
    pub name: String,
    pub kennung: String,
    pub wert: Vec<u8>,
}

pub struct Notiz {
    pub koerper: String,
    pub signaturen: Vec<Signatur>,
}

pub struct Pruefpunkt {
    pub origin: String,
    pub groesse: u64,
    pub wurzel: String,
    pub erweiterungen: Vec<String>,
}

pub fn base64_streng(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 4 != 0 || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
        return Err("Ungültiges Base64.".into());
    }
    let roh = STANDARD.decode(text).map_err(|_| "Ungültiges Base64.".to_string())?;
    if STANDARD.encode(&roh) != text {
        return Err("Base64 ist nicht kanonisch.".into());
    }
    Ok(roh)
}

pub fn schluessel_kennung(name: &str, typ: u8, oeffentlich: &[u8]) -> String {
    let mut roh = Vec::new();
    roh.extend_from_slice(name.as_bytes());
    roh.push(0x0a);
    roh.push(typ);
    roh.extend_from_slice(oeffentlich);
    hex::encode(&sha256(&roh)[..4])
}

pub fn schluessel_lesen(text: &str) -> Result<Schluessel, String> {
    let roh = text.trim();
    let erstes = roh.find('+').ok_or("Schlüssel hat nicht die Form Name+Kennung+Daten.")?;
    let zweites = roh[erstes + 1..].find('+').map(|p| p + erstes + 1).ok_or("Schlüssel hat nicht die Form Name+Kennung+Daten.")?;
    if erstes < 1 {
        return Err("Schlüssel hat nicht die Form Name+Kennung+Daten.".into());
    }
    let name = &roh[..erstes];
    let kennung_hex = &roh[erstes + 1..zweites];
    let daten = &roh[zweites + 1..];
    if name.chars().any(char::is_whitespace) {
        return Err("Ungültiger Schlüsselname.".into());
    }
    let bytes = base64_streng(daten)?;
    if bytes.len() != 33 || (bytes[0] != TYP_ED25519 && bytes[0] != TYP_KOSIGNATUR) {
        return Err("Nur Ed25519-Schlüssel der Typen 1 und 4 werden unterstützt.".into());
    }
    let typ = bytes[0];
    let oeffentlich: [u8; 32] = bytes[1..].try_into().map_err(|_| "Länge".to_string())?;
    if schluessel_kennung(name, typ, &oeffentlich) != kennung_hex {
        return Err("Die Kennung passt nicht zum Schlüssel.".into());
    }
    Ok(Schluessel { name: name.to_string(), typ, oeffentlich, kennung: kennung_hex.to_string() })
}

pub fn notiz_lesen(text: &str) -> Result<Notiz, String> {
    let trennung = text.rfind("\n\n").ok_or("Notiz hat keinen Signaturteil.")?;
    let koerper = &text[..trennung + 1];
    let rest = &text[trennung + 2..];
    if !rest.ends_with('\n') {
        return Err("Signaturzeilen müssen mit Zeilenumbruch enden.".into());
    }
    if koerper.chars().any(|c| (c as u32) < 0x20 && c != '\n') {
        return Err("Steuerzeichen im Text.".into());
    }
    let zeilen: Vec<&str> = rest[..rest.len() - 1].split('\n').collect();
    if zeilen.is_empty() || zeilen.len() > 32 {
        return Err("Anzahl der Signaturen ungültig.".into());
    }
    let mut signaturen = Vec::new();
    for zeile in zeilen {
        let rumpf = zeile.strip_prefix(GEDANKENSTRICH_UND_LEERZEICHEN).ok_or("Signaturzeile beginnt nicht mit dem Gedankenstrich.")?;
        let teile: Vec<&str> = rumpf.split(' ').collect();
        if teile.len() != 2 {
            return Err("Signaturzeile ist ungültig.".into());
        }
        let blob = base64_streng(teile[1])?;
        if blob.len() < 5 {
            return Err("Signatur zu kurz.".into());
        }
        signaturen.push(Signatur { name: teile[0].to_string(), kennung: hex::encode(&blob[..4]), wert: blob[4..].to_vec() });
    }
    Ok(Notiz { koerper: koerper.to_string(), signaturen })
}

pub fn pruefpunkt_lesen(koerper: &str) -> Result<Pruefpunkt, String> {
    if !koerper.ends_with('\n') {
        return Err("Prüfpunkt endet nicht mit Zeilenumbruch.".into());
    }
    let zeilen: Vec<&str> = koerper[..koerper.len() - 1].split('\n').collect();
    if zeilen.len() < 3 || zeilen.iter().any(|z| z.is_empty()) {
        return Err("Prüfpunkt hat weniger als drei Zeilen.".into());
    }
    let g = zeilen[1];
    if g.is_empty() || !g.bytes().all(|b| b.is_ascii_digit()) || (g.len() > 1 && g.starts_with('0')) {
        return Err("Baumgröße ist keine Dezimalzahl.".into());
    }
    let groesse: u64 = g.parse().map_err(|_| "Baumgröße zu groß.".to_string())?;
    let wurzel = base64_streng(zeilen[2])?;
    if wurzel.len() != 32 {
        return Err("Wurzel hat nicht 32 Byte.".into());
    }
    Ok(Pruefpunkt { origin: zeilen[0].to_string(), groesse, wurzel: hex::encode(wurzel), erweiterungen: zeilen[3..].iter().map(|z| z.to_string()).collect() })
}

fn ed25519(oeffentlich: &[u8; 32], nachricht: &[u8], signatur: &[u8]) -> bool {
    let Ok(schluessel) = VerifyingKey::from_bytes(oeffentlich) else { return false };
    let Ok(feld) = <[u8; 64]>::try_from(signatur) else { return false };
    schluessel.verify(nachricht, &Signature::from_bytes(&feld)).is_ok()
}

pub struct Signaturergebnis {
    pub gueltig: Vec<String>,
    pub fehlerhaft: Vec<String>,
}

pub fn signaturen_pruefen(notiz: &Notiz, vertraute: &[Schluessel]) -> Signaturergebnis {
    let mut gueltig = Vec::new();
    let mut fehlerhaft = Vec::new();
    let mut gesehen: Vec<(String, String)> = Vec::new();
    for s in &notiz.signaturen {
        let Some(schluessel) = vertraute.iter().find(|v| v.name == s.name && v.kennung == s.kennung) else { continue };
        let id = (s.name.clone(), s.kennung.clone());
        if gesehen.contains(&id) {
            fehlerhaft.push(s.name.clone());
            continue;
        }
        gesehen.push(id);
        if schluessel.typ == TYP_ED25519 {
            if s.wert.len() == 64 && ed25519(&schluessel.oeffentlich, notiz.koerper.as_bytes(), &s.wert) {
                gueltig.push(s.name.clone());
            } else {
                fehlerhaft.push(s.name.clone());
            }
        } else if schluessel.typ == TYP_KOSIGNATUR {
            if s.wert.len() != 72 {
                fehlerhaft.push(s.name.clone());
                continue;
            }
            let zeit = u64::from_be_bytes(s.wert[..8].try_into().unwrap());
            let nachricht = format!("cosignature/v1\ntime {}\n{}", zeit, notiz.koerper);
            if ed25519(&schluessel.oeffentlich, nachricht.as_bytes(), &s.wert[8..]) {
                gueltig.push(s.name.clone());
            } else {
                fehlerhaft.push(s.name.clone());
            }
        }
    }
    Signaturergebnis { gueltig, fehlerhaft }
}

pub struct Punktergebnis {
    pub lesbar: bool,
    pub bestanden: bool,
    pub groesse: u64,
    pub zeugen_gueltig: usize,
}

pub fn pruefpunkt_pruefen(text: &str, log_schluessel: &str, zeugen: &[String], schwelle: usize) -> Punktergebnis {
    let Ok(notiz) = notiz_lesen(text) else { return Punktergebnis { lesbar: false, bestanden: false, groesse: 0, zeugen_gueltig: 0 } };
    let Ok(punkt) = pruefpunkt_lesen(&notiz.koerper) else { return Punktergebnis { lesbar: false, bestanden: false, groesse: 0, zeugen_gueltig: 0 } };
    let Ok(log) = schluessel_lesen(log_schluessel) else { return Punktergebnis { lesbar: true, bestanden: false, groesse: punkt.groesse, zeugen_gueltig: 0 } };
    let log_sig = signaturen_pruefen(&notiz, &[log.clone()]);
    let log_ok = log.typ == TYP_ED25519 && log.name == punkt.origin && log_sig.gueltig.len() == 1 && log_sig.fehlerhaft.is_empty();
    let zeugen_schluessel: Vec<Schluessel> = zeugen.iter().filter_map(|t| schluessel_lesen(t).ok()).filter(|z| z.typ == TYP_KOSIGNATUR).collect();
    let zeugen_sig = signaturen_pruefen(&notiz, &zeugen_schluessel);
    let zeugen_ok = zeugen_sig.gueltig.len() >= schwelle && schwelle > 0 && zeugen_sig.fehlerhaft.is_empty();
    Punktergebnis { lesbar: true, bestanden: log_ok && zeugen_ok, groesse: punkt.groesse, zeugen_gueltig: zeugen_sig.gueltig.len() }
}
