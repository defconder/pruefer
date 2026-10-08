use crate::ereignis::{kanonisch, sha256_hex};
use serde_json::{Map, Value};

pub fn regelstand_hash(regel: &Value) -> Option<String> {
    kanonisch(regel).ok().map(|text| sha256_hex(&text))
}

pub fn regel_auswerten(regel: &Value, eingaben: &Value) -> Option<(String, Option<i64>)> {
    if regel.get("sprache")?.as_str()? != "regeln-1" {
        return None;
    }
    match regel.get("art")?.as_str()? {
        "stufen" => {
            let toene: Vec<i64> = regel.get("stufen")?.as_array()?.iter().filter_map(|s| s.get("ton").and_then(Value::as_i64)).collect();
            let nutzer = eingaben.get("nutzer")?.as_i64()?;
            let objekt = eingaben.get("objekt")?.as_i64()?;
            if !toene.contains(&nutzer) || !toene.contains(&objekt) {
                return None;
            }
            let abstand = (nutzer - objekt).max(0);
            Some((if abstand == 0 { "erlaubt" } else { "verweigert" }.to_string(), Some(abstand)))
        }
        "matrix" => {
            let kategorie = eingaben.get("kategorie").and_then(Value::as_str).unwrap_or("");
            let immer = regel.get("immerErlaubt").and_then(Value::as_array).map(|l| l.iter().any(|k| k.as_str() == Some(kategorie))).unwrap_or(false);
            if kategorie.is_empty() || immer {
                return Some(("erlaubt".into(), None));
            }
            let zweck = eingaben.get("zweck")?.as_str()?;
            let erlaubt = regel.get("erlaubt")?.get(zweck).and_then(Value::as_array).map(|l| l.iter().any(|k| k.as_str() == Some(kategorie))).unwrap_or(false);
            Some((if erlaubt { "erlaubt" } else { "verweigert" }.to_string(), None))
        }
        _ => None,
    }
}

pub fn beleg_pruefen(beleg: &Value, regelstaende: &Map<String, Value>) -> bool {
    let pruefen = || -> Option<bool> {
        let regelstand = beleg.get("regelstand")?.as_str()?;
        let regel = regelstaende.get(regelstand)?;
        if regelstand_hash(regel)? != regelstand || regel.get("id")? != beleg.get("regel")? {
            return Some(false);
        }
        let (ergebnis, abstand) = regel_auswerten(regel, beleg.get("eingaben")?)?;
        if ergebnis != beleg.get("ergebnis")?.as_str()? {
            return Some(false);
        }
        if regel.get("art")?.as_str()? == "stufen" {
            return Some(abstand == beleg.get("abstand").and_then(Value::as_i64));
        }
        Some(true)
    };
    pruefen().unwrap_or(false)
}
