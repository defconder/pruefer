use pruefer::anker::bitcoin_kopf_pruefen;
use pruefer::aussage::{aussage_pruefen, index_aufbauen, kette_pruefen};
use pruefer::ereignis::{auszug_pruefen, ereignis_hash_pruefen};
use pruefer::merkle::{blatt_hash, konsistenz_pruefen, wurzel};
use pruefer::note::pruefpunkt_pruefen;
use pruefer::regeln::beleg_pruefen;
use serde_json::Value;
use std::path::PathBuf;

struct Pruefung {
    fehler: usize,
}

impl Pruefung {
    fn pruefe(&mut self, name: &str, bedingung: bool) {
        if !bedingung {
            self.fehler += 1;
            println!("FEHLER {}", name);
        }
    }
}

fn text<'a>(v: &'a Value, schluessel: &str) -> &'a str {
    v.get(schluessel).and_then(Value::as_str).unwrap_or("")
}

fn pfad_liste(v: &Value) -> Vec<String> {
    v.as_array().map(|l| l.iter().filter_map(|p| p.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

fn main() {
    let pfad = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("../testvektoren/testvektoren.json"));
    let roh = std::fs::read_to_string(&pfad).expect("Testvektoren nicht lesbar");
    let v: Value = serde_json::from_str(&roh).expect("Testvektoren kein JSON");
    let mut p = Pruefung { fehler: 0 };
    let mut zaehler = 0usize;

    let blaetter: Vec<[u8; 32]> = v["merkle"]["blaetter"].as_array().unwrap().iter().map(|h| blatt_hash(h.as_str().unwrap())).collect();
    for (groesse, erwartet) in v["merkle"]["wurzeln"].as_object().unwrap() {
        let n: usize = groesse.parse().unwrap();
        p.pruefe(&format!("Wurzel für Größe {}", groesse), hex::encode(wurzel(&blaetter[..n])) == erwartet.as_str().unwrap());
        zaehler += 1;
    }
    for k in v["merkle"]["konsistenz"].as_array().unwrap() {
        let alt = k["alt"].as_u64().unwrap();
        let neu = k["neu"].as_u64().unwrap();
        let ok = konsistenz_pruefen(alt, neu, v["merkle"]["wurzeln"][alt.to_string()].as_str().unwrap(), v["merkle"]["wurzeln"][neu.to_string()].as_str().unwrap(), &pfad_liste(&k["pfad"]));
        p.pruefe(&format!("Konsistenz {} nach {}", alt, neu), ok);
        zaehler += 1;
    }
    let zeugen: Vec<String> = v["notizen"]["zeugen"].as_array().unwrap().iter().map(|z| z.as_str().unwrap().to_string()).collect();
    for f in v["notizen"]["faelle"].as_array().unwrap() {
        let r = pruefpunkt_pruefen(text(f, "text"), text(&v["notizen"], "logSchluessel"), &zeugen, f["schwelle"].as_u64().unwrap() as usize);
        let name = text(f, "name");
        if f["erwartet"]["lesbar"] == Value::Bool(false) {
            p.pruefe(&format!("Prüfpunkt \"{}\" wird als unlesbar abgelehnt", name), !r.lesbar);
        } else {
            p.pruefe(&format!("Prüfpunkt \"{}\": Ergebnis", name), r.bestanden == f["erwartet"]["bestanden"].as_bool().unwrap());
            p.pruefe(&format!("Prüfpunkt \"{}\": Baumgröße", name), r.groesse == f["erwartet"]["groesse"].as_u64().unwrap());
            if f["erwartet"]["logGueltig"].as_bool().unwrap_or(false) {
                p.pruefe(&format!("Prüfpunkt \"{}\": Zeugen", name), r.zeugen_gueltig as u64 == f["erwartet"]["zeugenGueltig"].as_u64().unwrap());
            }
        }
        zaehler += 1;
    }

    for f in v["ereignis"]["faelle"].as_array().unwrap() {
        p.pruefe(&format!("Ereignis \"{}\"", text(f, "name")), ereignis_hash_pruefen(&f["event"]) == f["erwartet"].as_bool().unwrap());
        zaehler += 1;
    }
    for f in v["ereignis"]["auszuege"].as_array().unwrap() {
        let name = text(f, "name");
        let r = auszug_pruefen(&f["auszug"]);
        let erwartet_ok = f["erwartet"]["ok"].as_bool().unwrap();
        p.pruefe(&format!("Auszug \"{}\": Ergebnis", name), r.is_some() == erwartet_ok);
        if let (true, Some(r)) = (erwartet_ok, r) {
            p.pruefe(&format!("Auszug \"{}\": Prüfsumme", name), r.hash == text(&f["erwartet"], "hash"));
            let mut offene = r.offene.clone();
            offene.sort();
            let erwartete: Vec<String> = pfad_liste(&f["erwartet"]["offene"]);
            p.pruefe(&format!("Auszug \"{}\": offene Felder", name), offene == erwartete);
            p.pruefe(&format!("Auszug \"{}\": verdeckte Felder", name), r.verdeckt as u64 == f["erwartet"]["verdeckt"].as_u64().unwrap());
        }
        zaehler += 1;
    }
    let ereignisse: Vec<Value> = v["aussage"]["ereignisse"].as_array().unwrap().clone();
    p.pruefe("Kette der Ereignisse", kette_pruefen(&ereignisse, &"0".repeat(64)));
    let (index_wurzel, index_anzahl) = index_aufbauen(&ereignisse);
    p.pruefe("Indexwurzel über die Ereignisse", index_wurzel == text(&v["aussage"], "indexWurzel"));
    p.pruefe("Zahl der Indexeinträge", index_anzahl as u64 == v["aussage"]["indexAnzahl"].as_u64().unwrap());
    let aussage_zeugen: Vec<String> = v["aussage"]["zeugen"].as_array().unwrap().iter().map(|z| z.as_str().unwrap().to_string()).collect();
    for f in v["aussage"]["faelle"].as_array().unwrap() {
        let name = text(f, "name");
        let r = aussage_pruefen(&f["doc"], text(&v["aussage"], "logSchluessel"), &aussage_zeugen, f["schwelle"].as_u64().unwrap() as usize);
        p.pruefe(&format!("Aussage \"{}\": Ergebnis", name), r.ok == f["erwartet"]["ok"].as_bool().unwrap());
        if f["erwartet"]["ok"].as_bool().unwrap() && r.ok {
            p.pruefe(&format!("Aussage \"{}\": Stufe", name), r.stufe as u64 == f["erwartet"]["stufe"].as_u64().unwrap());
            let erwartet: Vec<Option<u64>> = f["erwartet"]["anzahlen"].as_array().unwrap().iter().map(Value::as_u64).collect();
            p.pruefe(&format!("Aussage \"{}\": Anzahlen", name), r.anzahlen == erwartet);
        }
        zaehler += 1;
    }
    for f in v["anker"].as_array().unwrap() {
        let name = text(f, "name");
        let r = bitcoin_kopf_pruefen(text(f, "kopf"), f["mindestarbeit"].as_u64().unwrap() as u32);
        p.pruefe(&format!("Zeitanker \"{}\": Ergebnis", name), r.ok == f["erwartet"]["ok"].as_bool().unwrap());
        if f["erwartet"]["ok"].as_bool().unwrap() {
            p.pruefe(&format!("Zeitanker \"{}\": Blockprüfsumme", name), r.block_hash == text(&f["erwartet"], "blockHash"));
            p.pruefe(&format!("Zeitanker \"{}\": Blockzeit", name), r.block_zeit == f["erwartet"]["blockZeit"].as_u64().unwrap());
            p.pruefe(&format!("Zeitanker \"{}\": Arbeit", name), r.arbeit_bits as u64 == f["erwartet"]["arbeitBits"].as_u64().unwrap());
        }
        zaehler += 1;
    }
    let regelstaende = v["regeln"]["regelstaende"].as_object().unwrap();
    for f in v["regeln"]["belege"].as_array().unwrap() {
        p.pruefe(&format!("Beleg \"{}\"", text(f, "name")), beleg_pruefen(&f["beleg"], regelstaende) == f["erwartet"].as_bool().unwrap());
        zaehler += 1;
    }

    if p.fehler == 0 {
        println!("Alle Testvektoren bestanden ({} Vektoren).", zaehler);
    } else {
        println!("{} Abweichung(en).", p.fehler);
        std::process::exit(1);
    }
}
