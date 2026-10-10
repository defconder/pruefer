use pruefer::anker::bitcoin_kopf_pruefen;
use pruefer::aussage::{aussage_pruefen, index_aufbauen, kette_pruefen, schluessel_von, INDEXREGELN, INDEXREGELN_2};
use pruefer::ereignis::{auszug_pruefen, ereignis_hash_pruefen};
use pruefer::merkle::{blatt_hash, konsistenz_pruefen, wurzel};
use pruefer::note::pruefpunkt_pruefen;
use base64::{engine::general_purpose::STANDARD, Engine};
use pruefer::regeln::beleg_pruefen;
use pruefer::ots::{merkle_wurzel_aus_kopf, ots_auswerten, ripemd160, Bestaetigung};
use pruefer::slhdsa;
use pruefer::stichprobe;
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
        let r = pruefpunkt_pruefen(text(f, "text"), text(&v["notizen"], "logSchluessel"), &zeugen, f["schwelle"].as_u64().unwrap() as usize, None);
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
    let (index_wurzel, index_anzahl) = index_aufbauen(&ereignisse, INDEXREGELN);
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

    if let Some(h) = v.get("hashbasiert") {
        for f in h["signaturen"].as_array().unwrap() {
            let name = text(f, "name");
            let verfahren = text(f, "verfahren");
            let oeffentlich = STANDARD.decode(text(f, "oeffentlich")).unwrap();
            let nachricht = hex::decode(text(f, "nachricht")).unwrap();
            let signatur = STANDARD.decode(text(f, "signatur")).unwrap();
            let kontext = text(f, "kontext").as_bytes().to_vec();
            let erwartet = f["erwartet"].as_bool().unwrap();
            p.pruefe(&format!("Hashbasierte Signatur \"{}\"", name), slhdsa::pruefen(verfahren, &oeffentlich, &nachricht, &signatur, &kontext) == erwartet);
            if erwartet {
                for stelle in [0usize, 15, 16, 100, signatur.len() / 2, signatur.len() - 1] {
                    let mut kaputt = signatur.clone();
                    kaputt[stelle] ^= 1;
                    p.pruefe(&format!("Hashbasierte Signatur \"{}\": Veränderung an Stelle {} wird erkannt", name, stelle), !slhdsa::pruefen(verfahren, &oeffentlich, &nachricht, &kaputt, &kontext));
                }
                let mut andere = nachricht.clone();
                andere.push(1);
                p.pruefe(&format!("Hashbasierte Signatur \"{}\": andere Nachricht wird erkannt", name), !slhdsa::pruefen(verfahren, &oeffentlich, &andere, &signatur, &kontext));
                p.pruefe(&format!("Hashbasierte Signatur \"{}\": abgeschnittene Signatur wird erkannt", name), !slhdsa::pruefen(verfahren, &oeffentlich, &nachricht, &signatur[..signatur.len() - 1], &kontext));
            }
            zaehler += 1;
        }
        for f in h["pruefpunkte"].as_array().unwrap() {
            let name = text(f, "name");
            let zeugen: Vec<String> = f["zeugen"].as_array().unwrap().iter().map(|z| z.as_str().unwrap().to_string()).collect();
            let r = pruefpunkt_pruefen(text(f, "text"), text(f, "logSchluessel"), &zeugen, f["schwelle"].as_u64().unwrap() as usize, f["logSchluesselPq"].as_str());
            p.pruefe(&format!("Hashbasierter Prüfpunkt \"{}\": Ergebnis", name), r.bestanden == f["erwartet"]["bestanden"].as_bool().unwrap());
            p.pruefe(&format!("Hashbasierter Prüfpunkt \"{}\": Zustand der hashbasierten Signatur", name), r.pq == f["erwartet"]["pq"].as_bool());
            zaehler += 1;
        }
    }

    if let Some(z) = v.get("zeitbeweis") {
        for f in z["ripemd160"].as_array().unwrap() {
            let eingabe = hex::decode(text(f, "eingabe")).unwrap();
            p.pruefe("RIPEMD-160", hex::encode(ripemd160(&eingabe)) == text(f, "erwartet"));
            zaehler += 1;
        }
        for f in z["faelle"].as_array().unwrap() {
            let name = text(f, "name");
            let daten = STANDARD.decode(text(f, "ots")).unwrap();
            let r = ots_auswerten(&daten);
            let erwartet_ok = f["erwartet"]["ok"].as_bool().unwrap();
            p.pruefe(&format!("Zeitbeweis \"{}\": Ergebnis", name), r.is_ok() == erwartet_ok);
            if let (true, Ok(r)) = (erwartet_ok, r) {
                p.pruefe(&format!("Zeitbeweis \"{}\": Prüfsumme", name), hex::encode(&r.digest) == text(&f["erwartet"], "digest"));
                let ist: Vec<(String, u64, String)> = r.attestierungen.iter().map(|a| match a {
                    Bestaetigung::Bitcoin { hoehe, nachricht } => ("bitcoin".to_string(), *hoehe, hex::encode(nachricht)),
                    Bestaetigung::Ausstehend => ("ausstehend".to_string(), 0, String::new()),
                    Bestaetigung::Unbekannt => ("unbekannt".to_string(), 0, String::new()),
                }).collect();
                let erwartet: Vec<(String, u64, String)> = f["erwartet"]["attestierungen"].as_array().unwrap().iter().map(|a| (text(a, "art").to_string(), a["hoehe"].as_u64().unwrap_or(0), text(a, "nachricht").to_string())).collect();
                p.pruefe(&format!("Zeitbeweis \"{}\": Bestätigungen", name), ist == erwartet);
                if let Some(k) = f.get("kopf") {
                    p.pruefe(&format!("Zeitbeweis \"{}\": Wurzel im Blockkopf", name), hex::encode(merkle_wurzel_aus_kopf(text(k, "hex"))) == ist[0].2);
                }
            }
            zaehler += 1;
        }
    }

    if let Some(z) = v.get("zaehlbeweis") {
        let ereignisse: Vec<Value> = z["ereignisse"].as_array().unwrap().clone();
        for (i, (e, m)) in ereignisse.iter().zip(z["schluesselmengen"].as_array().unwrap()).enumerate() {
            for (feld, regeln) in [("regeln1", INDEXREGELN), ("regeln2", INDEXREGELN_2)] {
                let mut ist = schluessel_von(e, regeln);
                ist.sort();
                p.pruefe(&format!("Schlüsselmenge des Ereignisses {} unter den Indexregeln ({})", i, feld), ist == pfad_liste(&m[feld]));
                zaehler += 1;
            }
        }
        let (w1, a1) = index_aufbauen(&ereignisse, INDEXREGELN);
        let (w2, a2) = index_aufbauen(&ereignisse, INDEXREGELN_2);
        p.pruefe("Indexwurzel unter den Indexregeln 1", w1 == text(z, "indexWurzel1") && a1 as u64 == z["indexAnzahl1"].as_u64().unwrap());
        p.pruefe("Indexwurzel unter den Indexregeln 2", w2 == text(z, "indexWurzel2") && a2 as u64 == z["indexAnzahl2"].as_u64().unwrap());
        zaehler += 2;
        let z_zeugen: Vec<String> = pfad_liste(&z["zeugen"]);
        for f in z["faelle"].as_array().unwrap() {
            let name = text(f, "name");
            let r = aussage_pruefen(&f["doc"], text(z, "logSchluessel"), &z_zeugen, f["schwelle"].as_u64().unwrap() as usize);
            p.pruefe(&format!("Zählprotokoll \"{}\": Ergebnis", name), r.ok == f["erwartet"]["ok"].as_bool().unwrap());
            if f["erwartet"]["ok"].as_bool().unwrap() && r.ok {
                p.pruefe(&format!("Zählprotokoll \"{}\": Stufe", name), r.stufe as u64 == f["erwartet"]["stufe"].as_u64().unwrap());
                let erwartet: Vec<Option<u64>> = f["erwartet"]["anzahlen"].as_array().unwrap().iter().map(Value::as_u64).collect();
                p.pruefe(&format!("Zählprotokoll \"{}\": Anzahlen", name), r.anzahlen == erwartet);
            }
            zaehler += 1;
        }
    }

    if let Some(s) = v.get("stichprobe") {
        for f in s["ziehungen"].as_array().unwrap() {
            let ist = stichprobe::ziehen(text(f, "wurzelHex"), f["groesse"].as_u64().unwrap(), text(f, "beaconHex"), f["anzahl"].as_u64().unwrap()).unwrap();
            let erwartet: Vec<u64> = f["ergebnis"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
            p.pruefe(&format!("Ziehung aus {} Ereignissen mit {} Ziehungen", f["groesse"], f["anzahl"]), ist == erwartet);
            zaehler += 1;
        }
        for f in s["schranken"].as_array().unwrap() {
            let ist = stichprobe::obergrenze(f["anzahl"].as_u64().unwrap(), f["konfidenz"].as_f64().unwrap());
            let soll = f["obergrenze"].as_f64().unwrap();
            p.pruefe(&format!("Obergrenze für {} Ziehungen bei {}", f["anzahl"], f["konfidenz"]), (ist - soll).abs() <= 1e-12 * soll.abs().max(1.0));
            zaehler += 1;
        }
    }

    if p.fehler == 0 {
        println!("Alle Testvektoren bestanden ({} Vektoren).", zaehler);
    } else {
        println!("{} Abweichung(en).", p.fehler);
        std::process::exit(1);
    }
}
