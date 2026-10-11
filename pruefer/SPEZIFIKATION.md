# Spezifikation der Formate und Prüfschritte

Fassung 0.4. Diese Seite beschreibt genau, was der Prüfer rechnet, damit jemand ihn in einer anderen Sprache nachbauen kann. Drei Umsetzungen (JavaScript, Python, Rust) bestehen dieselben Testvektoren in `testvektoren/`. Englische Fassung: [SPECIFICATION.en.md](SPECIFICATION.en.md).

Begriffe: Ein Hex-Wert ist Kleinbuchstaben, ohne Präfix. `||` ist Verkettung. `SHA-256` rechnet über Bytes. Zeichenfolgen sind UTF-8.

## 1. Ereignisse

Ein Ereignis ist ein JSON-Objekt. Es gibt zwei Formate, erkennbar am Feld `hv`.

### 1.1 Altes Format (ohne `hv`)

Pflichtfelder `seq` (ganze Zahl, beginnt bei 0), `type`, `prevHash`, `hash`. Es gilt:

```
hash = hex( SHA-256( prevHash || JSON.stringify( ereignis ohne das Feld hash ) ) )
```

`JSON.stringify` serialisiert die Felder in der Reihenfolge, in der sie im Ereignis stehen, ohne Leerraum. Umsetzungen in anderen Sprachen müssen die Feldreihenfolge, die Zahlendarstellung und das Escaping nach ECMAScript genau nachbilden. Dieses Format wird nur noch geprüft, nicht mehr geschrieben, außer wenn ein Feldname das neue Format ausschließt.

### 1.2 Neues Format (`hv` gleich 2)

Ein Ereignis der Version 2 hat die Kopffelder `seq`, `type`, `at`, `hv`, `prevHash`, `feldWurzel`, außerdem `hash` und `salze`. Alle übrigen Felder sind Inhaltsfelder. Ihre Namen entsprechen `[A-Za-z0-9_]{1,64}`. Ein Salz ist eine Zeichenfolge aus `[A-Za-z0-9_-]{16,64}` und gehört zu genau einem Inhaltsfeld, `salze` enthält genau die Namen der Inhaltsfelder.

```
blatt(name)  = SHA-256( 0x00 || kanonisch({ "n": name, "s": salz, "w": wert }) )
feldWurzel   = Merkle-Wurzel (Abschnitt 2) über die Blätter, Felder aufsteigend nach UTF-16-Codeeinheiten des Namens
kopf         = { seq, type, at, hv: 2, prevHash, feldWurzel }
hash         = hex( SHA-256( prevHash || kanonisch(kopf) ) )
```

`kanonisch` ist JSON ohne Leerraum mit Schlüsseln aufsteigend nach UTF-16-Codeeinheiten, Zeichenfolgen und Zahlen wie `JSON.stringify`. Für Werte aus Zeichenfolgen, ganzen Zahlen, Wahrheitswerten, Listen und Objekten entspricht das RFC 8785. Gleitkommazahlen sind in den Testvektoren ausgeschlossen, weil ihre Darstellung zwischen Sprachen abweicht.

Weil die Prüfsumme nur vom Kopf und der Feldwurzel abhängt, lassen sich Inhaltsfelder verdecken, ohne die Prüfsumme zu verändern (Abschnitt 4).

Das erste Ereignis hat `prevHash` aus 64 Nullen. Für zwei Ereignisse mit aufeinanderfolgenden `seq` verlangt der Prüfer, dass das spätere das `hash` des früheren als `prevHash` nennt.

## 2. Merkle-Baum

RFC 6962 und RFC 9162 mit SHA-256.

- Blatt `i` des Protokolls ist `SHA-256( 0x00 || UTF-8( hash_i ) )`, wobei `hash_i` die Hexzeichenfolge der Prüfsumme des Ereignisses mit `seq = i` ist.
- Ein innerer Knoten ist `SHA-256( 0x01 || links || rechts )`.
- Bei `n` Blättern ist `k` die größte Zweierpotenz kleiner als `n`.
- Der leere Baum hat die Wurzel `SHA-256( "" )`.

Einschlussbeweis nach RFC 9162 Abschnitt 2.1.3, Konsistenzbeweis nach Abschnitt 2.1.4. Der Prüfer begrenzt Baumgrößen auf 2^31 - 1 und Beweispfade auf 64 Elemente.

Andere Bäume (Feldbaum, Index) benutzen dieselbe Teilung, ihre Blätter sind `SHA-256( 0x00 || Daten )` mit den dort beschriebenen Daten.

## 3. Baumkopf des Pakets

```
treeHead: {
  treeSize, rootHash (hex), headHash (hex), at (ms seit 1970),
  signature: { keyId, algorithm: "Ed25519", signature (hex) },
  publicKeyPem
}
```

`keyId` ist die Hexzeichenfolge der ersten 16 Byte von `SHA-256( SPKI-DER des öffentlichen Schlüssels )`. Signiert wird die UTF-8-Darstellung von `kanonisch({ treeSize, rootHash, headHash, at, keyId })`.

## 4. Beweispaket `defconder-beweispaket-1`

```
{ schema, createdAt, exporter, purpose, asset, treeHead, events: [ Eintrag ], analyses, original, transparenz?, hinweise }
Eintrag = { event, proof } | { auszug, proof }
```

`proof` ist der Einschlussbeweis des Ereignisses im Baum des Baumkopfs. `asset.sha256` ist die Prüfsumme der Originaldatei. `analyses[i].result.outputDigest` ist die SHA-256 von `kanonisch({ findings (ohne das Feld id), artifacts })`. Aufzeichnungen tragen eine Segmentkette: `SHA-256( vorherigeKette || "|" || sha256 || "|" || index || "|" || size || "|" || startMs || "|" || endMs )`.

### 4.1 Auszug `defconder-auszug-1`

```
{ schema, kopf: { seq, type, at, hv: 2, prevHash, feldWurzel, hash }, blaetter: [ Blatt ] }
Blatt = { h: Hex }                     verdecktes Feld, nur das Blatt
      | { n: name, s: salz, w: wert }  offenes Feld
```

Die Blätter stehen in der Reihenfolge des Feldbaums. Der Prüfer rechnet die Blätter offener Felder aus `n`, `s`, `w`, nimmt die verdeckten Blätter wie genannt, bildet die Wurzel, vergleicht sie mit `feldWurzel` und berechnet daraus `hash`. Offene Namen müssen aufsteigend und eindeutig sein. Verdeckte Feldnamen und Werte stehen nirgends im Auszug.

## 5. Prüfpunkt (Transparenzprotokoll)

Ein Prüfpunkt ist eine signierte Notiz nach [c2sp.org/signed-note](https://c2sp.org/signed-note) mit dem Text nach [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint):

```
<origin>\n
<treeSize dezimal>\n
<rootHash Base64>\n
<Erweiterungszeile>\n        (null oder mehr)
\n
U+2014 U+0020 <name> U+0020 <Base64( Kennung(4 Byte) || Signatur )>\n
```

- Jede Signaturzeile beginnt mit dem Gedankenstrich U+2014 und einem Leerzeichen.
- Schlüsselkennung `= SHA-256( Name || 0x0A || Typ || Schlüssel )[:4]`. Typ `0x01` ist eine Ed25519-Signatur des Protokolls über den Text. Typ `0x04` ist die Gegenzeichnung eines Zeugen. Typ `0xFF` mit einer Verfahrenskennung ist eine hashbasierte Signatur (Abschnitt 13).
- Gegenzeichnung (cosignature/v1): die Signatur ist `Zeit (8 Byte, big-endian) || Ed25519( "cosignature/v1\ntime <Zeit dezimal>\n" || Text )`.
- Ein Schlüssel wird als `Name+Kennung(hex)+Base64(Typ || 32 Byte)` ausgetauscht.
- Base64 muss kanonisch sein. Signaturen unbekannter Schlüssel werden ignoriert. Besteht die Signatur eines bekannten Schlüssels nicht, lehnt der Prüfer den ganzen Prüfpunkt ab.

Erweiterungszeilen sind Teil des signierten Texts, die Zeugen zeichnen sie mit. Definiert sind:

```
defconder-index-1 <Zahl der Indexeinträge dezimal> <Indexwurzel Base64>
defconder-index-2 <Zahl der Indexeinträge dezimal> <Indexwurzel Base64>
defconder-zeitanker-1 bitcoin <Blockkopf, 160 Zeichen Hex>
```

## 6. Block `transparenz` im Paket

```
transparenz: { logSchluessel, notiz, konsistenz: { von, bis, pfad: [hex] } | null }
```

`notiz` ist der Prüfpunkt als Text. Ist seine Baumgröße gleich `treeHead.treeSize`, müssen die Wurzeln gleich sein. Sonst verlangt der Prüfer `konsistenz` zwischen der kleineren und der größeren Größe. Gedeckt sind dann die Ereignisse mit `seq` kleiner als die kleinere Größe.

## 7. Prüfschritte und Vertrauensstufen eines Pakets

1. Form des Pakets und Grenzen der Eingabe (höchstens 200000 Ereignisse, Beweispfade höchstens 64 Elemente).
2. Schlüsselkennung und Signatur des Baumkopfs.
3. Wenn festgelegte Schlüsselkennungen vorliegen: gehört der Schlüssel dazu, gegebenenfalls nach den Schlüsselwechseln (Abschnitt 11)?
4. Prüfsumme und Einschlussbeweis jedes Ereignisses oder Auszugs, Verkettung aufeinanderfolgender Ereignisse.
5. Originaldatei, Ergebnisprüfsummen, Segmentkette.
6. Wenn `transparenz` vorhanden: Signatur des Protokolls, Gegenzeichnungen festgelegter Zeugen (mindestens `schwelle`), Bindung des Baumkopfs an den Prüfpunkt, Zeitanker.

Stufe 0: Schritte 1 bis 5 bestanden. Stufe 1: zusätzlich Schritt 3 mit festgelegtem Schlüssel. Stufe 2: Schritt 4 und 6 bestanden mit festgelegtem Protokollschlüssel und der geforderten Zahl festgelegter Zeugen. Sind Zeugen festgelegt, aber zu wenige Gegenzeichnungen gültig, besteht der Prüfpunkt nicht. Fehlt der Block `transparenz` ganz, obwohl Zeugen festgelegt sind, besteht das Paket nicht. Mit der Option `mindestStufe` besteht ein Dokument nur, wenn mindestens diese Stufe erreicht wird.

## 8. Aussage über das Protokoll `defconder-aussage-1`

Beweist Vollständigkeit und Abwesenheit relativ zu einem Index, dessen Wurzel im Prüfpunkt steht.

### 8.1 Index

Schlüsselfelder: `id, recordId, userId, actorId, createdBy, executedBy, publishedBy, deletedBy, uploadedBy, approvedBy, sha256, assetId, entityTypeId, actionTypeId, objectId, username, purposeId, apiKeyId`.

Für jedes Ereignis `e` entstehen diese Schlüssel (ohne Wiederholung): `typ=<type>`, und für jedes Schlüsselfeld `F` mit Zeichenfolge `V` der Länge 1 bis 200: `F=V` und `<type>|F=V`.

Zu jedem Schlüssel gehört die Liste der Prüfsummen der Ereignisse in Reihenfolge von `seq` und

```
kette_0 = 32 Nullbyte,  kette_i = SHA-256( kette_(i-1) || Rohbytes(hash_i) )
blattdaten = SHA-256( "indexregeln-1\n" || Schlüssel ) || Anzahl (8 Byte, big-endian) || kette_n
```

Die Blätter des Index sind `SHA-256( 0x00 || blattdaten )`, aufsteigend nach der ersten Komponente (Schlüsselprüfsumme, bytweise). Zwei Randblätter sind immer dabei: Schlüsselprüfsumme aus 32 Nullbyte und aus 32 Byte 0xFF, jeweils mit Anzahl 0 und Kette aus Nullbyte. Die Wurzel dieses Baums steht in der Erweiterungszeile `defconder-index-1`. Der Index deckt die Ereignisse mit `seq` kleiner als die Baumgröße des Prüfpunkts.

### 8.2 Aussagen

```
{ schema, regeln: "indexregeln-1", notiz, logSchluessel, aussagen: [ ... ] }
vorhanden: { art, schluessel, anzahl, kette, index, pfad, ereignisse?: [hex], belege?: [{ seq, pfad }] }
abwesend:  { art, schluessel, links: Blatt, rechts: Blatt }       Blatt = { keyHash, anzahl, kette, index, pfad }
```

`vorhanden` ist gültig, wenn das Blatt aus Schlüsselprüfsumme, `anzahl`, `kette` unter `index` im Index liegt und `anzahl` mindestens 1 ist. Ist `ereignisse` angegeben, müssen es `anzahl` verschiedene Prüfsummen sein, deren Kette `kette` ergibt. Ist `belege` angegeben, liegt jedes Ereignis im Baum des Prüfpunkts, in aufsteigender Folge von `seq`. `abwesend` ist gültig, wenn beide Blätter im Index liegen, ihre Indizes benachbart sind und `links.keyHash < Schlüsselprüfsumme < rechts.keyHash` gilt.

Grenze: Der Prüfer kann nicht prüfen, ob der Index vollständig aus dem Protokoll abgeleitet wurde. Das geschieht durch Nachrechnen mit dem vollständigen Protokoll (Beobachter).

## 9. Entscheidungsnachweis `defconder-entscheidung-1`

```
{ schema, notiz, logSchluessel, seq, ereignisse: [ { event | auszug, pfad } ] }
```

Das Ereignis mit `seq` trägt ein Feld `belege`. Jeder Beleg:

```
{ regel, regelstand, eingaben, ergebnis, abstand?, anzahl?, endgueltig?, grund? }
```

`regelstand` ist `hex( SHA-256( kanonisch(regel) ) )` einer Regel, die in einem Ereignis `RegelstandVeroeffentlicht` (Felder `regelId`, `regelstand`, `regel`) mit kleinerer Folgenummer steht. Die Ereignisse müssen im Prüfpunkt liegen (Einschlussbeweis gegen die Wurzel des Prüfpunkts).

### 9.1 Regelsprache `regeln-1`

`{ sprache: "regeln-1", id, art, ... }`.

- `art: "stufen"` mit `stufen: [{ id, ton }]`. Eingaben `{ nutzer, objekt }` (Töne aus den Stufen). `abstand = max(0, nutzer - objekt)`. Ergebnis `erlaubt`, wenn der Abstand 0 ist, sonst `verweigert`.
- `art: "matrix"` mit `erlaubt: { zweck: [kategorie] }` und `immerErlaubt: [kategorie]`. Eingaben `{ zweck, kategorie }`. Ergebnis `erlaubt`, wenn die Kategorie leer, in `immerErlaubt` oder in `erlaubt[zweck]` steht, sonst `verweigert`.

Der Prüfer rechnet jede Regel selbst durch: bei Stufen alle Kombinationen (dieselbe Stufe erlaubt, höhere Freigabe erlaubt nie weniger, weniger geheimes Objekt nie strenger), bei Matrizen alle aufgeführten Paare. Er verlässt sich dabei auf kein externes Beweisprogramm. Die Regel ist so klein, dass die Aufzählung selbst der Beweis ist.

Trägt ein Beleg `endgueltig: "verweigert"` mit `grund: "freigabestufe"`, muss die Regel `verweigert` ergeben. Mit `grund: "formale-pruefung"` muss die Regel `erlaubt` ergeben, die endgültige Verweigerung stammt dann aus einer weiteren Prüfung der Anwendung, die der Prüfer nicht nachrechnet.

## 10. Zeitanker

`defconder-zeitanker-1 bitcoin <Kopf>`: 80 Byte Blockkopf in Hex. Der Prüfer rechnet `SHA-256( SHA-256( Kopf ) )`, kehrt die Bytes um (Blockprüfsumme), prüft sie gegen den Zielwert aus `nBits` (Mantisse ohne Vorzeichenbit, Exponent 3 bis 32) und berechnet die Rechenarbeit als `floor( log2( 2^256 / (Ziel + 1) ) )` Bit. Er verlangt eine Mindestarbeit (Voreinstellung 64 Bit). Der Prüfpunkt ist frühestens zwei Stunden vor der Blockzeit entstanden. Das belegt "nicht früher als", nicht "nicht später als".

## 11. Schlüsselwechsel `defconder-schluesselwechsel-1`

```
{ schema, von, nach, at, entzieht, vonPem, nachPem, signatur }
```

Der alte Schlüssel signiert `kanonisch({ schema, von, nach, at, entzieht })`. Der Prüfer folgt einer Kette von Wechseln ab den festgelegten Kennungen. `entzieht: true` nimmt den alten Schlüssel aus dem Kreis der anerkannten Schlüssel.

## 12. Widerspruchsbeweis `defconder-widerspruch-1`

```
{ schema, logSchluessel, a, b }
```

`a` und `b` sind Prüfpunkte. Bewiesen ist ein Widerspruch, wenn beide die gültige Signatur des Protokolls tragen, dieselbe Baumgröße haben und verschiedene Wurzeln. Das ist ein Beweis, den jeder nachrechnen kann. Eine Rücksetzung oder ein fehlender Konsistenzbeweis ist dagegen kein kryptografischer Beweis, der Beobachter meldet sie als Alarm mit Beweisstücken.


## 13. Hashbasierte Signatur (SLH-DSA)

Ein Protokoll kann seinen Prüfpunkt zusätzlich mit einem hashbasierten Verfahren nach FIPS 205 unterschreiben. Das Verfahren rechnet nur mit SHA-256 und bleibt auch gegenüber einem Quantencomputer sicher, solange SHA-256 hält. Unterstützt sind SLH-DSA-SHA2-128s (Signatur 7856 Byte) und SLH-DSA-SHA2-128f (17088 Byte). Verwendet wird die äußere Form mit Kontextzeichenfolge (`slh_sign`, `slh_verify`), nicht die vorgehashte.

Schlüssel: `Name+Kennung+Base64( 0xFF || Verfahrenskennung || 0x00 || öffentlicher Schlüssel )`. Die Verfahrenskennung ist die ASCII-Zeichenfolge `defconder-slh-dsa-sha2-128s-1` oder `defconder-slh-dsa-sha2-128f-1`, der öffentliche Schlüssel hat 32 Byte (PK.seed || PK.root). Das Typbyte `0xFF` steht nach c2sp.org/signed-note für Typen ohne eigenes Typbyte. Die Kennung ist `SHA-256( Name || 0x0A || 0xFF || Verfahrenskennung || 0x00 || Schlüssel )[:4]`.

Signaturzeile: wie in Abschnitt 5, mit der Signatur als Wert. Signiert wird der Text des Prüfpunkts (alle Bytes bis einschließlich des Zeilenumbruchs vor der Leerzeile) mit der Kontextzeichenfolge `defconder-pruefpunkt-1`. Die Zeile trägt den Namen des Protokolls und steht hinter den Gegenzeichnungen der Zeugen, die sie nie sehen. Eine Gegenzeichnung durch Zeugen mit hashbasiertem Verfahren gibt es nicht. C2SP kennt für Gegenzeichnungen den Typ `0x06` mit ML-DSA-44, diesen Typ prüft der Prüfer nicht.

Wer einen hashbasierten Schlüssel des Protokolls festlegt, verlangt genau eine gültige Signatur dieses Schlüssels. Sie fehlt oder ist ungültig: der Prüfpunkt besteht nicht. Ohne festgelegten Schlüssel wird die Zeile ignoriert wie jede Signatur eines unbekannten Schlüssels.

## 14. Zeitbeweis `defconder-zeitbeweis-1`

Beweist, dass ein Prüfpunkt spätestens zu einer Bitcoin-Blockzeit bestand. Er ergänzt die Untergrenze des Zeitankers (Abschnitt 10) um eine Obergrenze.

```
{ schema, notiz, logSchluessel?, ots: Base64(Datei im Format von OpenTimestamps), koepfe: { "<Höhe>": <Blockkopf, 160 Zeichen Hex> } }
```

Gestempelt wird `SHA-256` über den Text des Prüfpunkts wie in Abschnitt 13. Die Datei `ots` beginnt mit den 31 Byte `00 "OpenTimestamps" 00 00 "Proof" 00 BF 89 E2 E8 84 E8 92 94`, dann Hauptversion 1 (Längenzahl nach LEB128), das Byte `08` (SHA-256), 32 Byte Prüfsumme und der Baum der Schritte. Ein Knoten liest ein Byte. `FF` kündigt einen weiteren Zweig an und das nächste Byte benennt dessen Art. `00` ist eine Bestätigung: 8 Byte Art, dann Nutzlast mit vorangestellter Länge. Alle anderen Bytes sind Operationen auf der laufenden Nachricht:

| Byte | Operation |
|---|---|
| `08` | SHA-256 |
| `03` | RIPEMD-160 |
| `F0` | anfügen (Argument mit Längenzahl, mindestens 1 Byte) |
| `F1` | voranstellen (ebenso) |
| `F2` | Bytes umkehren |
| `F3` | als kleingeschriebene Hexzeichen ausschreiben |

SHA-1 (`02`) und Keccak-256 (`67`) lehnt der Prüfer ab. Nach der Operation folgt der Teilbaum für das Ergebnis. Bestätigungsarten: `05 88 96 0D 73 D7 19 01` ist Bitcoin (Nutzlast die Blockhöhe als Längenzahl, nichts weiter), `83 DF E3 0D 2E F9 0C 8E` ist ausstehend, andere Arten werden ignoriert. Grenzen: Datei höchstens 1000000 Byte, Nachricht höchstens 4096 Byte, Tiefe höchstens 256, Knoten höchstens 20000, Längenzahlen höchstens 5 Byte, keine Bytes nach dem Baum.

Bei einer Bitcoin-Bestätigung muss die Nachricht am Ende des Pfads gleich den Bytes 36 bis 67 des Blockkopfs zur Höhe sein. Der Kopf muss seinen Zielwert erfüllen und die Mindestarbeit tragen (Abschnitt 10). Der Prüfer rechnet vorsichtig mit der Blockzeit plus zwei Stunden als spätestem Zeitpunkt. Nennt der Prüfpunkt einen Zeitanker, müssen Untergrenze und Obergrenze zusammenpassen.

## 15. Stichprobe `defconder-stichprobe-1`

Zieht aus dem Protokoll Ereignisse mit einem Zufall, den der Betreiber beim Festschreiben nicht kannte, und gibt aus fehlerfreien Ziehungen eine Schranke für den Anteil verletzender Ereignisse an.

```
{ schema, notiz, logSchluessel?, regel: { anzahl, abstand, konfidenz, pruefungen: [ "kette", "index", "entscheidung" ] },
  zeitbeweis: { ots, koepfe }, zufall: { koepfe: [ Blockkopf ] }, proben: [ Probe ] }
```

`zeitbeweis` bestätigt den Prüfpunkt (Abschnitt 14) in einem Block der Höhe `h`. `zufall.koepfe` sind genau `abstand` Blockköpfe der Höhen `h+1` bis `h+abstand`, jeder mit gültiger Arbeit und dem Vorgänger im Feld `prev` des Kopfs. Der Zufall ist die Blockprüfsumme des letzten Kopfs in der üblichen Schreibweise (mit führenden Nullen) als 32 Byte.

```
saat = SHA-256( "defconder-stichprobe-1" || 0x00 || Wurzel des Prüfpunkts (32) || Zufall (32) || Baumgröße (8, big-endian) || anzahl (8, big-endian) )
Ziehung z = 0, 1, 2, ...: w = erste 8 Byte von SHA-256( saat || z (8, big-endian) ) als Zahl ohne Vorzeichen
                          grenze = floor( 2^64 / Baumgröße ) * Baumgröße
                          ist w >= grenze, wird z übersprungen, sonst ist w mod Baumgröße die nächste Ziehung
```

Es gibt `anzahl` Ziehungen mit Zurücklegen. `proben` enthält genau einen Eintrag je gezogener Folgenummer, aufsteigend:

```
Probe = { seq, event | auszug, pfad, vorgaenger?: { hash, pfad }, indexBelege?: [ { schluessel, keyHash, anzahl, kette, index, pfad } ], entscheidung?: { ereignisse } }
```

Geprüft wird, je nach `pruefungen`: Kette (Prüfsumme des Ereignisses, Einschluss unter `seq`, bei `seq` größer 0 die Prüfsumme des Vorgängers gleich `prevHash` samt Einschluss, bei `seq` gleich 0 `prevHash` aus 64 Nullen), Index (für jeden Schlüssel des Ereignisses ein Blatt mit Anzahl mindestens 1, nur bei offenem Ereignis) und Entscheidung (jedes Ereignis der Typen `AccessDenied` und `FederatedQueryExecuted` trägt Belege, die ein Entscheidungsnachweis nach Abschnitt 9 bestätigt). Bei einem einzigen Verstoß besteht die Stichprobe nicht und nennt keine Schranke. Sonst gilt: Mit Sicherheit `konfidenz` liegt der Anteil verletzender Ereignisse unter `1 - (1 - konfidenz)^(1/anzahl)`.

Die Schranke sagt nichts über einzelne seltene Verstöße. Sie gilt nur, wenn der Prüfpunkt von Zeugen bestätigt ist, sonst hätte der Betreiber mehrere vorbereiten und den günstigen später vorlegen können.

## 16. Indexregeln 2 (Zählprotokolle)

`indexregeln-2` erweitert die Schlüssel aus Abschnitt 8.1. Hat ein Ereignis ein Feld `at` mit einer ganzen Zahl von 0 bis 253402300799999 (Millisekunden seit 1970), sei `M` der Kalendermonat nach UTC in der Form `JJJJ-MM`. Zu den bisherigen Schlüsseln kommen `monat=M` und für jeden bisherigen Schlüssel `K` der Schlüssel `K|monat=M`. Die Schlüsselprüfsumme beginnt mit `indexregeln-2\n`, die Erweiterungszeile heißt `defconder-index-2`. Ein Prüfpunkt trägt genau eine Indexzeile, eine Aussage nennt dieselben Regeln wie der Prüfpunkt.

Eine Aussage ohne `ereignisse` beweist so die Zahl der Ereignisse eines Typs in einem Monat, ohne die Ereignisse zu zeigen. Die Summe mehrerer Monate bildet, wer die bewiesenen Zahlen addiert.

## 17. Freigabe nur gegen Protokolleintrag

Daten liegen verschlüsselt. Der Schlüssel ist unter `n` Schlüsselhütern geteilt, `k` von ihnen genügen. Ein Hüter gibt seinen Anteil nur heraus, wenn die Anfrage im Protokoll eines von Zeugen bestätigten Prüfpunkts steht. Wer entschlüsselt hat, hat also einen Eintrag hinterlassen.

Teilen: Shamir über GF(2^8) mit dem Polynom `x^8 + x^4 + x^3 + x + 1`. Ein Anteil ist `x (1 bis 255) || y-Bytes`. Anfrage: ein Ereignis vom Typ `ZugriffAngefragt` mit den Feldern `objectId` und `empfaengerSchluessel` (öffentlicher X25519-Schlüssel, 32 Byte, Base64). Der Hüter prüft den Prüfpunkt gegen die festgelegten Schlüssel (Protokoll, Zeugen, Schwelle), den Einschluss und den Typ des Ereignisses. Er antwortet mit der Quittung und dem Anteil, verschlüsselt an den Empfänger: X25519 mit einem flüchtigen Schlüssel, `HKDF-SHA-256( Geheimnis, Salz = Rohbytes der Anfrageprüfsumme, Info = "defconder-freigabe-1", 32 Byte )`, AES-256-GCM mit den Rohbytes der Anfrageprüfsumme als zusätzlichen Daten.

```
Quittung = { schema: "defconder-freigabequittung-1", hueter, anfrageHash, seq, objektId, nutzerId | null, groesse, wurzel, at, anteil, signatur }
```

`signatur` ist die Ed25519-Signatur des Hüters (Typ `0x01`) über `kanonisch( Quittung ohne signatur )`, hex. `groesse` und `wurzel` nennen den Prüfpunkt, den der Hüter gesehen hat.

### 17.1 Freigabenachweis `defconder-freigabe-1`

```
{ schema, notiz, logSchluessel?, anfrage: { event | auszug, pfad }, objektId, nutzerId?, hueter?, schwelle?, quittungen: [ Quittung ], konsistenz?: { "<von>-<bis>": { pfad } } }
```

Der Prüfer verlangt: gültiger Prüfpunkt, die Anfrage liegt unter `seq` im Prüfpunkt und nennt `objectId` gleich `objektId`, mindestens `schwelle` Quittungen verschiedener festgelegter Hüter mit gültiger Signatur, die genau diese Anfrage (Prüfsumme, `seq`, Objekt, Nutzer) nennen und einen Stand `groesse` größer `seq` und höchstens der Größe des Prüfpunkts. Ist `groesse` kleiner, verlangt er den Konsistenzbeweis von `groesse` bis zur Größe des Prüfpunkts mit der Wurzel der Quittung als alter Wurzel.

### 17.2 Freigabebericht `defconder-freigabebericht-1`

Ein Hüter unterschreibt auf Verlangen eine Auskunft `{ schema: "defconder-freigabeauskunft-1", hueter, objektId, quittungen: [ { anfrageHash, at } ], bis, anzahlGesamt, signatur }` mit denselben Regeln für `signatur`.

```
{ schema, objektId, schwelle, auskuenfte: [ Auskunft ], weitereQuittungen?: [ Quittung ], aussage?: Aussage }
```

Bei `n` festgelegten Hütern und der Schwelle `k` verlangt der Prüfer mindestens `n - k + 1` gültige Auskünfte. Listen alle keine Quittung, können höchstens `k - 1` Hüter eine ausgestellt haben, und ein Schlüssel konnte nicht freigegeben werden. Eine Quittung in `weitereQuittungen`, die eine Auskunft desselben Hüters verschweigt, macht den Bericht ungültig. Ist `aussage` beigefügt (Abschnitt 8), muss jede genannte Anfrage unter den Ereignissen des Protokolls zu `objectId` stehen.

Grenzen: Die Hüter müssen unabhängig voneinander arbeiten. Wer `k` Hüter auf seine Seite bringt, entschlüsselt ohne Eintrag. Ein Eintrag steht erst im nächsten bezeugten Prüfpunkt, das kostet Zeit. Wer den Klartext hat, kann ihn kopieren.

### 17.3 Lieferung `defconder-lieferung-1` und Anteilsprüfsumme

Ein Hüter unterschreibt zu jeder Hülle, die er herausgibt: `{ schema: "defconder-lieferung-1", hueter, anfrageHash, objektId, huelle, signatur }`. `huelle` ist SHA-256 über die kanonische JSON-Form der Hülle (`fluechtig`, `nonce`, `text`, `tag`). Die Prüfsumme eines Anteils ist SHA-256 über `defconder-anteil-1`, 0x00, die Objektkennung, 0x00 und die Bytes des Anteils (erstes Byte ist die Nummer). Wer das Geheimnis teilt, legt die Prüfsummen fest und hinterlegt sie beim Objekt.

Ein Beleg gegen einen Hüter besteht aus Lieferung, Hülle, dem Hüllenschlüssel der einen Lieferung, Anfrage, Objekt, Nummer und der festgelegten Prüfsumme. Er gilt, wenn die Unterschrift stimmt, die Hülle zur Lieferung gehört, sich die Hülle mit dem Schlüssel öffnen lässt (die Prüfsumme der Verschlüsselung stimmt also) und der Anteil darin nicht zur festgelegten Prüfsumme passt. Eine Hülle, die sich nicht öffnen lässt, beweist nichts gegen den Hüter, weil der Empfänger einen falschen Schlüssel nennen könnte. Die Prüfsummen selbst muss der Prüfende vom Teilenden beziehen. Die Umsetzung steht in `hueter/empfang.mjs`, ein Prüfer für Lieferungen im Browser gibt es noch nicht.

## 18. Beweiserneuerung `defconder-erneuerung-1`

Hält den Beweiswert eines Prüfpunkts über den Bruch eines Verfahrens hinaus. Wer nach dem Bruch von Ed25519 eine Signatur fälscht, kann sie nicht vor das Quantenzeitalter datieren, wenn der Prüfpunkt davor unter einem anderen Verfahren im Zeitbeweis stand.

```
{ schema, notiz, logSchluessel?, glieder: [ Glied ] }
Glied = { schema: "defconder-erneuerungsglied-1", vorher, zeit, verfahren, schluessel, signatur, zeitbeweis?: { ots, koepfe } }
```

`vorher` ist beim ersten Glied `hex( SHA-256( Text des Prüfpunkts ) )`, sonst `hex( SHA-256( kanonisch( voriges Glied ohne zeitbeweis ) ) )`. `signatur` ist die Signatur des Schlüssels (hashbasiert mit der Kontextzeichenfolge `defconder-erneuerung-1`, oder Ed25519) über `kanonisch( Glied ohne signatur und zeitbeweis )`, hex. Der Zeitbeweis stempelt `SHA-256( kanonisch( Glied ohne zeitbeweis ) )`, also die Datei mit genau diesem Text. Die Zeiten steigen, jede genannte Zeit liegt nicht nach dem bestätigten Zeitpunkt.

Mit der Annahme `Verfahren = Datum` verlangt der Prüfer für jedes angenommen gebrochene Verfahren ein Glied anderer Art, dessen bestätigter Zeitpunkt vor dem Datum liegt und das zu diesem Zeitpunkt selbst nach der Annahme noch nicht gebrochen war.

## 19. Veröffentlichung des Prüfers `defconder-pruefer-release-1`

```
{ manifest: { schema, version, htmlSha256, summenSha256, dateien }, signaturen: [ { verfahren, schluessel, signatur } ] }
```

`htmlSha256` ist die SHA-256 der Datei `pruefer.html`, `summenSha256` die der Liste `SHA256SUMS` (Prüfsumme und Pfad aller Dateien des Prüfers). Die Seite wird reproduzierbar gebaut, der Bau liefert bei gleichem Quelltext dieselben Bytes. Signiert wird `kanonisch( manifest )` einmal mit Ed25519 und einmal hashbasiert (Kontextzeichenfolge `defconder-release-1`). Wer Schlüssel festlegt, verlangt von jedem festgelegten Schlüssel eine gültige Signatur.
