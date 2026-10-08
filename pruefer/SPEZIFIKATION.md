# Spezifikation der Formate und Prüfschritte

Fassung 0.3. Diese Seite beschreibt genau, was der Prüfer rechnet, damit jemand ihn in einer anderen Sprache nachbauen kann. Drei Umsetzungen (JavaScript, Python, Rust) bestehen dieselben Testvektoren in `testvektoren/`. Englische Fassung: [SPECIFICATION.en.md](SPECIFICATION.en.md).

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
- Schlüsselkennung `= SHA-256( Name || 0x0A || Typ || Schlüssel )[:4]`. Typ `0x01` ist eine Ed25519-Signatur des Protokolls über den Text. Typ `0x04` ist die Gegenzeichnung eines Zeugen.
- Gegenzeichnung (cosignature/v1): die Signatur ist `Zeit (8 Byte, big-endian) || Ed25519( "cosignature/v1\ntime <Zeit dezimal>\n" || Text )`.
- Ein Schlüssel wird als `Name+Kennung(hex)+Base64(Typ || 32 Byte)` ausgetauscht.
- Base64 muss kanonisch sein. Signaturen unbekannter Schlüssel werden ignoriert. Besteht die Signatur eines bekannten Schlüssels nicht, lehnt der Prüfer den ganzen Prüfpunkt ab.

Erweiterungszeilen sind Teil des signierten Texts, die Zeugen zeichnen sie mit. Definiert sind:

```
defconder-index-1 <Zahl der Indexeinträge dezimal> <Indexwurzel Base64>
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
