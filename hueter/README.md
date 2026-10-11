# Defconder Hüter

Ein kleiner Referenzdienst für **Freigabe nur gegen Protokolleintrag**. Daten liegen verschlüsselt, der Schlüssel ist per Shamir unter `n` Hütern geteilt, `k` genügen. Ein Hüter gibt seinen Anteil nur heraus, wenn die Anfrage im Protokoll eines Prüfpunkts steht, den die festgelegten Zeugen bestätigt haben. Er stellt dafür eine signierte Quittung aus. Lizenz Apache-2.0. English version: [README.en.md](README.en.md).

Das ist ein Muster zum Verstehen, Prüfen und Nachbauen, kein gehärteter Dienst.

## Ablauf

1. Die Anwendung trägt ein Ereignis `ZugriffAngefragt` mit `objectId` und `empfaengerSchluessel` (X25519, Base64) ins Protokoll ein und wartet auf den nächsten bezeugten Prüfpunkt.
2. Der Anfragende schickt dem Hüter Ereignis, Einschlussbeweis und Prüfpunkt (`POST /freigabe`).
3. Der Hüter prüft Prüfpunkt (Protokollschlüssel, Zeugen, Schwelle), Einschluss und Typ. Danach antwortet er mit Quittung und Anteil, verschlüsselt an den Empfänger.
4. Der Anfragende sammelt `k` Anteile, setzt den Schlüssel zusammen und entschlüsselt. Die Quittungen bilden den Freigabenachweis (`defconder-freigabe-1`), den der Prüfer nachrechnet.
5. Auf Verlangen unterschreibt jeder Hüter eine Auskunft über seine Quittungen zu einem Objekt (`GET /auskunft?objekt=...`). Aus `n - k + 1` Auskünften ohne Quittung folgt, dass für das Objekt kein Schlüssel freigegeben werden konnte (`defconder-freigabebericht-1`).

## Betrieb

```bash
node hueter.mjs --name hueter-1.example.org --log "defconder.example/log+1a2b3c4d+AQ..." \
  --zeuge "zeuge-a.example+5e6f7a8b+BA..." --zeuge "zeuge-b.example+9c0d1e2f+BA..." --zeugen-schwelle 2 \
  --anteil objekt-1=<Anteil in Base64> --port 8811 --dir ./hueter-daten
```

Beim ersten Start entsteht ein Schlüssel in `hueter.key`. Der Hüter gibt den öffentlichen Schlüssel auf einem Weg weiter, den der Betreiber nicht kontrolliert. Quittungen stehen in `quittungen.jsonl`. Die Dateien `shamir.mjs` und `umschlag.mjs` teilen den Schlüssel und verschlüsseln Daten und Anteile.

## Sabotage durch einen Hüter

Shamir allein beweist nicht, wer einen falschen Anteil geliefert hat. Ein Hüter, der nach einem gültigen Protokolleintrag Müll liefert, kann die Freigabe stören, aber nichts stehlen. Dagegen gibt es zwei Schutzschichten in `empfang.mjs`:

- **Prüfsummen der Anteile.** Wer das Geheimnis teilt, legt je Anteil eine Prüfsumme fest (`pruefsummenErzeugen`) und hinterlegt sie beim Objekt. Der Empfänger vergleicht jeden entschlüsselten Anteil damit (`anteileEmpfangen`). Falsche Anteile werden aussortiert, und der Empfänger setzt den Schlüssel aus den guten zusammen, solange mindestens `k` gute da sind.
- **Unterschriebene Lieferung.** Jeder Hüter unterschreibt mit `defconder-lieferung-1`, welche Hülle er geliefert hat. Passt der Anteil in einer unterschriebenen Hülle nicht zur festgelegten Prüfsumme, kann jeder Dritte das mit dem Beleg nachrechnen (`fehlverhaltenPruefen`). Dazu gibt der Empfänger den Hüllenschlüssel dieser einen Lieferung preis, mehr nicht.

Ohne festgelegte Prüfsummen bleibt `schluesselFinden`: Es probiert Teilmengen der Anteile und prüft jeweils, ob sich der Datensatz öffnen lässt. Das findet ein gültiges Paar, wenn es eines gibt, nennt aber nur Verdächtige, keinen Beweis.

Offene Stellen: Liefert ein Hüter eine Hülle, die sich gar nicht entschlüsseln lässt, kann nur der Empfänger das behaupten, ein Dritter kann es nicht nachprüfen. Und sabotieren so viele Hüter, dass weniger als `k` gute bleiben, scheitert die Freigabe, die Schuldigen sind dann zwar benannt, aber die Daten bleiben zu. Das ist der Preis dafür, dass kein Einzelner allein entschlüsseln kann: Der Dienst stellt Vertraulichkeit vor Verfügbarkeit. Ein überprüfbares Teilen im Sinne von Feldman oder Pedersen gibt es bisher nicht.

## Grenzen

- Wer `k` Hüter auf seine Seite bringt, entschlüsselt ohne Eintrag. Die Hüter müssen unabhängig voneinander betrieben werden.
- Wer den Klartext hat, kann ihn kopieren. Das Protokoll zeigt den Zugriff, es verhindert kein Weitergeben.
- Der Eintrag steht erst im nächsten bezeugten Prüfpunkt. Zwischen Anfrage und Freigabe vergeht diese Zeit.
- Die Auskünfte der Hüter sind Zusagen. Ein Hüter, der eine falsche Auskunft unterschreibt, fällt auf, sobald jemand eine Quittung desselben Hüters dagegenhält.
- Der Dienst spricht einfaches HTTP, ohne Anmeldung der Anfragenden. Betreiben Sie ihn hinter einem Reverse-Proxy mit TLS. Wer Anteile abholen darf, entscheidet allein der Eintrag im Protokoll, nicht die Person.
- Die Anteile verlassen den Dienst verschlüsselt an den Empfängerschlüssel aus dem Ereignis. Der Hüter hält sie selbst unverschlüsselt im Aufruf, schützen Sie das Gerät.
