# Sicherheitslücken melden

Bitte melden Sie Lücken im Prüfer, im Zeugen, im Beobachter oder in der Spezifikation **vertraulich** per E-Mail an justautomatemore@jamoneai.de und nicht als öffentliches Issue.

Hilfreich sind die Fassung (siehe `pruefer/package.json`), die Eingabe oder ein Testvektor, der das Problem zeigt, und das erwartete Verhalten. Von besonderem Interesse sind:

- ein Dokument, das der Prüfer annimmt, obwohl es verändert oder gefälscht ist
- ein Dokument, das der Prüfer ablehnt, obwohl es gültig ist
- Abweichungen zwischen den drei Umsetzungen (JavaScript, Python, Rust) bei derselben Eingabe
- Lücken oder Widersprüche in der Spezifikation oder im Bedrohungsmodell
- Eingaben, die den Prüfer abstürzen lassen oder unbegrenzt Speicher oder Zeit verbrauchen

Wir antworten, so schnell es geht, versprechen aber keine feste Frist. Es gibt kein Preisgeld. Wer einen Fehler meldet, wird auf Wunsch mit Namen im Änderungsprotokoll genannt.

# Reporting vulnerabilities

Please report vulnerabilities in the verifier, the witness, the observer or the specification **confidentially** by e-mail to justautomatemore@jamoneai.de, not as a public issue. Include the version, the input or a test vector that shows the problem, and the behaviour you expected. We answer as quickly as we can without promising a fixed deadline. There is no bounty. Reporters are credited in the changelog on request.
