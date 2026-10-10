const ARTEN = {
  paket: "Beweispaket",
  aussage: "Aussage über das Protokoll",
  entscheidung: "Entscheidungsnachweis",
  pruefpunkt: "Prüfpunkt",
  zeitbeweis: "Zeitbeweis",
  stichprobe: "Stichprobe",
  freigabe: "Freigabenachweis",
  freigabebericht: "Freigabebericht",
  erneuerung: "Beweiserneuerung",
};

function nichtBestanden(ergebnis) {
  return ergebnis.checks.filter((c) => !c.ok).map((c) => (c.detail ? `${c.label}: ${c.detail}` : c.label));
}

export function berichtErzeugen(art, ergebnis) {
  const titel = ARTEN[art] ?? "Prüfergebnis";
  const bericht = { titel, ergebnis: "", bewiesen: [], nichtBewiesen: [], gegnerBraeuchte: [], empfehlung: [], fehlgeschlagen: [], hinweise: [...(ergebnis.warnungen ?? [])] };
  if (!ergebnis.ok) {
    bericht.ergebnis = "Nicht bestanden. Verwenden Sie dieses Dokument nicht als Nachweis.";
    bericht.fehlgeschlagen = nichtBestanden(ergebnis);
    bericht.nichtBewiesen.push("Es wird nichts bewiesen. Mindestens ein Prüfschritt ist fehlgeschlagen oder konnte nicht ausgeführt werden.");
    bericht.empfehlung.push("Fordern Sie das Dokument erneut beim Betreiber an und prüfen Sie es erneut. Bleibt das Ergebnis gleich, behandeln Sie das Dokument als verfälscht oder beschädigt.");
    return bericht;
  }

  if (art === "freigabebericht") {
    bericht.ergebnis = ergebnis.ausgeschlossen ? "Für dieses Objekt wurde kein Schlüssel freigegeben." : "Für dieses Objekt ist eine Freigabe belegt oder nicht ausgeschlossen.";
    if (ergebnis.ausgeschlossen) bericht.bewiesen.push(`${ergebnis.hueterAntwortete.length} von ${ergebnis.n} Hütern (Schwelle ${ergebnis.k}) haben unterschrieben, dass sie keine Quittung für dieses Objekt ausgestellt haben. Die übrigen Hüter reichen allein nicht für einen Schlüssel.`);
    for (const f of ergebnis.freigaben ?? []) bericht.bewiesen.push(`Anfrage ${f.anfrageHash.slice(0, 16)}…: Quittungen von ${f.hueter.join(", ")}${f.sicher ? " (genug für eine Freigabe)" : f.moeglich ? " (eine Freigabe ist möglich)" : ""}.`);
    bericht.nichtBewiesen.push("Dass die Hüter ehrlich Auskunft gegeben haben. Eine falsche Auskunft fällt auf, sobald jemand eine Quittung desselben Hüters dagegenhält.");
    bericht.nichtBewiesen.push("Dass der Klartext nicht auf einem anderen Weg beschafft wurde, etwa vor Einführung der Hüter oder aus einer Kopie.");
    bericht.gegnerBraeuchte.push("Ein Gegner bräuchte so viele Hüter auf seiner Seite, wie die Schwelle verlangt, oder müsste eine falsche Auskunft unterschreiben lassen, die durch eine Quittung auffliegt.");
    bericht.hinweise.push(...(ergebnis.warnungen ?? []));
    return bericht;
  }
  const stufe = ergebnis.stufe ?? 0;
  if (stufe === 0) {
    bericht.ergebnis = "In sich stimmig (Stufe 0). Das Dokument ist seit seiner Erstellung unverändert.";
    bericht.bewiesen.push("Alle Prüfsummen, Verkettungen und Beweispfade im Dokument sind richtig nachgerechnet.");
    bericht.nichtBewiesen.push("Von wem das Dokument stammt. Das Dokument bringt seinen Schlüssel selbst mit, wer einen eigenen Schlüssel erzeugt, besteht diese Stufe ebenso.");
    bericht.gegnerBraeuchte.push("Ein Gegner braucht nur einen eigenen Schlüssel und etwas Rechenzeit, um ein Dokument zu erzeugen, das diese Stufe besteht.");
    bericht.empfehlung.push("Legen Sie die Kennung des Schlüssels des Betreibers fest, die Sie auf einem anderen Weg als dem Dokument selbst erhalten haben, und prüfen Sie erneut.");
  } else if (stufe === 1) {
    bericht.ergebnis = "Schlüssel gebunden (Stufe 1). Das Dokument stammt vom Inhaber des festgelegten Schlüssels und ist unverändert.";
    bericht.bewiesen.push("Alles aus Stufe 0.");
    bericht.bewiesen.push("Das Dokument wurde mit dem Schlüssel unterschrieben, den Sie festgelegt haben.");
    bericht.nichtBewiesen.push("Dass der Betreiber das Protokoll vor der Unterschrift nicht neu geschrieben hat. Der Betreiber könnte Ereignisse geändert oder weggelassen und danach unterschrieben haben.");
    bericht.gegnerBraeuchte.push("Der Betreiber selbst, oder jemand mit Zugriff auf den Schlüssel des Betreibers, kann ein Protokoll erzeugen, das diese Stufe besteht.");
    bericht.empfehlung.push("Legen Sie zusätzlich den Schlüssel des Protokolls und die Schlüssel unabhängiger Zeugen fest, um Stufe 2 zu erreichen.");
  } else {
    bericht.ergebnis = `Bezeugt (Stufe 2). ${ergebnis.stufeText}.`;
    bericht.bewiesen.push("Alles aus Stufe 1.");
    bericht.bewiesen.push("Unabhängige Zeugen, deren Schlüssel Sie festgelegt haben, haben den Stand des Protokolls bestätigt und bei jedem neuen Stand verlangt, dass er lückenlos aus dem vorigen folgt.");
    bericht.bewiesen.push("Der Betreiber kann den bezeugten Teil des Protokolls nicht mehr heimlich ändern, ohne dass die Zeugen den Widerspruch bemerken.");
    bericht.nichtBewiesen.push("Dass die Zeugen tatsächlich unabhängig vom Betreiber sind. Das beurteilen Sie, nicht der Prüfer.");
    bericht.nichtBewiesen.push("Dass das, was im Protokoll steht, inhaltlich wahr ist. Es ist nur nachweislich unverändert.");
    bericht.gegnerBraeuchte.push("Ein Gegner braucht den Betreiber und mindestens so viele Zeugen auf seiner Seite, wie Sie als Schwelle verlangt haben, oder einen Bruch von SHA-256 oder Ed25519.");
    bericht.gegnerBraeuchte.push("Wurde ein Zeuge zum allerersten Stand des Protokolls erst nach einer Fälschung hinzugezogen, fällt diese Fälschung nicht auf.");
  }

  if (stufe >= 1) {
    if (ergebnis.pq === true) {
      bericht.bewiesen.push("Der Prüfpunkt trägt zusätzlich eine hashbasierte Signatur (SLH-DSA, nur auf SHA-256 gestützt), die ein künftiger Quantencomputer nicht fälschen kann, solange SHA-256 hält.");
      bericht.nichtBewiesen.push("Dass die Gegenzeichnungen der Zeugen quantensicher sind. Sie beruhen auf Ed25519.");
    } else {
      bericht.hinweise.push("Die Signaturen dieses Dokuments beruhen auf Ed25519. Ein künftiger Quantencomputer könnte sie fälschen. Schutz bieten eine hashbasierte Signatur des Protokolls (Option --log-schluessel-pq) und ein Zeitanker, der zeigt, dass der Prüfpunkt früher bestand.");
    }
  }

  if (art === "paket") {
    bericht.nichtBewiesen.push("Dass das Protokoll alle Ereignisse zur Datei enthält. Ein Paket zeigt nur die Ereignisse, die der Betreiber beigelegt hat.");
    const auszuege = ergebnis.checks.find((c) => c.id === "ereignisse" && /als Auszug/.test(c.label));
    if (auszuege) bericht.hinweise.push("Ein Teil der Ereignisse liegt als Auszug mit verdeckten Feldern vor. Die verdeckten Felder wurden nicht geprüft, aber die Prüfsumme des ganzen Ereignisses bindet sie, nichts kann nachträglich ausgetauscht werden.");
  }
  if (art === "aussage") {
    bericht.bewiesen.push(...(ergebnis.aussagen ?? []).filter((a) => a.ok).map((a) => a.text));
    bericht.nichtBewiesen.push("Dass der Index vollständig aus dem Protokoll abgeleitet wurde. Das lässt sich nur durch Nachrechnen mit dem vollständigen Protokoll prüfen, zum Beispiel mit dem Beobachter.");
    bericht.nichtBewiesen.push("Dass ein Ereignis nicht doch unter einem Schlüssel steht, den die Indexregeln nicht vorsehen.");
  }
  if (art === "zeitbeweis") {
    if (ergebnis.spaetestens) bericht.bewiesen.push(`Der signierte Text des Prüfpunkts bestand spätestens am ${new Date(ergebnis.spaetestens).toISOString()}. Ein später erzeugter Prüfpunkt, etwa mit einer gefälschten Signatur, kann diesen Beweis nicht nachholen.`);
    if (ergebnis.fruehestens) bericht.bewiesen.push(`Der Prüfpunkt entstand frühestens am ${new Date(ergebnis.fruehestens).toISOString()}, denn er nennt einen Bitcoin-Block, der damals schon bestand.`);
    bericht.nichtBewiesen.push("Dass der Inhalt des Prüfpunkts wahr oder vollständig ist.");
    bericht.nichtBewiesen.push("Den genauen Zeitpunkt. Blockzeiten sind nur auf etwa zwei Stunden genau.");
    bericht.gegnerBraeuchte.push("Ein Gegner müsste einen Bitcoin-Block mit passender Transaktionswurzel erzeugen, das kostet die gesamte Rechenarbeit des Netzes.");
  }
  if (art === "erneuerung") {
    const liste = ergebnis.glieder ?? [];
    bericht.bewiesen.push(`Der Prüfpunkt wurde ${liste.length} Mal erneuert: ${liste.map((g) => `${g.verfahren ?? "unbekannt"}${g.spaetestens ? ` (bestätigt spätestens ${new Date(g.spaetestens).toISOString().slice(0, 10)})` : " (ohne Zeitbeweis)"}`).join(", dann ")}.`);
    for (const c of ergebnis.checks.filter((x) => x.id === "bruchfest" && x.ok)) bericht.bewiesen.push(c.label + ".");
    bericht.nichtBewiesen.push("Dass der Inhalt des Prüfpunkts wahr ist. Die Erneuerung hält nur den Beweiswert über den Bruch eines Verfahrens hinaus.");
    bericht.nichtBewiesen.push("Dass ein Verfahren nicht schon früher gebrochen wurde, als Sie angenommen haben.");
    bericht.gegnerBraeuchte.push("Ein Gegner müsste vor der Erneuerung das ursprüngliche Verfahren brechen oder gleichzeitig das erneuernde Verfahren und den Bitcoin-Zeitbeweis überwinden.");
  }
  if (art === "freigabe" && ergebnis.anfrage) {
    bericht.bewiesen.push(`Die Anfrage nach ${ergebnis.anfrage.objektId} (Ereignis ${ergebnis.anfrage.seq}) stand im Protokoll, bevor ${ergebnis.gueltigeHueter.length} festgelegte Hüter (${ergebnis.gueltigeHueter.join(", ")}) ihren Anteil am Schlüssel herausgaben. Zum Entschlüsseln braucht es ${ergebnis.schwelle}.`);
    bericht.nichtBewiesen.push("Dass die Hüter nicht zusammengearbeitet haben. Mit so vielen Hütern, wie die Schwelle verlangt, und dem Betreiber ließe sich eine Freigabe ohne Eintrag erzwingen.");
    bericht.nichtBewiesen.push("Dass der Empfänger den Klartext nicht weitergegeben hat. Das Protokoll zeigt den Zugriff, es verhindert kein Kopieren danach.");
    bericht.gegnerBraeuchte.push(`Ein Gegner bräuchte ${ergebnis.schwelle} Hüter auf seiner Seite oder den Schlüssel selbst. Er kann dann entschlüsseln, ohne dass ein Eintrag entsteht.`);
  }
  if (art === "stichprobe" && ergebnis.stichprobe) {
    const s = ergebnis.stichprobe;
    const prozent = (x) => `${(Math.ceil(x * 1e6) / 1e4).toLocaleString("de-DE", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} %`;
    if (s.obergrenze !== null) {
      bericht.bewiesen.push(`Aus dem Protokoll bis Größe ${s.groesse} wurden mit dem Zufall aus einem Bitcoin-Block ${s.gezogen} Ereignisse gezogen (${s.verschieden} verschiedene). Bei allen stimmten die geprüften Eigenschaften.`);
      bericht.bewiesen.push(`Mit ${Math.round(s.konfidenz * 1000) / 10} % Sicherheit liegt der Anteil der Ereignisse, die eine der geprüften Eigenschaften verletzen, unter ${prozent(s.obergrenze)}.`);
    }
    if (s.einzelverstossUnentdeckt !== null && s.einzelverstossUnentdeckt !== undefined) bericht.nichtBewiesen.push(`Dass kein einzelnes Ereignis die Eigenschaften verletzt. Ein einzelner Verstoß bliebe mit Wahrscheinlichkeit ${(Math.floor(s.einzelverstossUnentdeckt * 10000) / 100).toLocaleString("de-DE")} % unentdeckt.`);
    bericht.gegnerBraeuchte.push("Der Betreiber müsste den Block mit dem Zufall vorhersagen oder mehrere Prüfpunkte vorbereiten und von den Zeugen bestätigen lassen. Das scheitert, wenn die Zeugen nur einen Stand bestätigen, der lückenlos aus dem vorigen folgt.");
    if (s.fehler && (s.fehler.kette.length || s.fehler.index.length || s.fehler.entscheidung.length)) bericht.fehlgeschlagen.push(...s.fehler.kette, ...s.fehler.index, ...s.fehler.entscheidung);
  }
  if (art === "entscheidung") {
    for (const b of ergebnis.belege ?? []) {
      if (b.ok) bericht.bewiesen.push(`Die Entscheidung nach der Regel „${b.regel}“ (${b.ergebnis}${b.anzahl ? `, ${b.anzahl} Fälle` : ""}) entspricht der im Protokoll veröffentlichten Regel.`);
    }
    bericht.nichtBewiesen.push("Dass die Eingaben, zum Beispiel die Freigabestufe eines Nutzers, richtig erfasst waren.");
    bericht.nichtBewiesen.push("Dass die Regel fachlich richtig ist. Nachgewiesen ist nur, dass die Anwendung nach der veröffentlichten Regel entschieden hat und dass die Regel in sich stimmig ist.");
  }
  return bericht;
}

export function berichtText(bericht) {
  const teile = [`${bericht.titel}: ${bericht.ergebnis}`, ""];
  const abschnitt = (name, liste) => {
    if (!liste.length) return;
    teile.push(name);
    for (const z of liste) teile.push(`  - ${z}`);
    teile.push("");
  };
  abschnitt("Fehlgeschlagene Prüfschritte:", bericht.fehlgeschlagen);
  abschnitt("Was bewiesen ist:", bericht.bewiesen);
  abschnitt("Was nicht bewiesen ist:", bericht.nichtBewiesen);
  abschnitt("Was ein Gegner dafür bräuchte:", bericht.gegnerBraeuchte);
  abschnitt("Empfehlung:", bericht.empfehlung);
  abschnitt("Hinweise:", bericht.hinweise);
  return teile.join("\n").trimEnd() + "\n";
}
