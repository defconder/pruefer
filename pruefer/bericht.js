const ARTEN = {
  paket: "Beweispaket",
  aussage: "Aussage über das Protokoll",
  entscheidung: "Entscheidungsnachweis",
  pruefpunkt: "Prüfpunkt",
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
