import { hex, unhex, sha256Bytes, leafHash, verifyInclusion, verifyConsistency, MAX_BAUMGROESSE } from "./merkle.js";
import { ereignisHashPruefen, auszugPruefen } from "./ereignis.js";
import { zeitankerPruefen } from "./zeitanker.js";
import { notizLesen, pruefpunktLesen, schluesselLesen, signaturenPruefen, base64Decode, TYP_ED25519, TYP_KOSIGNATUR } from "./note.js";

const encoder = new TextEncoder();
const MAX_EREIGNISSE = 200000;

export { hex, unhex, leafHash, verifyInclusion, verifyConsistency };

export async function sha256(data) {
  return hex(await sha256Bytes(data));
}

export function canonicalJson(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

function pemBytes(publicKeyPem) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length > 4096) throw new Error("Ungültiger Schlüssel.");
  return base64Decode(publicKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
}

async function verifySignature(head) {
  try {
    if (head.signature.algorithm !== "Ed25519") return { error: "Unbekanntes Signaturverfahren." };
    const key = await globalThis.crypto.subtle.importKey("spki", pemBytes(head.publicKeyPem), { name: "Ed25519" }, false, ["verify"]);
    const body = canonicalJson({ treeSize: head.treeSize, rootHash: head.rootHash, headHash: head.headHash, at: head.at, keyId: head.signature.keyId });
    return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, unhex(head.signature.signature), encoder.encode(body));
  } catch (err) {
    return { error: String(err.message ?? err) };
  }
}

export async function keyIdOf(publicKeyPem) {
  return (await sha256(pemBytes(publicKeyPem))).slice(0, 32);
}

export async function schluesselwechselPruefen(kette, vertraute) {
  const aktuell = new Set(vertraute);
  const checks = [];
  const liste = Array.isArray(kette) ? kette : kette ? [kette] : [];
  for (const w of liste) {
    try {
      if (w?.schema !== "defconder-schluesselwechsel-1") throw new Error("Unbekanntes Format.");
      if (!aktuell.has(w.von)) throw new Error("Der alte Schlüssel gehört nicht zu den vertrauten Schlüsseln.");
      if ((await keyIdOf(w.vonPem)) !== w.von || (await keyIdOf(w.nachPem)) !== w.nach) throw new Error("Eine Kennung passt nicht zum Schlüssel.");
      const key = await globalThis.crypto.subtle.importKey("spki", pemBytes(w.vonPem), { name: "Ed25519" }, false, ["verify"]);
      const nachricht = canonicalJson({ schema: w.schema, von: w.von, nach: w.nach, at: w.at, entzieht: w.entzieht === true });
      const ok = await globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, unhex(w.signatur), encoder.encode(nachricht));
      if (!ok) throw new Error("Die Signatur des alten Schlüssels ist ungültig.");
      aktuell.add(w.nach);
      if (w.entzieht === true) aktuell.delete(w.von);
      checks.push({ ok: true, label: `Schlüsselwechsel von ${w.von.slice(0, 8)}… auf ${w.nach.slice(0, 8)}… ist vom alten Schlüssel bestätigt`, detail: w.entzieht === true ? "Der alte Schlüssel wird nicht mehr anerkannt." : "" });
    } catch (err) {
      checks.push({ ok: false, label: "Schlüsselwechsel", detail: String(err?.message ?? err) });
      return { ok: false, vertraute: [...aktuell], checks };
    }
  }
  return { ok: true, vertraute: [...aktuell], checks };
}

function pruefeForm(pkg) {
  if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) return "Das Paket ist kein Objekt.";
  const head = pkg.treeHead;
  if (!head || typeof head !== "object") return "Der Baumkopf fehlt.";
  if (!Number.isInteger(head.treeSize) || head.treeSize < 1 || head.treeSize > MAX_BAUMGROESSE) return "Die Baumgröße ist ungültig.";
  if (typeof head.rootHash !== "string" || !/^[0-9a-f]{64}$/.test(head.rootHash)) return "Die Baumwurzel ist ungültig.";
  if (!head.signature || typeof head.signature.signature !== "string" || typeof head.signature.keyId !== "string") return "Die Signatur fehlt.";
  if (!Array.isArray(pkg.events) || pkg.events.length > MAX_EREIGNISSE) return "Die Ereignisliste fehlt oder ist zu groß.";
  for (const entry of pkg.events) {
    if (!entry || typeof entry !== "object" || !Array.isArray(entry.proof)) return "Ein Ereignis hat nicht die erwartete Form.";
    const ereignis = entry.event ?? entry.auszug?.kopf;
    if (!ereignis || typeof ereignis !== "object" || (entry.event && entry.auszug)) return "Ein Ereignis hat nicht die erwartete Form.";
    if (typeof ereignis.hash !== "string" || typeof ereignis.prevHash !== "string" || !Number.isInteger(ereignis.seq)) return "Ein Ereignis hat keine Prüfsumme, Vorgängerprüfsumme oder Folgenummer.";
  }
  if (!pkg.asset || typeof pkg.asset !== "object" || typeof pkg.asset.sha256 !== "string" || typeof pkg.asset.id !== "string") return "Die Angaben zur Datei fehlen.";
  if (!Array.isArray(pkg.analyses)) return "Die Analysen fehlen.";
  return null;
}

async function pruefeTransparenz(pkg, opts, head, add) {
  const t = pkg.transparenz;
  const ergebnis = { vorhanden: Boolean(t), logGebunden: false, zeugenGueltig: 0, schwelle: 0, gebunden: false, gedeckt: 0, zeitanker: null };
  if (!t) return ergebnis;
  let notiz;
  let punkt;
  try {
    notiz = notizLesen(t.notiz);
    punkt = pruefpunktLesen(notiz.koerper);
  } catch (err) {
    add("transparenz_form", "Prüfpunkt der Transparenzliste ist lesbar", false, String(err.message ?? err));
    return ergebnis;
  }
  const festgelegterLog = opts.logSchluessel ? await schluesselLesen(opts.logSchluessel) : null;
  const eingebetteterLog = typeof t.logSchluessel === "string" ? await schluesselLesen(t.logSchluessel).catch(() => null) : null;
  const logSchluessel = festgelegterLog ?? eingebetteterLog;
  if (!logSchluessel || logSchluessel.typ !== TYP_ED25519) {
    add("transparenz_log", "Signatur des Protokolls unter dem Prüfpunkt", false, "Es steht kein Schlüssel des Protokolls zur Verfügung.");
    return ergebnis;
  }
  if (logSchluessel.name !== punkt.origin) {
    add("transparenz_log", "Name des Protokolls im Prüfpunkt passt zum Schlüssel", false, `Prüfpunkt ${punkt.origin}, Schlüssel ${logSchluessel.name}`);
    return ergebnis;
  }
  const logSig = await signaturenPruefen(notiz, [logSchluessel]);
  ergebnis.logGebunden = Boolean(festgelegterLog) && logSig.gueltig.length === 1 && logSig.fehlerhaft.length === 0;
  add("transparenz_log", festgelegterLog ? "Prüfpunkt trägt die Signatur des festgelegten Protokollschlüssels" : "Prüfpunkt trägt eine Signatur des mitgelieferten Protokollschlüssels (nicht festgelegt)", logSig.gueltig.length === 1 && logSig.fehlerhaft.length === 0, `Baumgröße ${punkt.groesse}, Wurzel ${punkt.wurzelHex.slice(0, 16)}…`);

  if (logSig.gueltig.length === 1 && logSig.fehlerhaft.length === 0) ergebnis.zeitanker = await zeitankerPruefen(punkt.erweiterungen, opts, add);

  const zeugen = await Promise.all((opts.zeugen ?? []).map((z) => schluesselLesen(z)));
  const nurKosig = zeugen.filter((z) => z.typ === TYP_KOSIGNATUR);
  const schwelle = Number.isInteger(opts.schwelle) ? opts.schwelle : nurKosig.length >= 3 ? 2 : nurKosig.length;
  ergebnis.schwelle = schwelle;
  if (nurKosig.length > 0) {
    const zeugenSig = await signaturenPruefen(notiz, nurKosig);
    ergebnis.zeugenGueltig = zeugenSig.gueltig.length;
    add(
      "transparenz_zeugen",
      `${zeugenSig.gueltig.length} von mindestens ${schwelle} geforderten Gegenzeichnungen festgelegter, unabhängiger Zeugen sind gültig`,
      zeugenSig.gueltig.length >= schwelle && schwelle > 0 && zeugenSig.fehlerhaft.length === 0,
      zeugenSig.gueltig.map((g) => g.name).join(", ") + (zeugenSig.fehlerhaft.length ? ` | fehlerhaft: ${zeugenSig.fehlerhaft.map((f) => `${f.name} (${f.grund})`).join(", ")}` : ""),
    );
  }

  let bindungOk = false;
  let detail = "";
  const von = punkt.groesse;
  const bis = head.treeSize;
  if (von === bis) {
    bindungOk = punkt.wurzelHex === head.rootHash;
    detail = bindungOk ? `Baumgröße ${bis} stimmt überein` : "Die Wurzel des Prüfpunkts weicht von der Wurzel des Pakets ab";
    ergebnis.gedeckt = bindungOk ? bis : 0;
  } else {
    const kon = t.konsistenz;
    const alt = Math.min(von, bis);
    const neu = Math.max(von, bis);
    const altWurzel = von < bis ? punkt.wurzelHex : head.rootHash;
    const neuWurzel = von < bis ? head.rootHash : punkt.wurzelHex;
    if (!kon || kon.von !== alt || kon.bis !== neu || !Array.isArray(kon.pfad)) {
      detail = "Es fehlt der Konsistenzbeweis zwischen Prüfpunkt und Baumkopf des Pakets";
    } else {
      bindungOk = await verifyConsistency({ oldSize: alt, newSize: neu, oldRoot: altWurzel, newRoot: neuWurzel, proof: kon.pfad });
      detail = bindungOk ? `Konsistenzbeweis von ${alt} nach ${neu} gültig` : "Konsistenzbeweis ungültig";
    }
    ergebnis.gedeckt = bindungOk ? Math.min(von, bis) : 0;
  }
  ergebnis.gebunden = bindungOk;
  add("transparenz_bindung", "Der Baumkopf des Pakets gehört zum bezeugten Prüfpunkt", bindungOk, detail);
  return ergebnis;
}

export async function verifyPackage(pkg, opts = {}) {
  const checks = [];
  const warnungen = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  const { originalBytes = null } = opts;
  const abbruch = (text) => {
    add("format", "Form des Beweispakets", false, text);
    return { ok: false, checks, warnungen, stufe: 0, stufeText: "Nicht prüfbar" };
  };
  try {
    if (pkg?.schema !== "defconder-beweispaket-1") return abbruch("Unbekanntes Format.");
    const formFehler = pruefeForm(pkg);
    if (formFehler) return abbruch(formFehler);
    const head = pkg.treeHead;
    const keyId = await keyIdOf(head.publicKeyPem);
    add("schluessel", "Kennung des Schlüssels stimmt mit dem mitgelieferten öffentlichen Schlüssel überein", keyId === head.signature.keyId, `Schlüsselkennung ${keyId}`);
    const sig = await verifySignature(head);
    add("kopf", "Signatur des Baumkopfs (Ed25519) ist gültig", sig === true, sig === true ? `Baumgröße ${head.treeSize}, Wurzel ${head.rootHash.slice(0, 16)}…` : sig?.error ?? "Signatur ungültig");

    let festgelegt = Array.isArray(opts.pinnedKeyIds) ? [...opts.pinnedKeyIds] : [];
    if (festgelegt.length > 0 && opts.wechsel) {
      const wechsel = await schluesselwechselPruefen(opts.wechsel, festgelegt);
      for (const c of wechsel.checks) add("schluesselwechsel", c.label, c.ok, c.detail);
      if (wechsel.ok) festgelegt = wechsel.vertraute;
    }
    const gebunden = festgelegt.length > 0;
    let schluesselGebunden = false;
    if (gebunden) {
      schluesselGebunden = festgelegt.includes(keyId);
      add("schluessel_gebunden", "Der Schlüssel des Baumkopfs gehört zu den vom Prüfer festgelegten Schlüsseln", schluesselGebunden, `erwartet ${festgelegt.join(", ")}, im Paket ${keyId}`);
    } else {
      warnungen.push("Kein Schlüssel festgelegt. Das Paket bringt seinen eigenen Schlüssel mit. Ohne einen festgelegten Schlüssel beweist die Prüfung nur, dass das Paket in sich stimmig ist, nicht, von wem es stammt.");
    }

    let eventsOk = 0;
    let proofsOk = 0;
    let ausgezogen = 0;
    const normal = [];
    const failedEvents = [];
    for (const entry of pkg.events) {
      let ereignis = entry.event;
      let hashOk;
      let hashGrund = "";
      if (entry.auszug) {
        const a = await auszugPruefen(entry.auszug);
        hashOk = a.ok;
        hashGrund = a.grund ?? "";
        ausgezogen += 1;
        const offen = {};
        for (const o of a.offene ?? []) offen[o.name] = o.wert;
        const { hv, seq, type, at, prevHash, hash } = entry.auszug.kopf;
        ereignis = { ...offen, seq, type, at, hv, prevHash, hash };
      } else {
        const r = await ereignisHashPruefen(ereignis);
        hashOk = r.ok;
        hashGrund = r.grund;
      }
      normal.push({ event: ereignis, proof: entry.proof });
      const proofOk = await verifyInclusion({ index: ereignis.seq, treeSize: head.treeSize, eventHash: ereignis.hash, path: entry.proof, rootHash: head.rootHash });
      if (hashOk) eventsOk += 1;
      if (proofOk) proofsOk += 1;
      if (!hashOk || !proofOk) failedEvents.push(`Ereignis ${ereignis.seq} (${ereignis.type}): ${hashOk ? "" : `Prüfsumme weicht ab (${hashGrund}) `}${proofOk ? "" : "Einschlussbeweis ungültig"}`);
    }
    add("ereignisse", `Prüfsumme aller ${pkg.events.length} Ereignisse neu berechnet${ausgezogen ? ` (davon ${ausgezogen} als Auszug mit verdeckten Feldern)` : ""}`, eventsOk === pkg.events.length, failedEvents.join("; "));
    add("einschluss", `Einschlussbeweis für alle ${pkg.events.length} Ereignisse gegen die Baumwurzel`, proofsOk === pkg.events.length, failedEvents.join("; "));

    const sortiert = [...normal].sort((a, b) => a.event.seq - b.event.seq);
    let paare = 0;
    let paareOk = 0;
    for (let i = 1; i < sortiert.length; i += 1) {
      if (sortiert[i].event.seq === sortiert[i - 1].event.seq + 1) {
        paare += 1;
        if (sortiert[i].event.prevHash === sortiert[i - 1].event.hash) paareOk += 1;
      }
    }
    const doppelt = new Set(normal.map((e) => e.event.seq)).size !== normal.length;
    add("verkettung", `Jedes Ereignis nennt die Prüfsumme seines Vorgängers (${paare} direkt aufeinanderfolgende Paare)`, !doppelt && paareOk === paare, doppelt ? "Folgenummern kommen doppelt vor." : paareOk === paare ? "" : `${paare - paareOk} Paare passen nicht zusammen`);

    const byType = (t) => normal.map((e) => e.event).filter((e) => e.type === t);
    const ingest = byType("MediaIngested").find((e) => e.id === pkg.asset.id);
    const recorded = byType("RecordingFinalized").find((e) => e.id === pkg.asset.id);
    const expectedHash = recorded?.sha256 ?? ingest?.sha256 ?? null;
    add("original_ereignis", "Die Prüfsumme der Originaldatei steht im verketteten Protokoll", Boolean(expectedHash) && expectedHash === pkg.asset.sha256, `Protokoll ${expectedHash?.slice(0, 16) ?? "keine"}…, Paket ${pkg.asset.sha256.slice(0, 16)}…`);
    let bytes = originalBytes;
    if (!bytes && pkg.original?.included && typeof pkg.original.base64 === "string") bytes = base64Decode(pkg.original.base64);
    if (bytes) {
      const h = await sha256(bytes);
      add("original", "Die mitgelieferte Originaldatei hat genau die protokollierte Prüfsumme", h === pkg.asset.sha256, `berechnet ${h.slice(0, 16)}…`);
    } else {
      add("original", "Originaldatei geprüft", false, "Es liegt keine Originaldatei bei. Zum Prüfen die Datei zusätzlich angeben.");
    }

    const completed = byType("AnalysisCompleted");
    const proposed = new Map(byType("FindingProposed").map((e) => [e.id, e]));
    let analysesOk = 0;
    const analysisIssues = [];
    for (const a of pkg.analyses) {
      const done = completed.find((e) => e.jobId === a.jobId);
      const bare = a.result.findings.map(({ id, ...rest }) => rest);
      const digest = await sha256(canonicalJson({ findings: bare, artifacts: a.result.artifacts }));
      const digestOk = Boolean(done) && done.outputDigest === a.result.outputDigest && (a.result.capped ? true : done.outputDigest === digest);
      let findingsOk = true;
      for (const f of a.result.findings) {
        const ev = proposed.get(f.id);
        if (!ev || ev.kind !== f.kind || canonicalJson(ev.where ?? {}) !== canonicalJson(f.where ?? {})) findingsOk = false;
      }
      if (digestOk && findingsOk) analysesOk += 1;
      else analysisIssues.push(`${a.task} (${a.jobId}): ${digestOk ? "" : "Ergebnisprüfsumme weicht ab "}${findingsOk ? "" : "Befunde passen nicht zum Protokoll"}`);
    }
    add("analysen", `Ergebnisse von ${pkg.analyses.length} Analysen stimmen mit ihrer Prüfsumme und den protokollierten Befunden überein`, analysesOk === pkg.analyses.length, analysisIssues.join("; "));

    const sealed = byType("RecordingSegmentSealed");
    if (sealed.length > 0 && recorded) {
      let previous = (byType("RecordingStarted").find((e) => e.id === pkg.asset.id) ?? {}).chainStart;
      let chainOk = Boolean(previous);
      for (const s of [...sealed].sort((a, b) => a.index - b.index)) {
        const link = await sha256(`${previous}|${s.sha256}|${s.index}|${s.size}|${s.startMs}|${s.endMs}`);
        chainOk = chainOk && s.chainPrev === previous && link === s.chainHash;
        previous = s.chainHash;
      }
      add("aufzeichnung", `Segmentkette der Aufzeichnung (${sealed.length} Segmente) lückenlos nachgerechnet`, chainOk && recorded.chainHead === previous, "");
    }

    const transparenz = await pruefeTransparenz(pkg, opts, head, add);
    if (!transparenz.vorhanden && (opts.zeugen ?? []).length > 0) add("transparenz_fehlt", "Das Paket enthält Gegenzeichnungen der festgelegten Zeugen", false, "Es sind Zeugen festgelegt, aber das Paket bringt keinen Prüfpunkt mit.");
    if (!transparenz.vorhanden) warnungen.push("Das Paket enthält keine Gegenzeichnungen unabhängiger Zeugen. Ein Betreiber könnte das Protokoll vor der Unterschrift neu geschrieben haben.");
    else if (!opts.logSchluessel) warnungen.push("Der Schlüssel des Protokolls ist nicht festgelegt. Die Gegenzeichnungen zählen nur, wenn der Prüfer den Protokollschlüssel und die Zeugen kennt.");
    else if (!(opts.zeugen ?? []).length) warnungen.push("Es sind keine Zeugen festgelegt. Ohne bekannte Zeugen lässt sich die Unabhängigkeit der Gegenzeichnungen nicht beurteilen.");

    const intern = checks.every((c) => c.ok);
    let stufe = 0;
    let stufeText = "Nur in sich stimmig";
    if (intern && schluesselGebunden) {
      stufe = 1;
      stufeText = "Schlüssel gebunden";
    }
    if (intern && transparenz.logGebunden && transparenz.gebunden && transparenz.schwelle > 0 && transparenz.zeugenGueltig >= transparenz.schwelle) {
      stufe = 2;
      stufeText = `Bezeugt von ${transparenz.zeugenGueltig} unabhängigen Zeugen (${transparenz.gedeckt} von ${head.treeSize} Ereignissen des Protokolls gedeckt)`;
    }
    if (Number.isInteger(opts.mindestStufe) && stufe < opts.mindestStufe) add("mindeststufe", `Mindestens Vertrauensstufe ${opts.mindestStufe} verlangt`, false, `erreicht ist Stufe ${stufe}`);
    const bestanden = checks.every((c) => c.ok);
    if (!bestanden) stufeText = "Nicht bestanden";
    return { ok: bestanden, checks, warnungen, stufe, stufeText, treeSize: head.treeSize, keyId: head.signature.keyId, exportedAt: pkg.createdAt, asset: pkg.asset, zeitanker: transparenz.zeitanker };
  } catch (err) {
    return abbruch(`Unerwarteter Fehler beim Prüfen: ${String(err?.message ?? err)}`);
  }
}

export async function pruefpunktPruefen(text, opts = {}) {
  const checks = [];
  const add = (id, label, ok, detail = "") => checks.push({ id, label, ok: Boolean(ok), detail });
  try {
    const notiz = notizLesen(text);
    const punkt = pruefpunktLesen(notiz.koerper);
    add("form", "Prüfpunkt ist lesbar", true, `${punkt.origin}, Baumgröße ${punkt.groesse}, Wurzel ${punkt.wurzelHex}`);
    if (!opts.logSchluessel) {
      add("log", "Signatur des Protokolls", false, "Es ist kein Schlüssel des Protokolls festgelegt.");
      return { ok: false, checks, punkt, zeugenGueltig: 0, schwelle: 0 };
    }
    const log = await schluesselLesen(opts.logSchluessel);
    const logSig = await signaturenPruefen(notiz, [log]);
    add("log", "Prüfpunkt trägt die Signatur des festgelegten Protokollschlüssels", log.typ === TYP_ED25519 && log.name === punkt.origin && logSig.gueltig.length === 1 && logSig.fehlerhaft.length === 0, logSig.fehlerhaft.map((f) => f.grund).join(", "));
    const zeugen = (await Promise.all((opts.zeugen ?? []).map((z) => schluesselLesen(z)))).filter((z) => z.typ === TYP_KOSIGNATUR);
    const schwelle = Number.isInteger(opts.schwelle) ? opts.schwelle : zeugen.length >= 3 ? 2 : zeugen.length;
    let zeugenGueltig = 0;
    if (zeugen.length > 0) {
      const sig = await signaturenPruefen(notiz, zeugen);
      zeugenGueltig = sig.gueltig.length;
      add("zeugen", `${zeugenGueltig} von mindestens ${schwelle} geforderten Gegenzeichnungen festgelegter Zeugen sind gültig`, zeugenGueltig >= schwelle && schwelle > 0 && sig.fehlerhaft.length === 0, sig.gueltig.map((g) => g.name + " (" + new Date(g.zeit * 1000).toISOString() + ")").join(", "));
    }
    const zeitanker = logSig.gueltig.length === 1 && logSig.fehlerhaft.length === 0 ? await zeitankerPruefen(punkt.erweiterungen, opts, add) : null;
    return { ok: checks.every((c) => c.ok), checks, punkt, zeugenGueltig, schwelle, zeitanker };
  } catch (err) {
    add("form", "Prüfpunkt ist lesbar", false, String(err?.message ?? err));
    return { ok: false, checks, punkt: null, zeugenGueltig: 0, schwelle: 0 };
  }
}
