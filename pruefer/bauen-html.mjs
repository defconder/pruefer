import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dateien = ["merkle.js", "note.js", "ereignis.js", "zeitanker.js", "pruefer-kern.js", "aussage.js", "regeln.js", "entscheidung.js", "widerspruch.js", "bericht.js"];

function umhuellen(datei, bekannt) {
  let quelltext = readFileSync(join(here, datei), "utf8");
  const exporte = [];
  quelltext = quelltext.replace(/^import \{([^}]*)\} from "\.\/([^"]+)";\n/gm, (_, namen, ziel) => `const {${namen}} = ${bekannt.get(ziel)};\n`);
  quelltext = quelltext.replace(/^export (async function|function|const) ([A-Za-z0-9_]+)/gm, (_, art, name) => {
    exporte.push(name);
    return `${art} ${name}`;
  });
  quelltext = quelltext.replace(/^export \{([^}]*)\};\n/gm, (_, namen) => {
    for (const n of namen.split(",")) exporte.push(n.trim());
    return "";
  });
  const kennung = `M_${datei.replace(/[^a-z]/gi, "_")}`;
  bekannt.set(datei, kennung);
  return `const ${kennung} = (() => {\n${quelltext}\nreturn { ${[...new Set(exporte)].join(", ")} };\n})();\n`;
}

const bekannt = new Map();
const gebuendelt = dateien.map((d) => umhuellen(d, bekannt)).join("\n");
const kern = bekannt.get("pruefer-kern.js");
const aussage = bekannt.get("aussage.js");
const entscheidung = bekannt.get("entscheidung.js");
const widerspruch = bekannt.get("widerspruch.js");
const bericht = bekannt.get("bericht.js");

const stil = `
:root { --bg: #f6f7f9; --card: #ffffff; --text: #1b2430; --muted: #5d6b7a; --line: #d5dbe2; --ok: #1f7a46; --bad: #b3261e; --warn: #8a5a00; --accent: #1565a8; color-scheme: light; }
@media (prefers-color-scheme: dark) { :root { --bg: #0e1319; --card: #151c24; --text: #e6ebf0; --muted: #93a1b0; --line: #2a3541; --ok: #5fcf8e; --bad: #ff8a80; --warn: #f3c969; --accent: #5aa9ee; color-scheme: dark; } }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, "Segoe UI", sans-serif; }
main { max-width: 860px; margin: 0 auto; padding: 28px 16px 60px; display: grid; gap: 18px; }
h1 { font-size: 22px; margin: 0; }
h2 { font-size: 16px; margin: 0; }
h3 { font-size: 14px; margin: 0; }
p { margin: 0; color: var(--muted); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; display: grid; gap: 12px; }
label { display: grid; gap: 4px; font-weight: 600; }
label small { font-weight: 400; color: var(--muted); }
input[type=file], input[type=number], textarea { font: inherit; }
textarea { min-height: 70px; padding: 6px 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--text); font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
input[type=number] { width: 80px; padding: 4px 6px; }
button { font: inherit; padding: 9px 16px; border-radius: 8px; border: 1px solid var(--accent); background: var(--accent); color: #fff; cursor: pointer; justify-self: start; }
button:disabled { opacity: .5; cursor: default; }
ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
li { display: grid; grid-template-columns: auto 1fr; gap: 10px; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; }
li b { font-size: 12px; letter-spacing: .04em; padding: 2px 8px; border-radius: 999px; align-self: start; }
li.ok b { color: var(--ok); border: 1px solid var(--ok); }
li.bad b { color: var(--bad); border: 1px solid var(--bad); }
li small { display: block; color: var(--muted); overflow-wrap: anywhere; }
.verdict { font-weight: 700; padding: 12px 14px; border-radius: 8px; }
.verdict.ok { color: var(--ok); border: 1px solid var(--ok); }
.verdict.bad { color: var(--bad); border: 1px solid var(--bad); }
.stufe { padding: 10px 14px; border-radius: 8px; border: 1px solid var(--line); font-weight: 600; }
.warn { padding: 10px 14px; border-radius: 8px; border: 1px solid var(--warn); color: var(--warn); }
.bericht { display: grid; gap: 8px; padding: 12px 14px; border: 1px solid var(--line); border-radius: 8px; }
.bericht ul { gap: 4px; }
.bericht li { display: block; border: 0; padding: 0 0 0 14px; position: relative; }
.bericht li::before { content: "·"; position: absolute; left: 2px; }
code { overflow-wrap: anywhere; }
[hidden] { display: none !important; }
`;

const skript = `
${gebuendelt}
const { verifyPackage, pruefpunktPruefen } = ${kern};
const { aussagePruefen } = ${aussage};
const { entscheidungPruefen } = ${entscheidung};
const { widerspruchPruefen } = ${widerspruch};
const { berichtErzeugen, berichtText } = ${bericht};

const zeilen = (id) => document.getElementById(id).value.split(/\\r?\\n/).map((z) => z.trim()).filter(Boolean);
const optionen = () => ({
  pinnedKeyIds: zeilen("kennungen"),
  logSchluessel: zeilen("logschluessel")[0],
  zeugen: zeilen("zeugen"),
  schwelle: Number(document.getElementById("schwelle").value) || undefined,
  mindestArbeitBits: document.getElementById("arbeit").value === "" ? undefined : Number(document.getElementById("arbeit").value),
  mindestStufe: document.getElementById("mindeststufe").value === "" ? undefined : Number(document.getElementById("mindeststufe").value),
});

function liste(checks) {
  const list = document.createElement("ul");
  for (const c of checks) {
    const li = document.createElement("li");
    li.className = c.ok ? "ok" : "bad";
    const tag = document.createElement("b");
    tag.textContent = c.ok ? "BESTANDEN" : "FEHLER";
    const text = document.createElement("div");
    text.textContent = c.label;
    if (c.detail) { const s = document.createElement("small"); s.textContent = c.detail; text.append(s); }
    li.append(tag, text);
    list.append(li);
  }
  return list;
}

function berichtAnzeigen(ziel, art, ergebnis) {
  const b = berichtErzeugen(art, ergebnis);
  const feld = document.createElement("div");
  feld.className = "bericht";
  const titel = document.createElement("h3");
  titel.textContent = "Bericht in Klartext";
  const ergebnisZeile = document.createElement("div");
  ergebnisZeile.textContent = b.titel + ": " + b.ergebnis;
  feld.append(titel, ergebnisZeile);
  for (const [name, eintraege] of [["Fehlgeschlagene Prüfschritte", b.fehlgeschlagen], ["Was bewiesen ist", b.bewiesen], ["Was nicht bewiesen ist", b.nichtBewiesen], ["Was ein Gegner dafür bräuchte", b.gegnerBraeuchte], ["Empfehlung", b.empfehlung], ["Hinweise", b.hinweise]]) {
    if (!eintraege.length) continue;
    const kopf = document.createElement("strong");
    kopf.textContent = name;
    const ul = document.createElement("ul");
    for (const e of eintraege) { const li = document.createElement("li"); li.textContent = e; ul.append(li); }
    feld.append(kopf, ul);
  }
  const speichern = document.createElement("button");
  speichern.textContent = "Bericht als Textdatei speichern";
  speichern.addEventListener("click", () => {
    const blob = new Blob([berichtText(b)], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "pruefbericht.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  });
  feld.append(speichern);
  ziel.append(feld);
}

function ergebnisAnzeigen(ziel, art, r, okText, schlechtText) {
  ziel.textContent = "";
  const verdict = document.createElement("div");
  verdict.className = "verdict " + (r.ok ? "ok" : "bad");
  verdict.textContent = r.ok ? okText : schlechtText;
  ziel.append(verdict);
  if (r.stufe !== undefined) {
    const stufe = document.createElement("div");
    stufe.className = "stufe";
    stufe.textContent = "Vertrauensstufe " + r.stufe + " von 2: " + r.stufeText;
    ziel.append(stufe);
  }
  for (const w of r.warnungen ?? []) { const d = document.createElement("div"); d.className = "warn"; d.textContent = w; ziel.append(d); }
  for (const a of r.aussagen ?? []) { const d = document.createElement("div"); d.className = "stufe"; d.textContent = a.text; ziel.append(d); }
  ziel.append(liste(r.checks));
  if (r.keyId) {
    const key = document.createElement("p");
    key.append("Schlüsselkennung des Betreibers: ");
    const code = document.createElement("code");
    code.textContent = r.keyId;
    key.append(code);
    ziel.append(key);
  }
  if (art) berichtAnzeigen(ziel, art, r);
}

const paket = document.getElementById("paket");
const original = document.getElementById("original");
const los = document.getElementById("los");
const ausgabe = document.getElementById("ausgabe");
paket.addEventListener("change", () => { los.disabled = !paket.files.length; });
los.addEventListener("click", async () => {
  ausgabe.hidden = false;
  ausgabe.textContent = "Wird geprüft ...";
  try {
    const doc = JSON.parse(await paket.files[0].text());
    const bytes = original.files.length ? new Uint8Array(await original.files[0].arrayBuffer()) : null;
    if (doc?.schema === "defconder-aussage-1") ergebnisAnzeigen(ausgabe, "aussage", await aussagePruefen(doc, optionen()), "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen.");
    else if (doc?.schema === "defconder-entscheidung-1") ergebnisAnzeigen(ausgabe, "entscheidung", await entscheidungPruefen(doc, optionen()), "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen.");
    else if (doc?.schema === "defconder-widerspruch-1") {
      const r = await widerspruchPruefen(doc, optionen());
      ergebnisAnzeigen(ausgabe, null, r, r.text, r.text);
    } else ergebnisAnzeigen(ausgabe, "paket", await verifyPackage(doc, { ...optionen(), originalBytes: bytes }), "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen. Dem Paket ist nicht zu trauen.");
  } catch (err) {
    ausgabe.textContent = "Die Datei ließ sich nicht lesen: " + err.message;
  }
});

document.getElementById("punktlos").addEventListener("click", async () => {
  const feld = document.getElementById("punktausgabe");
  feld.hidden = false;
  feld.textContent = "Wird geprüft ...";
  const r = await pruefpunktPruefen(document.getElementById("punkt").value, optionen());
  ergebnisAnzeigen(feld, "pruefpunkt", { ...r, stufe: undefined }, "Alle Prüfungen bestanden.", "Mindestens eine Prüfung ist fehlgeschlagen.");
});
`;

const hash = (text) => `'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`;
const csp = `default-src 'none'; script-src ${hash(skript)}; style-src ${hash(stil)}; img-src 'none'; font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; media-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'`;

const html = `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defconder Beweisprüfer</title>
<style>${stil}</style>
</head>
<body>
<main>
<div>
<h1>Defconder Beweisprüfer</h1>
<p>Prüft Beweispakete, Aussagen über das Protokoll, Entscheidungsnachweise, Widerspruchsbeweise und Prüfpunkte vollständig auf diesem Gerät. Die Seite darf technisch keine Verbindung ins Netz aufbauen, es werden keine Daten verschickt, und es braucht weder Netz noch Defconder.</p>
</div>
<div class="card">
<h2>Vertrauen festlegen (empfohlen)</h2>
<p>Ein Dokument bringt seinen eigenen Schlüssel mit. Ohne festgelegte Schlüssel beweist die Prüfung nur, dass es in sich stimmig ist. Tragen Sie ein, was Sie auf anderem Weg vom Betreiber und von unabhängigen Zeugen erhalten haben.</p>
<label>Schlüsselkennungen des Betreibers (eine je Zeile)<textarea id="kennungen" spellcheck="false" placeholder="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"></textarea></label>
<label>Schlüssel des Protokolls<small>Form Name+Kennung+Daten</small><textarea id="logschluessel" spellcheck="false" placeholder="defconder.example/instanz+1a2b3c4d+AQ..."></textarea></label>
<label>Schlüssel unabhängiger Zeugen (einer je Zeile)<textarea id="zeugen" spellcheck="false" placeholder="zeuge.example+5e6f7a8b+BA..."></textarea></label>
<label>Mindestens gültige Gegenzeichnungen<input id="schwelle" type="number" min="1" value="2"></label>
<label>Mindeststufe<small>Das Dokument gilt nur als bestanden, wenn mindestens diese Vertrauensstufe erreicht wird.</small><select id="mindeststufe"><option value="">keine Forderung</option><option value="1">Stufe 1, Schlüssel gebunden</option><option value="2">Stufe 2, bezeugt</option></select></label>
<label>Mindestarbeit eines Zeitankers in Bit<small>Leer lassen für die Voreinstellung 64. Ein Bitcoin-Block mit weniger Arbeit beweist nichts.</small><input id="arbeit" type="number" min="0" max="200"></label>
</div>
<div class="card">
<h2>Dokument prüfen</h2>
<label>Beweispaket, Aussage, Entscheidungsnachweis oder Widerspruchsbeweis (.json)<input id="paket" type="file" accept=".json,application/json"></label>
<label>Originaldatei, falls das Beweispaket sie nicht enthält (optional)<input id="original" type="file"></label>
<button id="los" disabled>Prüfen</button>
</div>
<div id="ausgabe" class="card" hidden></div>
<div class="card">
<h2>Prüfpunkt prüfen</h2>
<label>Prüfpunkt als Text (Signaturzeilen eingeschlossen)<textarea id="punkt" spellcheck="false"></textarea></label>
<button id="punktlos">Prüfpunkt prüfen</button>
</div>
<div id="punktausgabe" class="card" hidden></div>
<p>Was geprüft wird: die Prüfsumme jedes Ereignisses (auch bei Auszügen mit verdeckten Feldern), der Einschlussbeweis jedes Ereignisses in den Merkle-Baum, die Verkettung der Ereignisse, die Unterschrift des Baumkopfs, die Prüfsumme der Originaldatei, die Ergebnisprüfsummen aller Analysen und, wenn vorhanden, die Gegenzeichnungen unabhängiger Zeugen samt Konsistenzbeweis und ein Zeitanker. Die Vertrauensstufe sagt, wie weit das Ergebnis trägt: Stufe 0 in sich stimmig, Stufe 1 Schlüssel gebunden, Stufe 2 bezeugt.</p>
</main>
<script type="module">${skript}</script>
</body>
</html>
`;
writeFileSync(join(here, "pruefer.html"), html);
console.log("pruefer.html geschrieben (" + html.length + " Zeichen)");
