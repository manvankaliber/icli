"""Generate editable SVG launch-thread graphics with no external dependencies."""

from pathlib import Path
from html import escape
import xml.etree.ElementTree as ET
import re
import base64
import json
import argparse
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "thread"
NS = {"s": "http://www.w3.org/2000/svg"}
REFERENCE = ET.parse(ROOT / "assets" / "feature-comparison.svg").getroot()
APPS = {}
for group in REFERENCE.findall("s:g", NS):
    title = next((e.text for e in group.findall("s:text", NS) if e.get("class") == "title"), None)
    image = group.find("s:image", NS)
    if title and image is not None:
        APPS[title] = image.get("href")


def text(x, y, value, size=26, fill="ink", weight=400, extra=""):
    weight = 700 if weight >= 600 else 400
    return f'<text x="{x}" y="{y}" font-family="Arial,Helvetica,sans-serif" font-size="{size}" font-weight="{weight}" fill="var(--{fill})" {extra}>{escape(str(value))}</text>'


def box(x, y, w, h, fill="surface", radius=20, stroke="line"):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="var(--{fill})" stroke="var(--{stroke})" stroke-width="2"/>'


def line(x1, y1, x2, y2, color="line", width=2):
    return f'<path d="M{x1} {y1} H{x2}" stroke="var(--{color})" stroke-width="{width}"/>' if y1 == y2 else f'<path d="M{x1} {y1} L{x2} {y2}" stroke="var(--{color})" stroke-width="{width}"/>'


def icon(name, x, y, size=64):
    return f'<image href="{APPS[name]}" x="{x}" y="{y}" width="{size}" height="{size}"/>'


def pill(x, y, w, label, color="muted", fill="soft"):
    return box(x, y, w, 42, fill, 21, fill) + text(x + w/2, y + 28, label, 19, color, 600, 'text-anchor="middle"')


def check(x, y, positive=True):
    if positive:
        return f'<path d="M{x-8} {y} l6 6 13-15" fill="none" stroke="var(--green)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>'
    return f'<path d="M{x-7} {y-7} l14 14 m0-14 l-14 14" fill="none" stroke="var(--red)" stroke-width="3.5" stroke-linecap="round"/>'


def chrome(x, y, w):
    return ''.join(f'<circle cx="{x+26+i*22}" cy="{y+25}" r="5" fill="var(--line)"/>' for i in range(3)) + line(x, y+50, x+w, y+50)


def mono(x, y, value, size=24, fill="ink"):
    return text(x, y, value, size, fill, 400, 'style="font-family:Consolas,monospace"')


def footer(number, note=""):
    return line(64, 916, 1536, 916) + text(64, 958, "github.com/manvankaliber/icli", 22, "muted") + text(1536, 958, f"{number:02} / 06", 20, "muted", 500, 'text-anchor="end"') + (text(64, 891, note, 19, "muted") if note else "")


def frame(number, eyebrow, headline, subtitle, content, note="", dark=False):
    colors = ('--bg:#111214;--surface:#191b1e;--ink:#f1f2f3;--muted:#a4a8ad;--line:#37393c;--soft:#24272b;--green:#54d69a;--red:#ff7078;--blue:#82aaff;--greenbg:#173c2c;--bluebg:#202e48;' if dark else '--bg:#f7f8fa;--surface:#ffffff;--ink:#17191d;--muted:#626a73;--line:#d8dce1;--soft:#eef0f3;--green:#168553;--red:#c53842;--blue:#315fd5;--greenbg:#eaf6ef;--bluebg:#eef3ff;')
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="1000" viewBox="0 0 1600 1000" role="img" aria-labelledby="title desc">
<title id="title">{escape(headline)}</title><desc id="desc">{escape(subtitle + ' ' + note)}</desc>
<style>:root{{{colors}}}</style>
<rect width="1600" height="1000" fill="var(--bg)"/>
{text(64, 70, 'iCLI', 30, 'ink', 750)}{text(1536, 67, eyebrow.upper(), 19, 'muted', 600, 'text-anchor="end" letter-spacing="2"')}
{text(64, 170, headline, 62, 'ink', 650)}{text(64, 222, subtitle, 27, 'muted')}
{content}{footer(number, note)}</svg>'''
    # Resolve palette variables so SVG editors and non-browser exporters agree.
    for key, value in re.findall(r"(--[a-z]+):([^;]+);", colors):
        svg = svg.replace(f"var({key})", value)
    return svg.replace(f":root{{{colors}}}", "")


def introduction():
    s = box(64, 276, 1472, 230) + chrome(64, 276, 1472)
    s += mono(106, 392, "$ icli", 40) + text(106, 455, "Calendar, Contacts, and Mail through one local command.", 29, "muted")
    details = [("Calendar", "Events, invites, and sharing", "CalDAV"), ("Mail", "Search, read, draft, and send", "IMAP"), ("Contacts", "Search, create, and update", "CardDAV")]
    for i, (name, detail, protocol) in enumerate(details):
        x = 64 + i * 499
        s += box(x, 534, 474, 218) + icon(name, x+28, 564, 62) + text(x+110, 605, name, 31, weight=600)
        s += text(x+28, 663, detail, 25, "muted") + pill(x+28, 693, 126, protocol)
    s += text(64, 827, "One CLI. Your agent or your terminal.", 29, weight=600)
    s += pill(1018, 794, 158, "Windows") + pill(1194, 794, 148, "Linux") + pill(1360, 794, 176, "macOS")
    return "INTRODUCING 1.0", "Your agent. Your iCloud.", "A native command-line tool for Calendar, Mail, and Contacts.", s, "Independent project. Not affiliated with or endorsed by Apple."


def guidance():
    s = ""
    stages = [("01", "Discover", "Help where the agent needs it.", ["Command help", "Accepted options", "Prerequisites and defaults"]), ("02", "Recover", "Errors with a useful next step.", ["Structured error", "Recovery hint", "Follow-up command"]), ("03", "Continue", "Results ready for the next action.", ["Stable resource IDs", "Agent text, JSON, or CSV", "Follow-up suggestions"])]
    for i, (n, title, description, items) in enumerate(stages):
        x = 64+i*499
        s += box(x, 290, 474, 392) + pill(x+28, 318, 62, n) + text(x+28, 425, title, 43, weight=600)
        s += text(x+28, 468, description, 23, "muted") + line(x+28, 498, x+446, 498)
        for j, item in enumerate(items):
            s += check(x+39, 541+j*48) + text(x+66, 550+j*48, item, 25)
    s += box(64, 716, 1472, 120, "soft", 18, "soft") + mono(98, 765, "$ icli <command> --help", 28) + text(98, 806, "Guidance travels with the tool, throughout the task.", 26, "muted")
    return "AGENT GUIDANCE", "The next step is built in.", "Inline help, actionable errors, and predictable results.", s, ""


def efficiency():
    s = pill(64, 282, 318, "PRELIMINARY OBSERVATIONS", "muted")
    for x, value, label, detail in [(64, "~36×", "task performance", "Early observations across agent tasks"), (813, "82%", "fewer model tokens", "Compared with the previous workflow")]:
        s += box(x, 350, 723, 306) + text(x+36, 490, value, 120, "green", 650) + text(x+36, 551, label, 33, weight=600) + text(x+36, 610, detail, 23, "muted")
    s += box(64, 686, 1472, 158) + text(100, 746, "Small tasks", 30, weight=600) + text(100, 798, "Minutes", 32, "muted")
    s += line(280, 788, 491, 788, "line", 3) + text(527, 800, "Seconds", 38, "green", 600)
    s += text(1040, 749, "Formal benchmark", 26, "muted") + text(1040, 797, "In progress", 34, weight=600)
    return "TIME & TOKENS", "Fewer tokens. Faster tasks.", "Early observations from iCLI agent workflows.", s, "Preliminary observations supplied by the project author. Formal benchmark in progress."


def comparison():
    s = box(64, 280, 1472, 470)
    s += text(100, 340, "Command workflows", 27, "muted", 600) + text(1075, 340, "iCLI", 27, weight=600, extra='text-anchor="middle"') + text(1350, 340, "pyicloud", 27, "muted", 600, 'text-anchor="middle"')
    s += line(100, 365, 1500, 365)
    for i, (name, total, other) in enumerate([("Calendar", 11, 2), ("Contacts", 12, 2), ("Mail", 11, 0)]):
        y = 402+i*110
        s += icon(name, 100, y-9, 56) + text(182, y+29, name, 32, weight=600)
        s += text(1075, y+30, f"{total} / {total}", 36, "green", 600, 'text-anchor="middle"') + text(1350, y+30, f"{other} / {total}", 36, "muted", 500, 'text-anchor="middle"')
        if i < 2: s += line(100, y+70, 1500, y+70)
    s += text(64, 809, "CalDAV", 28, weight=600) + text(261, 809, "CardDAV", 28, weight=600) + text(474, 809, "IMAP", 28, weight=600)
    s += text(1536, 809, "Standard protocols. One local tool.", 26, "muted", extra='text-anchor="end"')
    return "WORKFLOW COVERAGE", "Compare what the CLI can do.", "Calendar, Contacts, and Mail coverage from the README comparison.", s, "Listed CLI workflows only, not every app feature. Comparison: pyicloud 2026.10.1."


def models():
    s = box(64, 286, 426, 555) + text(94, 340, "Providers tested", 24, "muted", 600)
    for i, name in enumerate(["OpenAI", "Anthropic", "Google", "Meta"]):
        y = 405+i*102
        s += text(96, y, name, 32, weight=600) + check(438, y-10)
        if i < 3: s += line(96, y+35, 458, y+35)
    s += box(518, 286, 1018, 555) + text(550, 341, "Example calendar workflow", 29, weight=600) + pill(1294, 310, 210, "SAMPLE DATA")
    s += line(550, 369, 1504, 369)
    days = ["MON", "TUE", "WED", "THU", "FRI"]
    for i, day in enumerate(days):
        x = 550+i*191
        s += text(x+89, 410, day, 18, "muted", 600, 'text-anchor="middle"')
        if i: s += line(x, 430, x, 739)
    for y in [434, 532, 630, 738]: s += line(550, y, 1504, y)
    events = [(0, 452, "Team sync", "09:00", "bluebg"), (2, 550, "Project review", "11:00", "greenbg"), (4, 648, "Weekly plan", "14:00", "bluebg")]
    for d, y, name, time, color in events:
        x = 558+d*191
        s += box(x, y, 175, 70, color, 9, color) + text(x+12, y+27, time, 18, "muted", 500) + text(x+12, y+53, name, 20, weight=600)
    s += text(550, 794, "Read events", 24, weight=600) + text(772, 794, "→", 28, "muted") + text(828, 794, "Find a slot", 24, weight=600) + text(1050, 794, "→", 28, "muted") + text(1106, 794, "Plan the week", 24, weight=600)
    return "MODEL FLEXIBILITY", "One CLI. Different agents.", "The same commands and output contract, whichever model calls them.", s, "Testing reported by the project author. Illustrative calendar with fictional events."


def native():
    s = box(64, 282, 1472, 230) + text(106, 380, "Rust", 72, weight=650) + text(106, 450, "A native CLI with an MIT license.", 30, "muted")
    s += pill(1150, 322, 340, "OPEN SOURCE", "green", "greenbg") + mono(1148, 454, "$ icli --help", 29)
    for i, name in enumerate(["Windows", "Linux", "macOS"]):
        x = 64+i*499
        s += box(x, 544, 474, 194) + text(x+28, 613, name, 37, weight=600) + text(x+28, 674, "Native executable", 26, "muted") + check(x+420, 602)
    s += text(64, 820, "Inspect the code. Build it. Contribute.", 32, weight=600) + text(1536, 820, "MIT LICENSE", 21, "muted", 600, 'text-anchor="end" letter-spacing="1.5"')
    return "BUILT IN RUST", "Written in Rust. Open source.", "iCloud workflows from a local executable on your operating system.", s, "Independent project. Not affiliated with or endorsed by Apple."


PAGES = [("01-introduction", introduction), ("02-agent-guidance", guidance), ("03-efficiency", efficiency), ("04-workflow-comparison", comparison), ("05-models-and-calendar", models), ("06-rust-and-open-source", native)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--png", action="store_true", help="Also export PNGs using ImageMagick and create a ZIP")
    options = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "dark").mkdir(exist_ok=True)
    for n, (name, build) in enumerate(PAGES, 1):
        args = build()
        for dark in [False, True]:
            target = OUT / "dark" / f"{name}.svg" if dark else OUT / f"{name}.svg"
            target.write_text(frame(n, *args, dark=dark), encoding="utf-8")
    cards = []
    for name, build in PAGES:
        themes = {}
        for theme in ["light", "dark"]:
            file = OUT / "dark" / f"{name}.svg" if theme == "dark" else OUT / f"{name}.svg"
            themes[theme] = "data:image/svg+xml;base64," + base64.b64encode(file.read_bytes()).decode()
        cards.append({"label": name.replace("-", " "), "images": themes})
    gallery = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
    body{margin:0;font:14px "Segoe UI",sans-serif;color:var(--foreground,#17191d)}.controls{display:flex;gap:8px;margin-bottom:16px}button{font:inherit;padding:8px 16px;border:1px solid var(--border,#d8dce1);border-radius:8px;background:var(--card,#fff);color:inherit;cursor:pointer}button.active{background:#17191d;color:#fff}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}figure{margin:0;min-width:0}img{display:block;width:100%;height:auto;border-radius:10px;border:1px solid #d8dce1;box-sizing:border-box}figcaption{margin:8px 0 4px;text-transform:capitalize;font-weight:600}@media(max-width:500px){.grid{grid-template-columns:1fr}}</style></head><body>
    <div class="controls"><button class="active" data-theme="light">Light</button><button data-theme="dark">Dark</button></div><div class="grid" id="grid"></div><script>
    const cards=__CARDS__;function show(theme){document.querySelectorAll('button').forEach(b=>b.classList.toggle('active',b.dataset.theme===theme));document.getElementById('grid').innerHTML=cards.map(c=>'<figure><img alt="'+c.label+'" src="'+c.images[theme]+'"><figcaption>'+c.label+'</figcaption></figure>').join('')}document.querySelectorAll('button').forEach(b=>b.onclick=()=>show(b.dataset.theme));show('light');
    </script></body></html>'''.replace("__CARDS__", json.dumps(cards))
    (OUT / "preview.html").write_text(gallery, encoding="utf-8")
    if options.png:
        with tempfile.TemporaryDirectory(prefix="icli-thread-") as folder:
            for svg in sorted(OUT.rglob("*.svg")):
                # librsvg's Windows font parser expects a single family name.
                source = svg.read_text(encoding="utf-8").replace('font-family="Arial,Helvetica,sans-serif"', 'font-family="Arial"').replace('font-family:Consolas,monospace', 'font-family:Consolas')
                render_source = Path(folder) / "render.svg"
                render_source.write_text(source, encoding="utf-8")
                subprocess.run(["magick", "-background", "none", str(render_source), str(svg.with_suffix(".png"))], check=True)
        with zipfile.ZipFile(OUT / "icli-thread-graphics.zip", "w", zipfile.ZIP_DEFLATED) as bundle:
            for file in sorted(OUT.rglob("*")):
                if file.suffix in {".svg", ".png", ".md"}:
                    bundle.write(file, file.relative_to(OUT))
    print(f"Generated {len(PAGES)} graphics in light and dark themes at {OUT}")


if __name__ == "__main__":
    main()
