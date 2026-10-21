# Launch-thread graphics

Six 1600 × 1000 graphics with editable SVG sources and PNG exports. The default
files use the README's light card style; `dark/` contains matching dark versions.
Open `preview.html` to compare the two themes.

Regenerate SVGs and the preview with Python's standard library:

```sh
python scripts/generate-thread-graphics.py
```

Export PNGs and a ZIP as well, using ImageMagick with SVG support:

```sh
python scripts/generate-thread-graphics.py --png
```

Edit copy, dimensions, colors, and layouts in that script. Text remains editable
in the SVGs. App icons are embedded from the existing README comparison asset,
with the same Apple iCloud guide attribution documented in the main README.

1. Introduction: Calendar, Mail, Contacts, and operating systems.
2. Agent guidance: help, recovery, and structured results.
3. Efficiency: author-supplied preliminary observations from the launch draft.
   These are not controlled benchmark results. The main README still lists
   benchmark measurements as TBD.
4. Comparison: the existing README's Calendar, Contacts, and Mail workflow counts
   against pyicloud 2026.10.1. Counts describe listed CLI workflows only.
5. Model flexibility: author-supplied provider testing list and a fictional
   calendar illustration. The illustration is not an actual model-run result.
6. Rust, MIT licensing, and native operating-system support.

These are social assets. They do not change documented CLI behavior or benchmark
results. No live iCloud account was used.
