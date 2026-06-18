#!/usr/bin/env bash
# Regenerate docs/slides.pdf from docs/slides.md.
# Requires: pandoc on $PATH (uses wkhtmltopdf engine via xelatex fallback).
#
# Usage: bash docs/build-slides.sh

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v pandoc >/dev/null 2>&1; then
  echo "ERROR: pandoc not found on PATH. Install with: pacman -S pandoc" >&2
  exit 1
fi

# Produce a regulator-grade deck: navy background, gold accent, monospace for hashes.
# xelatex gives the most predictable kerning; pdf-engine=xelatex is the project's default.
pandoc docs/slides.md \
  --from gfm \
  --to pdf \
  --pdf-engine=xelatex \
  --toc=false \
  --standalone \
  --variable geometry:margin=1in \
  --variable mainfont="DejaVu Sans" \
  --variable monofont="DejaVu Sans Mono" \
  --variable colorlinks=true \
  --output docs/slides.pdf

echo "OK: docs/slides.pdf regenerated from docs/slides.md"
