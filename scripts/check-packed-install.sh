#!/usr/bin/env bash
# Pack → install the BUILT wheel into a fresh venv → documented smoke + pytest.
#
# The working tree is not the artifact. `python -m build` produces the sdist/wheel
# that would be published; this script installs THAT wheel (not `pip install -e .`)
# and imports the public entry (`from coderifts import CodeRifts` — README Quick start).
# Pytest then runs against the installed package from a cwd that is not the source tree,
# so local ./coderifts cannot shadow site-packages.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/py-sdk-pack-XXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "build venv            : $TMP/build"
python3 -m venv "$TMP/build"
"$TMP/build/bin/python" -m pip install -U pip build >/dev/null
"$TMP/build/bin/python" -m build --outdir "$TMP/dist" "$ROOT"

WHEEL="$(ls "$TMP/dist"/coderifts_sdk-*.whl)"
SDIST="$(ls "$TMP/dist"/coderifts_sdk-*.tar.gz)"
echo "wheel                 : $(basename "$WHEEL") ($(wc -c < "$WHEEL" | tr -d ' ') bytes)"
echo "sdist                 : $(basename "$SDIST") ($(wc -c < "$SDIST" | tr -d ' ') bytes)"

echo "install venv          : $TMP/run"
python3 -m venv "$TMP/run"
"$TMP/run/bin/python" -m pip install -U pip >/dev/null
"$TMP/run/bin/python" -m pip install "$WHEEL"

# Documented public entry (README Quick start). The PyPI name is coderifts-sdk;
# the import is coderifts — not coderifts_sdk.
"$TMP/run/bin/python" -c "
from coderifts import CodeRifts, read_decision, CodeRiftsError
assert callable(CodeRifts)
assert callable(read_decision)
print('ok import coderifts CodeRifts,read_decision')
"

# Pytest against the installed wheel. Cwd is TMP so the source tree is not on
# sys.path as a first-party package; tests live in ROOT/tests.
"$TMP/run/bin/python" -m pip install 'pytest>=7' >/dev/null
(cd "$TMP" && "$TMP/run/bin/python" -m pytest "$ROOT/tests" -q)

echo "packed install smoke: OK"
