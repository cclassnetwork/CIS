#!/usr/bin/env bash
# CCLASS INTELLIGENCE SUITE installer for Kali Linux / Debian / Ubuntu.
#   ./install.sh             install dependencies into ./.venv, initialise the database, run the self-tests
#   ./install.sh --vendor    additionally store Bootstrap/Leaflet/Chart.js/Cytoscape locally (offline dashboard)
#   ./install.sh --no-tests  skip the self-test run
#   ./install.sh --no-apt    never call apt (use when python3-venv is already installed)
set -euo pipefail

cd "$(dirname "$0")"
VENDOR=0; TESTS=1; APT=1
for arg in "$@"; do
  case "$arg" in
    --vendor) VENDOR=1 ;;
    --no-tests) TESTS=0 ;;
    --no-apt) APT=0 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;34m[CCLASS]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[CCLASS] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[CCLASS] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install it with: sudo apt install python3"
python3 - <<'PY' || die "Python 3.9 or newer is required."
import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

# --- system packages (venv + pip; ping is used by the optional network inventory) -----------------------------
need_pkgs=()
python3 -c "import venv, ensurepip" >/dev/null 2>&1 || need_pkgs+=(python3-venv python3-pip)
command -v ping >/dev/null 2>&1 || need_pkgs+=(iputils-ping)
if [ "${#need_pkgs[@]}" -gt 0 ]; then
  if [ "$APT" -eq 1 ] && command -v apt-get >/dev/null 2>&1; then
    say "Installing system packages: ${need_pkgs[*]}"
    $SUDO apt-get update -qq || warn "apt-get update failed; continuing"
    $SUDO apt-get install -y -qq "${need_pkgs[@]}" || die "apt could not install: ${need_pkgs[*]}"
  else
    warn "Missing system packages (${need_pkgs[*]}) and apt is unavailable or disabled."
  fi
fi

# --- virtual environment -----------------------------------------------------------------------------------
if [ ! -x .venv/bin/python ]; then
  say "Creating virtual environment (.venv)"
  python3 -m venv .venv || die "Could not create a virtualenv. Try: sudo apt install python3-venv"
fi
say "Installing Python dependencies"
.venv/bin/python -m pip install --quiet --upgrade pip || warn "pip upgrade failed; continuing with the existing pip"
.venv/bin/python -m pip install --quiet -r requirements.txt \
  || die "Dependency installation failed. Check your Internet connection / proxy and re-run ./install.sh"
touch .venv/.cclass_ready   # tells cclass.py the virtualenv is complete and safe to use

# --- optional local copies of the front-end libraries ----------------------------------------------------------
if [ "$VENDOR" -eq 1 ]; then
  V=cclass_suite/web/static/vendor; mkdir -p "$V"
  say "Downloading front-end libraries to $V"
  CDN=https://cdn.jsdelivr.net/npm
  fetch() { curl -fsSL --retry 2 "$1" -o "$V/$2" || { warn "could not download $2"; rm -f "$V/$2"; return 1; }; }
  ok=1
  fetch "$CDN/bootstrap@5.3.3/dist/css/bootstrap.min.css" bootstrap.min.css || ok=0
  fetch "$CDN/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" bootstrap.bundle.min.js || ok=0
  fetch "$CDN/leaflet@1.9.4/dist/leaflet.css" leaflet.css || ok=0
  fetch "$CDN/leaflet@1.9.4/dist/leaflet.js" leaflet.js || ok=0
  fetch "$CDN/chart.js@4.4.3/dist/chart.umd.min.js" chart.umd.min.js || ok=0
  fetch "$CDN/cytoscape@3.30.2/dist/cytoscape.min.js" cytoscape.min.js || ok=0
  if [ "$ok" -ne 1 ]; then
    warn "Some libraries failed to download; removing the partial set so the dashboard falls back to the CDN."
    rm -rf "$V"
  fi
fi

# --- database initialisation ---------------------------------------------------------------------------------
say "Initialising database"
.venv/bin/python cclass.py init

# --- self tests ------------------------------------------------------------------------------------------------
if [ "$TESTS" -eq 1 ]; then
  say "Running self-tests"
  if .venv/bin/python -m pytest -q tests; then say "All tests passed."; else warn "Some tests failed - see output above."; fi
fi

cat <<MSG

$(printf '\033[1;32m')Installation complete.$(printf '\033[0m')

  Create the admin account:   python3 cclass.py users add admin --role admin
  Start the dashboard:        python3 cclass.py            (or: python3 cclass.py --dashboard)
  Then open:                  http://127.0.0.1:8000
  Try the offline demo:       python3 cclass.py demo       (or the button on the Overview page)
  All commands:               python3 cclass.py --help

MSG
