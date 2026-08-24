#!/bin/sh
# Launcher for the Linux TCP/53 block watch. Same three choices as
# run_tcp53.bat offers on Windows.
set -eu

cd "$(dirname "$0")"

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "python3 was not found. Install the distribution's python3 package."
    exit 1
fi

cat <<'MENU'
===================================================
  TCP/53 Block Watch
===================================================

  [1] Watch continuously  (Ctrl+C to stop)
  [2] Run one diagnosis and write a report
  [3] Run the self-test

MENU

printf 'Select [1]: '
read -r choice || choice=""
[ -n "$choice" ] || choice=1

case "$choice" in
    2) "$PYTHON" ./tcp53-diagnose.py ;;
    3) "$PYTHON" ./tcp53-selftest.py ;;
    *) "$PYTHON" ./tcp53-watch.py ;;
esac
