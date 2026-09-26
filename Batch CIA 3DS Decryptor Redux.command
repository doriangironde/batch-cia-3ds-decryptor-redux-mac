#!/bin/bash
# Double-clickable launcher for the macOS port of Batch CIA 3DS Decryptor Redux.
# Equivalent to double-clicking the Windows .bat file.

cd "$(dirname "$0")" || exit 1

PY=""
for candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    fi
done

if [ -z "$PY" ]; then
    echo
    echo "  Python 3.6 or newer is required but was not found."
    echo
    echo "  Install it with:  brew install python3"
    echo "  or from https://www.python.org/downloads/macos/"
    echo
    read -r -p "  Press Enter to close . . . " _
    exit 1
fi

exec "$PY" decryptor_mac.py "$@"
