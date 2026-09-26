#!/bin/bash
# Installs the third-party binaries the macOS port needs into bin/:
#
#   ctrtool     macOS build from 3DSGuy/Project_CTR  (v1.2.1, same as the
#               Windows release of Batch CIA 3DS Decryptor Redux)
#   makerom     macOS build from 3DSGuy/Project_CTR  (v0.18.4, same as the
#               Windows release)
#   seeddb.bin  from xxmichibxx/Batch-CIA-3DS-Decryptor-Redux (only needed for
#               9.6.0-24+ seed-encrypted titles)
#
# decrypt_mac.py, the decryption engine, is pure Python and needs no download.
#
# These files are deliberately NOT committed to this repository so that nothing
# third-party is redistributed here. Run this script once after cloning.

set -euo pipefail
cd "$(dirname "$0")"

CTRTOOL_TAG="ctrtool-v1.2.1"
MAKEROM_TAG="makerom-v0.18.4"
RELEASE_BASE="https://github.com/3DSGuy/Project_CTR/releases/download"
SEEDDB_URL="https://raw.githubusercontent.com/xxmichibxx/Batch-CIA-3DS-Decryptor-Redux/master/bin/seeddb.bin"
SEEDDB_SHA256="ccdcea5e4465194158737462436ec10ae48669dd961902282ac2861e260d03c9"

case "$(uname -m)" in
    arm64)  ARCH="macos_arm64"  ;;
    x86_64) ARCH="macos_x86_64" ;;
    *) echo "  Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

command -v curl >/dev/null || { echo "  curl is required" >&2; exit 1; }
command -v unzip >/dev/null || { echo "  unzip is required" >&2; exit 1; }

mkdir -p bin
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# fetch_release <tag> <binary name>
fetch_release() {
    local tag="$1" name="$2"
    echo "  Fetching $name ($tag, $ARCH)..."
    curl -fsSL -o "$TMP/$tag.zip" "$RELEASE_BASE/$tag/$tag-$ARCH.zip"
    unzip -oq "$TMP/$tag.zip" -d "$TMP/$name"
    install -m 0755 "$TMP/$name/$name" "bin/$name"
    # macOS quarantines downloaded binaries; strip the attribute so Gatekeeper
    # does not refuse to run them.
    xattr -c "bin/$name" 2>/dev/null || true
}

fetch_seeddb() {
    echo "  Fetching seeddb.bin (9.6.0-24+ seed database)..."
    curl -fsSL -o "$TMP/seeddb.bin" "$SEEDDB_URL"
    if command -v shasum >/dev/null; then
        local got
        got="$(shasum -a 256 "$TMP/seeddb.bin" | cut -d' ' -f1)"
        if [ "$got" != "$SEEDDB_SHA256" ]; then
            echo "  seeddb.bin checksum mismatch (got $got)" >&2
            exit 1
        fi
    fi
    install -m 0644 "$TMP/seeddb.bin" bin/seeddb.bin
}

fetch_release "$CTRTOOL_TAG" ctrtool
fetch_release "$MAKEROM_TAG" makerom
fetch_seeddb

echo
echo "  Installed into bin/:"
ls -l bin/ctrtool bin/makerom bin/seeddb.bin
echo
echo "  Versions:"
bin/ctrtool 2>&1 | head -2 || true
bin/makerom 2>&1 | head -2 || true
echo
echo "  Sanity check of the decryption engine:"
python3 bin/decrypt_mac.py --selftest || true
echo
echo "  Done. Double-click 'Batch CIA 3DS Decryptor Redux.command' to run."
