# Batch CIA 3DS Decryptor Redux — macOS

A native macOS port of **[Batch CIA 3DS Decryptor Redux](https://github.com/xxmichibxx/Batch-CIA-3DS-Decryptor-Redux)**
v1.0.6.3, the Windows `.bat` release.

It decrypts Nintendo 3DS `.cia` and `.3ds` files so you can install them on
emulators or keep readable backups of your own games. Double-click a `.command`
file instead of a `.bat`, and it just works.

- Runs on **Apple silicon and Intel** Macs, 64-bit
- **No dependencies to install** — Python 3 and `openssl` both ship with macOS
- Decrypts a 3.7 GB title in about **30 seconds**
- Fixes three real bugs in the original Windows decryption engine (see below)

> Decrypt your own backups. Nothing here bypasses account or purchase
> authentication, and the output is only useful for content you own.

## Install

```bash
git clone https://github.com/doriangironde/batch-cia-3ds-decryptor-redux-mac.git
cd batch-cia-3ds-decryptor-redux-mac
./setup-macos.sh
```

`setup-macos.sh` downloads `ctrtool` and `makerom` (the official macOS builds
from [3DSGuy/Project_CTR](https://github.com/3DSGuy/Project_CTR), at the same
versions the Windows release uses) plus `seeddb.bin`. They are not committed
here so that nothing third-party is redistributed by this repository — see
[THIRD-PARTY.md](THIRD-PARTY.md).

You also need **Python 3.6+**. macOS ships `/usr/bin/python3`, so there is
usually nothing to do; otherwise `brew install python3`.

## Use

1. Put your `.cia` / `.3ds` files in the repository folder.
2. Double-click **`Batch CIA 3DS Decryptor Redux.command`**.
3. If asked about CCI conversion, answer **N** unless you specifically want
   installable `.cci` files.
4. Decrypted files appear next to the originals as
   `<name> Game-decrypted.cia`, `<name> Patch-decrypted.cia`, and so on.
5. Details land in `log/programlog.txt`.

From a terminal:

```bash
./"Batch CIA 3DS Decryptor Redux.command"        # interactive
python3 decryptor_mac.py --no-pause --no-cci     # non-interactive, keep CIAs
python3 decryptor_mac.py --no-pause --cci        # non-interactive, convert to CCI
python3 decryptor_mac.py some-file.cia            # only the files you name
```

Sanity-check the crypto on your machine at any time:

```bash
python3 bin/decrypt_mac.py --selftest
```

That runs the NIST SP 800-38A AES-128-CTR and AES-128-CBC vectors plus a
`scramblekey` check. Every line should read `PASS`.

## What is in here

| Path | Purpose |
|---|---|
| `Batch CIA 3DS Decryptor Redux.command` | Double-clickable launcher |
| `decryptor_mac.py` | Port of the `.bat` logic: type detection, makerom calls, logging |
| `bin/decrypt_mac.py` | Port of `decrypt.exe` — the NCCH decryption engine (pure Python) |
| `setup-macos.sh` | Fetches `ctrtool`, `makerom` and `seeddb.bin` |
| `THIRD-PARTY.md` | Attribution and licensing notes |

`bin/decrypt_mac.py` needs no download. AES runs through `pycryptodome` if it
happens to be installed, otherwise the system `openssl` (hardware accelerated),
otherwise a bundled pure-Python fallback that is far too slow for large titles.

## Verification

Decryption was checked against `ctrtool`'s independent implementation. For both
CIAs used during development, every region — exheader, ExeFS and RomFS — is
**byte-identical** to `ctrtool`'s output, including a 3.7 GB RomFS and a
9.6.0-24 seed-crypto partition. The rebuilt CIAs report `Crypto Key: None` when
read back, and `ctrtool -y` passes 31/31 content hash checks.

Measured on an M-series Mac:

| Title | Input | Time |
|---|---|---|
| Game update | 70 MB, 1 NCCH | ~1 s |
| Gamecard image | 3.7 GB, 2 NCCHs, incl. 9.6 seed crypto | ~30 s |

## Differences from the Windows version

### The original engine was broken

`decrypt.exe` is a PyInstaller-packed Python 2.7 script. This port is a
line-by-line port of the recovered source, and doing so surfaced three real
defects. The upshot: **the original never derived a correct title key**, so
every file it touched decrypted to garbage — which `makerom` still cheerfully
repackaged into a structurally valid CIA. That is why its log cheerfully
reported "Decrypting succeeded" on files it had not actually decrypted.

1. **Wrong common key.** `decrypt.py` used
   `to_bytes([8, 9, 10, 11, 12, 13][keyId], 16)` as the ES common key. Those
   are *keyslot numbers*, not key material, so the AES key became `0x…08`. The
   real common keys (e.g. `64C5FD55DD3AD988325BAAEC5243DB98` for `keyId` 0) are
   used here, matching `3DSGuy/Project_CTR`.
2. **CBC chain never advanced.** Consecutive reads of a CIA content reused the
   same IV instead of carrying the cipher chain, so only the first block of each
   partition decrypted correctly.
3. **Content offset desync.** When a content failed the `NCCH` magic check, the
   original `continue`d without advancing `nextContentOffs`, corrupting every
   later content in the same CIA.

### Driver fixes

- **Title version is preserved.** The `.bat` passed the string `2.2.0` to
  `makerom -ver`, which silently mis-parsed it into version `0.0.2`. The
  parenthesised value (`2080`) is used now, so a v2.2.0 update stays v2.2.0 —
  which is what the upstream README claims the tool already did.
- **`makerom -content` instead of `-i`**, and the `file:index:id` field order
  was corrected; the batch had `index` and `id` swapped.
- **Filename sanitising** keeps `[A-Za-z0-9 _&.-]` like the batch's PowerShell
  filter, but no longer eats path separators, and de-duplicates colliding names
  instead of overwriting a file.
- The "press any key" prompt is skipped when stdin is not a terminal, so the
  tool is scriptable.

### Deliberate omissions

- **TWL (DSi) CIAs** are detected and reported, then skipped. The `.bat` used a
  `ren` call with a wildcard that `cmd.exe` does not support, so that path was
  already broken. Use a Windows machine, or melonDS to run TWL titles.
- **Online title-key lookup is off by default.** The original *tried* to fall
  back to a network key service when a seed was missing from `seeddb.bin`, but
  the code was unreachable on Python 2 (`urllib.urlopen` does not exist there).
  It is implemented here, correctly, behind `--allow-online-keys`. Without that
  flag the tool is fully offline.
- The decorative "GOLF" easter egg was dropped.

### Unverified path

The `.3ds` → `.cci` rebuild could not be tested end to end: no real `.3ds`
sample was available, and **makerom v0.18.4 refuses to build a CCI from raw
`.ncch` inputs**, so a synthetic test file cannot be manufactured. The NCSD
parsing and decryption path *is* verified (partition traversal, `tmp.Main.ncch`
naming, "Not Encrypted" handling), and the rebuild call matches the `.bat`. If
you have an actual `.3ds`, please try it — failures are captured verbatim in
the log.

## Caveats

- **Move finished files out of the folder before running again.** An existing
  `<name>*-decrypted.cia` makes the tool skip that title, and the CCI path
  *deletes* the decrypted CIA whether or not it succeeded.
- Input filenames get rewritten to strip parentheses and other awkward
  characters. That is inherited from the `.bat`; move your originals elsewhere
  first if you want to keep the exact names.
- Answer **N** to the CCI question unless you are sure. CCI conversion is not
  supported for DLC, demos, system titles, TWL titles or updates.
- `[TIK WARNING] Failed to sign header` from makerom is **expected** for modded
  tickets, whose signature field is all `FF`. Re-signing needs console keys
  nobody has, which is why `-ignoresign` is used. The output is still a valid
  decrypted CIA.

## Credits

- **Batch CIA 3DS Decryptor Redux** — [xxmichibxx](https://github.com/xxmichibxx/Batch-CIA-3DS-Decryptor-Redux),
  itself a rewrite of matiffeder's original. Bug reports about Windows
  behaviour belong upstream.
- **`decrypt.exe`** — davidmorom, recovered from the bundled PyInstaller
  archive and ported to Python 3.
- **CTRTool / MakeROM** — [3DSGuy/Project_CTR](https://github.com/3DSGuy/Project_CTR).
- **seeddb.bin** — [ihaveamac](https://github.com/ihaveamac/3DS-rom-tools/tree/master/seeddb).

macOS port by [doriangironde](https://github.com/doriangironde). No license is
granted here; see [THIRD-PARTY.md](THIRD-PARTY.md) for why, and for who to ask.
