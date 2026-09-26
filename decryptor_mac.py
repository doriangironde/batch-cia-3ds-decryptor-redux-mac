#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decryptor_mac.py -- macOS port of "Batch CIA 3DS Decryptor Redux.bat" (v1.0.6.3).

Drives the same pipeline as the Windows batch file:

    ctrtool  -> analyse the CIA / 3DS file
    decrypt  -> decrypt every NCCH into bin/tmp.*.ncch
    makerom  -> rebuild the decrypted CIA (or CCI for .3ds files)
    makerom  -> optionally convert the decrypted CIA to CCI (.cci)

Usage:
    python3 decryptor_mac.py            # interactive, same as double-clicking
    python3 decryptor_mac.py --no-pause --cci
    python3 decryptor_mac.py file.cia [file.3ds ...]
"""

import argparse
import datetime
import glob
import os
import platform
import re
import shutil
import subprocess
import sys

SCRIPT_VERSION = "v1.0.6.3"
BANNER = "Batch CIA 3DS Decryptor Redux (macOS port)"

HERE = os.path.dirname(os.path.realpath(__file__))
BIN = os.path.join(HERE, "bin")
CTRT = os.path.join(BIN, "ctrtool")
MAKEROM = os.path.join(BIN, "makerom")
DECRYPT = os.path.join(BIN, "decrypt_mac.py")
SEEDDB = os.path.join(BIN, "seeddb.bin")
LOGDIR = os.path.join(HERE, "log")
LOGFILE = os.path.join(LOGDIR, "programlog.txt")

# NCCH partition names, indexed by NCSD partition number (for .3ds / CCI files)
NCSD_PARTITIONS = ["Main", "Manual", "DownloadPlay", "Partition4",
                   "Partition5", "Partition6", "N3DSUpdateData", "UpdateData"]

# Title ID prefix -> CIA type.  Keys are the first 8 hex digits.
TITLE_TYPES = [
    ("00040000", "Game"),        # eShop / gamecard
    ("00040010", "System"),
    ("0004001b", "System"),
    ("00040030", "System"),
    ("0004009b", "System"),
    ("000400db", "System"),
    ("00040130", "System"),
    ("00040138", "System"),
    ("00040002", "Demo"),
    ("0004000e", "Patch"),
    ("0004008c", "DLC"),
    ("00048005", "TWL"),         # TWL system application
    ("0004800f", "TWL"),         # TWL system data archive
    ("00048004", "TWL"),         # TWL 3DS DSiWare port
]

# CIA types that cannot be converted to CCI (mirrors the batch file)
NO_CCI_TYPES = {"DLC", "Patch", "Demo", "System", "TWL"}

SYSTEM_LABELS = {
    "00040010": "a system application",
    "0004001b": "a system data archive",
    "000400db": "a system data archive",
    "00040030": "a system applet",
    "0004009b": "a shared data archive",
    "00040130": "a system module",
    "00040138": "a system firmware",
}


def now():
    return datetime.datetime.now().strftime("%d.%m.%Y - %H:%M:%S")


class Log(object):
    def __init__(self, path):
        self.path = path
        self.fh = open(path, "w")

    def info(self, msg):
        line = "%s = [i] %s" % (now(), msg)
        self.fh.write(line + "\n")
        self.fh.flush()

    def warn(self, msg):
        line = "%s = [^] %s" % (now(), msg)
        self.fh.write(line + "\n")
        self.fh.flush()

    def error(self, msg):
        line = "%s = [^!] %s" % (now(), msg)
        self.fh.write(line + "\n")
        self.fh.flush()

    def plain(self, msg=""):
        self.fh.write(msg + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()


def banner():
    print("  ############################################################")
    print("  ###                                                      ###")
    title = "  %s %s" % (BANNER, SCRIPT_VERSION)
    pad = max(1, 54 - len(title))
    left = pad // 2
    print("  ###%s%s%s###" % (" " * left, title, " " * (pad - left)))
    print("  ###                                                      ###")
    print("  ############################################################")


def run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


def clean_ncch():
    for path in glob.glob(os.path.join(BIN, "*.ncch")):
        try:
            os.remove(path)
        except OSError:
            pass


def sanitize_names():
    """Strip characters the batch file's PowerShell filter removed.

    The Windows script kept only [A-Za-z0-9 _&.-]; makerom and the shell
    handle those names reliably.  Collisions get a numeric suffix instead of
    silently clobbering a file (the batch file had that bug).
    """
    for path in sorted(glob.glob(os.path.join(HERE, "*.cia")) +
                       glob.glob(os.path.join(HERE, "*.3ds"))):
        directory, base = os.path.split(path)
        stem, ext = os.path.splitext(base)
        new_stem = re.sub(r"[^A-Za-z0-9 _&.\-]", "", stem).strip()
        if not new_stem:
            new_stem = "unnamed"
        candidate = new_stem + ext
        n = 2
        while candidate.lower() != base.lower() and os.path.exists(os.path.join(directory, candidate)):
            candidate = "%s_%d%s" % (new_stem, n, ext)
            n += 1
        if candidate != base:
            os.rename(path, os.path.join(directory, candidate))
            print("  Renamed: %s  ->  %s" % (base, candidate))


def analyse(path, log):
    """Run ctrtool over a CIA/3DS and return its output text."""
    proc = run([CTRT, "--seeddb=" + SEEDDB, path], cwd=HERE)
    return proc.stdout.decode("utf-8", "replace")


def parse_cia_info(text):
    info = {"title_id": "", "version": "0", "crypto": "", "content_ids": []}
    for line in text.splitlines():
        stripped = line.strip()
        if "Title id:" in line:
            info["title_id"] = stripped.split("Title id:")[1].strip().lower()
        elif "TitleVersion:" in stripped:
            # ctrtool prints "|- TitleVersion:  2.2.0 (2080)".  makerom's -ver
            # wants the parenthesised value.  (The Windows batch file passed the
            # "2.2.0" text here, which makerom silently mis-parses.)
            rest = stripped.split("TitleVersion:")[1]
            match = re.search(r"\(([^)]*)\)", rest)
            if match:
                info["version"] = match.group(1)
            elif rest.split():
                info["version"] = rest.split()[0]
        elif "Crypto Key" in line:
            info["crypto"] = stripped
        elif "ContentId:" in line:
            hexid = stripped.split("ContentId:")[1].strip()
            if hexid.lower().startswith("0x"):
                try:
                    info["content_ids"].append(int(hexid, 16))
                except ValueError:
                    pass
    return info


def title_type(title_id):
    if not title_id:
        return "Unknown"
    prefix = title_id[:8]
    for pref, kind in TITLE_TYPES:
        if prefix == pref:
            return kind
    return "Game"


def ncch_inputs(bindir="bin"):
    """Return [(path, index)] for the tmp.*.ncch files decrypt_mac.py produced,
    sorted numerically so the order matches the content index."""
    found = []
    for path in glob.glob(os.path.join(bindir, "tmp.*.ncch")):
        m = re.search(r"tmp\.(\d+)\.ncch$", os.path.basename(path))
        if m:
            found.append((path, int(m.group(1))))
    return sorted(found, key=lambda t: t[1])


def make_cci_for_3ds(stem, log, counters):
    """Rebuild a decrypted .3ds (NCSD) as a CCI, mirroring the batch file."""
    inputs = []
    for path, idx in ncch_inputs():
        name = os.path.basename(path)
        if re.match(r"tmp\.(Main|Manual|DownloadPlay|Partition[456]|N3DSUpdateData|UpdateData)\.ncch$", name):
            inputs += ["-content", "%s:%d" % (path, idx)]
    out = os.path.join(HERE, "%s-decrypted.cci" % stem)
    if os.path.exists(out):
        log.warn('3DS file "%s.3ds" was already decrypted' % stem)
        counters["final"] += 1
        return
    if not inputs:
        log.error("No NCCH partitions were decrypted for %s.3ds" % stem)
        counters["ds_err"] += 1
        return
    run([MAKEROM, "-f", "cci", "-ignoresign", "-target", "p", "-o", out] + inputs, cwd=HERE)
    clean_ncch()
    if not os.path.exists(out):
        log.error('Decrypting failed for file "%s.3ds"' % stem)
        counters["ds_err"] += 1
    else:
        log.info('Decrypting succeeded for file "%s.3ds"' % stem)
        counters["final"] += 1


def decrypt_with_engine(path, log):
    proc = run([sys.executable, DECRYPT, "--outdir", BIN, "--seeddb", SEEDDB, path], cwd=HERE)
    text = proc.stdout.decode("utf-8", "replace")
    for line in text.splitlines():
        if "Parsing" in line or "Product code" in line or "KeyY" in line or \
                "Title ID" in line or "crypto" in line.lower() or "Encrypted" in line:
            log.plain("    " + line)
    return proc.returncode == 0


def makerom_args_for_cia(kind, content_ids, version):
    """Build the makerom argument list.

    Note: makerom's documented syntax is `-content <file>:<index>:<id>`; the
    Windows batch file used an undocumented `-i` shorthand here.
    """
    args = ["-f", "cia", "-ignoresign", "-target", "p"]
    if kind == "DLC":
        args += ["-dlc"]
    for path, idx in ncch_inputs():
        # Patches and DLCs carry explicit content IDs in the TMD; everything
        # else uses the NCCH index as the content ID.
        cid = content_ids[idx] if (kind in ("Patch", "DLC") and idx < len(content_ids)) else idx
        args += ["-content", "%s:%d:%d" % (path, idx, cid)]
    args += ["-ver", version]
    return args


def make_decrypted_cia(stem, kind, info, log, counters):
    out = os.path.join(HERE, "%s %s-decrypted.cia" % (stem, kind))
    args = makerom_args_for_cia(kind, info["content_ids"], info["version"])
    log.info("Calling makerom for %s CIA [%s v%s]" % (kind, info["title_id"], info["version"]))
    proc = run([MAKEROM, "-o", out] + args, cwd=HERE)
    clean_ncch()
    if not os.path.exists(out):
        log.error("Decrypting failed [%s v%s]" % (info["title_id"], info["version"]))
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if line.strip():
                log.plain("      " + line)
        counters["cia_err"] += 1
        return None
    log.info("Decrypting succeeded [%s v%s]" % (info["title_id"], info["version"]))
    counters["final"] += 1
    return out


def convert_to_cci(cia_path, log, counters):
    stem = os.path.splitext(os.path.basename(cia_path))[0]
    out = os.path.join(HERE, "%s.cci" % stem)
    if os.path.exists(out):
        log.warn('CIA file "%s" was already converted into CCI' % os.path.basename(cia_path))
        counters["final"] += 1
        return
    log.info("Converting to CCI [%s]" % os.path.basename(cia_path))
    run([MAKEROM, "-ciatocci", os.path.basename(cia_path), "-o", os.path.basename(out)], cwd=HERE)
    if not os.path.exists(out):
        log.error("Converting to CCI failed [%s]" % os.path.basename(cia_path))
        counters["cci_err"] += 1
    else:
        os.remove(cia_path)
        log.info("Converting to CCI succeeded [%s]" % os.path.basename(out))
        counters["final"] += 1


def summarise(counters, convert_cci):
    print("  Summary:")
    if counters["ds"]:
        if counters["ds_err"]:
            print("  - %d from %d 3DS file[s] were not decrypted" % (counters["ds_err"], counters["ds"]))
        else:
            print("  - %d from %d 3DS file[s] decrypted" % (counters["ds"], counters["ds"]))
    if counters["cia"]:
        if convert_cci:
            if counters["cci_err"]:
                print("  - %d from %d CIA file[s] were not decrypted into CCI"
                      % (counters["cci_err"], counters["cia"]))
            else:
                print("  - %d from %d CIA file[s] decrypted into CCI" % (counters["cia"], counters["cia"]))
        elif counters["cia_err"]:
            print("  - %d from %d CIA file[s] were not decrypted" % (counters["cia_err"], counters["cia"]))
        else:
            print("  - %d from %d CIA file[s] decrypted" % (counters["cia"], counters["cia"]))


def pause():
    try:
        input("\n  Press Enter to close this window . . . ")
    except (EOFError, KeyboardInterrupt):
        pass


def check_environment(log):
    if platform.machine() not in ("x86_64", "arm64"):
        print()
        banner()
        print()
        print("  The current architecture is not supported.")
        print("  This port requires an Apple silicon or Intel Mac (64-bit).")
        print()
        print("  Script execution halted!")
        return False
    missing = [p for p in (CTRT, MAKEROM, DECRYPT) if not os.path.exists(p)]
    if missing:
        print()
        banner()
        print()
        print("  Missing required files in bin/:")
        for path in missing:
            print("    - %s" % os.path.basename(path))
        print()
        print("  Run ./setup-macos.sh to install the third-party binaries.")
        return False
    if not os.path.exists(SEEDDB):
        print()
        print("  Note: bin/seeddb.bin is missing. Titles that use 9.6.0-24+ seed")
        print("  crypto cannot be decrypted without it. Run ./setup-macos.sh.")
        print()
    for path in (CTRT, MAKEROM):
        if not os.access(path, os.X_OK):
            os.chmod(path, 0o755)
    return True


def main():
    ap = argparse.ArgumentParser(description="macOS port of Batch CIA 3DS Decryptor Redux")
    ap.add_argument("files", nargs="*", help="CIA / 3DS files (default: all in this folder)")
    ap.add_argument("--cci", dest="cci", action="store_true", default=None,
                    help="convert decrypted CIAs to CCI (equivalent to answering Y)")
    ap.add_argument("--no-cci", dest="cci", action="store_false",
                    help="keep decrypted CIAs as CIAs (equivalent to answering N)")
    ap.add_argument("--no-pause", action="store_true", help="do not wait for Enter at the end")
    args = ap.parse_args()

    if not check_environment(None):
        if not args.no_pause:
            pause()
        return 1

    os.makedirs(LOGDIR, exist_ok=True)
    log = Log(LOGFILE)
    log.plain(BANNER)
    log.plain("[i] = Information")
    log.plain("[^] = Warning")
    log.plain("[^!] = Error")
    log.plain()
    log.plain("%s %s" % (BANNER, SCRIPT_VERSION))
    log.info("Script started")

    counters = {"cia": 0, "ds": 0, "final": 0, "cia_err": 0, "cci_err": 0, "ds_err": 0}
    convert_cci = bool(args.cci)

    try:
        clean_ncch()
        sanitize_names()

        if args.files:
            targets = [os.path.abspath(p) for p in args.files]
        else:
            targets = sorted(glob.glob(os.path.join(HERE, "*.cia")) +
                             glob.glob(os.path.join(HERE, "*.3ds")))

        cia_files = [p for p in targets if p.lower().endswith(".cia") and "-decrypted" not in p]
        ds_files = [p for p in targets if p.lower().endswith(".3ds") and "-decrypted" not in p]
        counters["cia"] = len(cia_files)
        counters["ds"] = len(ds_files)

        if not targets:
            print()
            banner()
            print()
            print("  No CIA or 3DS files found!")
            print()
            print("  Please review log/programlog.txt for more details.")
            log.warn("No CIA or 3DS were found")
            log.info("Script execution ended")
            if not args.no_pause:
                pause()
            return 0

        if cia_files and convert_cci is None:
            print()
            banner()
            print()
            if len(cia_files) == 1:
                print("  A CIA file was found. Do you want to convert it to CCI?")
            else:
                print("  %d CIA files were found. Do you want to convert them to CCI?" % len(cia_files))
            print("  Please be aware that this doesn't work with the following")
            print("  titles:")
            print()
            print("  - Downloadable Content [DLC]")
            print("  - eShop Demos")
            print("  - System titles")
            print("  - TWL titles [DSi]")
            print("  - Updates")
            print()
            print("  This applies to all CIA files that have been found.")
            print("  The default option is No [N]. If you're unsure choose No.")
            print()
            print("  [Y] Yes")
            print("  [N] No")
            print()
            try:
                answer = input("  Enter: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            convert_cci = answer in ("y", "1")

        print()
        banner()
        print()
        print("  Decrypting...")

        # ---- .3ds / NCSD files ------------------------------------------
        for path in ds_files:
            stem = os.path.splitext(os.path.basename(path))[0]
            log.info('Found 3DS file "%s.3ds". Start decrypting...' % stem)
            clean_ncch()
            decrypt_with_engine(path, log)
            make_cci_for_3ds(stem, log, counters)
            clean_ncch()

        # ---- CIA files ---------------------------------------------------
        for path in cia_files:
            stem = os.path.splitext(os.path.basename(path))[0]
            already = glob.glob(os.path.join(HERE, "%s*-decrypted.cia" % stem))
            if already:
                if convert_cci:
                    convert_to_cci(already[0], log, counters)
                else:
                    log.warn('CIA file "%s.cia" was already decrypted' % stem)
                    counters["final"] += 1
                continue

            log.info('Found CIA file "%s.cia". Start decrypting...' % stem)
            text = analyse(path, log)
            if "ERROR" in text:
                log.error('CIA is invalid ["%s.cia"]' % stem)
                counters["cia_err"] += 1
                clean_ncch()
                continue
            info = parse_cia_info(text)
            kind = title_type(info["title_id"])

            if "None" in info["crypto"]:
                log.warn('CIA file "%s.cia" [%s v%s] is already decrypted'
                         % (stem, info["title_id"], info["version"]))
                counters["cia_err"] += 1
                clean_ncch()
                continue

            label = SYSTEM_LABELS.get(info["title_id"][:8])
            if label:
                log.info('CIA file "%s.cia" [%s v%s] is %s'
                         % (stem, info["title_id"], info["version"], label))
            elif kind == "Game":
                log.info('CIA file "%s.cia" [%s v%s] is a eShop or Gamecard title'
                         % (stem, info["title_id"], info["version"]))
            elif kind == "Demo":
                log.info('CIA file "%s.cia" [%s v%s] is a demo title'
                         % (stem, info["title_id"], info["version"]))
            elif kind in ("Patch", "DLC"):
                log.info('CIA file "%s.cia" [%s v%s] is a update or DLC title'
                         % (stem, info["title_id"], info["version"]))
            elif kind == "TWL":
                log.info('CIA file "%s.cia" [%s v%s] is a TWL title [DSi]'
                         % (stem, info["title_id"], info["version"]))
            else:
                log.warn('CIA file "%s.cia" [%s v%s] has an unrecognised title id'
                         % (stem, info["title_id"], info["version"]))

            if kind == "TWL":
                log.warn("TWL titles are not supported by this port "
                         "(use a Windows machine or melonDS)")
                counters["cia_err"] += 1
                clean_ncch()
                continue

            clean_ncch()
            decrypt_with_engine(path, log)
            if not ncch_inputs():
                log.error('Decrypting failed ["%s.cia"] -- no NCCH data produced' % stem)
                counters["cia_err"] += 1
                clean_ncch()
                continue

            result = make_decrypted_cia(stem, kind, info, log, counters)
            if result and convert_cci:
                if kind in NO_CCI_TYPES:
                    if os.path.exists(result):
                        os.remove(result)
                    log.warn("Converting to CCI for this title is not supported [%s]"
                             % info["title_id"])
                    counters["cci_err"] += 1
                else:
                    convert_to_cci(result, log, counters)

        clean_ncch()

        # ---- results -----------------------------------------------------
        print()
        banner()
        print()
        total = counters["cia"] + counters["ds"]
        errs = counters["cia_err"] + counters["cci_err"] + counters["ds_err"]
        if counters["final"] == 0:
            print("  No files were decrypted!")
        elif errs or counters["final"] != total:
            print("  Some files were not decrypted!")
            summarise(counters, convert_cci)
        else:
            print("  Decrypting finished!")
            summarise(counters, convert_cci)
        print()
        print("  Please review log/programlog.txt for more details.")
        print()

        if counters["final"] == 0:
            log.warn("No files where decrypted")
        elif errs or counters["final"] != total:
            log.warn("Some files where not decrypted")
        else:
            log.info("Decrypting process succeeded")
        log.info("Script execution ended")
        return 0
    finally:
        clean_ncch()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
