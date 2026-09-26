#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decrypt_mac.py -- Python 3 / macOS port of `decrypt.exe` (by davidmorom), the
decryption engine bundled with Batch CIA 3DS Decryptor Redux v1.0.6.3.

The Windows `decrypt.exe` is a PyInstaller bundle wrapping a Python 2.7 script.
This is a faithful port of that recovered source: identical crypto, identical
on-disk output, identical seeddb.bin handling.  Deliberate differences:

  * Python 3 / bytes-correct instead of Python 2.7.
  * AES backend is auto-selected: pycryptodome -> openssl(1) -> pure Python.
    macOS ships openssl, so there is nothing to install.
  * The original's online seed lookup was dead code (Python 2's `urllib` has no
    `urlopen` accepting a `context=` kwarg).  It is implemented here properly,
    but stays OFF unless `--allow-online-keys` is given.
  * NCCH files are written to `--outdir` (default: this script's own directory,
    i.e. `bin/`), which is where the Windows build wrote them.

No console, no keys, no network are required for normal titles: the NCCH
KeyY is read from the NCCH's own header and combined with the embedded 0x2C
master key, exactly as the original does.
"""

import argparse
import glob
import os
import re
import struct
import subprocess
import sys
from binascii import unhexlify
from hashlib import sha256

MEDIA_UNIT_SIZE = 512
NCSD_PARTITIONS = ["Main", "Manual", "DownloadPlay", "Partition4",
                   "Partition5", "Partition6", "N3DSUpdateData", "UpdateData"]


# ---------------------------------------------------------------------------
# AES backend: pycryptodome -> openssl(1) -> pure Python
# ---------------------------------------------------------------------------

def _gmul(a, b):
    """Multiply two bytes in GF(2^8) with the AES polynomial."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gmul(r, a)
        a = _gmul(a, a)
        e >>= 1
    return r


def _build_sbox():
    """Derive the AES S-box from GF(2^8) inversion + the affine transform.

    Deriving it beats hand-typing 256 hex bytes: it cannot contain a typo.
    """
    sbox = [0] * 256
    for a in range(256):
        inv = _gf_pow(a, 254) if a else 0
        s = inv
        x = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[a] = s ^ 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def _mul_table(factor):
    return [_gmul(x, factor) for x in range(256)]


_M2, _M3 = _mul_table(2), _mul_table(3)
_M9, _M11, _M13, _M14 = _mul_table(9), _mul_table(11), _mul_table(13), _mul_table(14)


def _shift_rows_perm():
    """Permutation for ShiftRows.

    Per FIPS-197 the state is column-major (flat index i == 4*column + row) and
    row r is cyclically rotated LEFT by r, i.e. new[r][c] = old[r][(c - r) % 4].
    Returned as a gather list `p` where out[i] = in[p[i]].
    """
    p = [0] * 16
    for c in range(4):
        for r in range(4):
            p[4 * ((c - r) % 4) + r] = 4 * c + r
    return p


SHIFT_ROWS = _shift_rows_perm()


def _invert_gather(perm):
    """Invert a gather permutation `out[i] = in[perm[i]]`."""
    inv = [0] * len(perm)
    for i, src in enumerate(perm):
        inv[src] = i
    return inv


INV_SHIFT_ROWS = _invert_gather(SHIFT_ROWS)


class PurePythonAES(object):
    """Minimal AES-128/192/256 block cipher.  Used only as a last resort."""

    def __init__(self, key):
        nk = len(key) // 4
        if nk not in (4, 6, 8):
            raise ValueError("invalid AES key length: %d" % len(key))
        self.nr = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        rcon = 1
        for i in range(nk, 4 * (self.nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= rcon
                rcon = _gmul(rcon, 2)
            elif nk > 6 and i % nk == 4:
                t = [SBOX[b] for b in t]
            prev = w[i - nk]
            w.append([prev[j] ^ t[j] for j in range(4)])
        self.w = w

    def _add_round_key(self, s, rnd):
        w = self.w
        for c in range(4):
            k = w[rnd * 4 + c]
            o = 4 * c
            s[o] ^= k[0]
            s[o + 1] ^= k[1]
            s[o + 2] ^= k[2]
            s[o + 3] ^= k[3]

    def encrypt_block(self, block):
        s = list(block)
        self._add_round_key(s, 0)
        for rnd in range(1, self.nr):
            s = [SBOX[b] for b in s]
            s = [s[i] for i in SHIFT_ROWS]
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                s[c] = _M2[a0] ^ _M3[a1] ^ a2 ^ a3
                s[c + 1] = a0 ^ _M2[a1] ^ _M3[a2] ^ a3
                s[c + 2] = a0 ^ a1 ^ _M2[a2] ^ _M3[a3]
                s[c + 3] = _M3[a0] ^ a1 ^ a2 ^ _M2[a3]
            self._add_round_key(s, rnd)
        s = [SBOX[b] for b in s]
        s = [s[i] for i in SHIFT_ROWS]
        self._add_round_key(s, self.nr)
        return bytes(s)

    def decrypt_block(self, block):
        s = list(block)
        self._add_round_key(s, self.nr)
        for rnd in range(self.nr - 1, 0, -1):
            s = [s[i] for i in INV_SHIFT_ROWS]
            s = [INV_SBOX[b] for b in s]
            self._add_round_key(s, rnd)
            # InvMixColumns
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                s[c] = _M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3]
                s[c + 1] = _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3]
                s[c + 2] = _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3]
                s[c + 3] = _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3]
        s = [s[i] for i in INV_SHIFT_ROWS]
        s = [INV_SBOX[b] for b in s]
        self._add_round_key(s, 0)
        return bytes(s)


def _find_openssl():
    for cand in ("/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


class _Backend(object):
    """AES-CTR / AES-CBC decryption over whichever implementation is present."""

    def __init__(self):
        self.name = None
        self._aes = None
        self._openssl = None
        try:
            from Crypto.Cipher import AES as _A  # pycryptodome
            self._aes = _A
            self.name = "pycryptodome"
            return
        except ImportError:
            pass
        self._openssl = _find_openssl()
        if self._openssl:
            self.name = "openssl (%s)" % self._openssl
            return
        self.name = "pure python (SLOW - expect minutes per GB)"

    @staticmethod
    def _check_key(key):
        if len(key) not in (16, 24, 32):
            raise ValueError("invalid AES key length: %d" % len(key))

    def ctr(self, data, key, counter):
        """Decrypt `data` in AES-CTR mode.  `counter` is the full 16-byte
        initial counter block (big endian)."""
        if not data:
            return b""
        self._check_key(key)
        if self._aes is not None:
            from Crypto.Util import Counter
            cipher = self._aes.new(key, self._aes.MODE_CTR,
                                   counter=Counter.new(128, initial_value=int.from_bytes(counter, "big")))
            return cipher.decrypt(data)
        if self._openssl is not None:
            p = subprocess.Popen(
                [self._openssl, "enc", "-aes-%d-ctr" % (len(key) * 8),
                 "-K", key.hex(), "-iv", counter.hex(), "-nosalt", "-nopad"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate(data)
            if p.returncode != 0:
                raise RuntimeError("openssl failed: %s" % err.decode("utf-8", "replace").strip())
            return out
        cipher = PurePythonAES(key)
        return self._ctr_pure(cipher, data, counter)

    @staticmethod
    def _ctr_pure(cipher, data, counter):
        ctr_int = int.from_bytes(counter, "big")
        out = bytearray(len(data))
        total = len(data)
        pos = 0
        # Regenerate one keystream block per 16 bytes of input.
        while pos < total:
            ks = cipher.encrypt_block((ctr_int + (pos // 16)).to_bytes(16, "big"))
            n = min(16, total - pos)
            for i in range(n):
                out[pos + i] = data[pos + i] ^ ks[i]
            pos += n
        return bytes(out)

    def cbc_decrypt(self, data, key, iv):
        """Decrypt `data` in AES-CBC mode (len(data) must be a multiple of 16)."""
        if not data:
            return b""
        self._check_key(key)
        if len(data) % 16:
            raise ValueError("CBC input is not a multiple of the block size")
        if self._aes is not None:
            return self._aes.new(key, self._aes.MODE_CBC, iv).decrypt(data)
        if self._openssl is not None:
            p = subprocess.Popen(
                [self._openssl, "enc", "-aes-%d-cbc" % (len(key) * 8), "-d",
                 "-K", key.hex(), "-iv", iv.hex(), "-nosalt", "-nopad"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate(data)
            if p.returncode != 0:
                raise RuntimeError("openssl failed: %s" % err.decode("utf-8", "replace").strip())
            return out
        cipher = PurePythonAES(key)
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            blk = data[i:i + 16]
            dec = cipher.decrypt_block(blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
        return bytes(out)


AES = _Backend()


# ---------------------------------------------------------------------------
# Key crypto constants
# ---------------------------------------------------------------------------

# ES common keys, indexed by the ticket's `keyId` field (ticket offset 0x1F1).
# Values taken from 3DSGuy/Project_CTR (ctrtool/src/KeyBag.cpp).
#
# NOTE: the original decrypt.py used `to_bytes([8,9,10,11,12,13][keyId], 16)`
# here.  Those are the *keyslot numbers*, not key material, so the Windows
# build derived a garbage title key for every title it ever touched.  These
# are the real common keys.
COMMON_KEYS_RETAIL = [
    "64C5FD55DD3AD988325BAAEC5243DB98",   # keyId 0 - application
    "4AAA3D0E27D4D728D0B1B433F0F9CBC8",   # keyId 1 - system
    "FBB0EF8CDBB0D8E453CD99344371697F",   # keyId 2 - unused
    "25959B7AD0409F72684198BA2ECD7DC6",   # keyId 3 - unused
    "7ADA22CAFFC476CC8297A0C7CEEEEBE",   # keyId 4 - unused
    "A5051CA1B37DCF3AFBCF8CC1EDD9CE02",   # keyId 5 - unused
]
COMMON_KEYS_DEV = [
    "55A3F872BDC80C555A654381139E153B",
    "4434ED14820CA1EBAB82C16E7BEF0C25",
    "F62E3F958E28A21F289EEC71A86629DC",
    "2B49CB6F9998D9ADD94F2EDE7B5DA3E27",
    "750552BFAA1C0407" + "55C8D59A55F9AD1F",
    "AADA4CA8F6E5A977E0A0F9E476CF0D63",
]

DEV_KEYS = 0
if DEV_KEYS == 0:
    KEY_0x2C = 246647523836745093481291640204864831571
    KEY_0x25 = 275024782269591852539264289417494026995
    KEY_0x18 = 174013536497093865167571429864564540276
    KEY_0x1B = 92615092018138441822550407327763030402
else:
    KEY_0x2C = 107678000672959294808833481810464881181
    KEY_0x25 = 172220582634352810158581394293866026779
    KEY_0x18 = 64197259709433409621779576860674900598
    KEY_0x1B = 144279189824071929460111192617823391670
FIXED_ZEROS = 0
FIXED_SYS = 109645209274529458878270608689136408907
SCRAMBLE_CONST = 42503689118608475533858958821215598218
KEYS = [[KEY_0x2C, KEY_0x25, KEY_0x18, KEY_0x1B], [FIXED_ZEROS, FIXED_SYS]]


def common_key(key_id, dev=False):
    table = COMMON_KEYS_DEV if dev else COMMON_KEYS_RETAIL
    if key_id >= len(table):
        raise KeyError("ticket keyId %d is out of range (0-%d)" % (key_id, len(table) - 1))
    return unhexlify(table[key_id])


def _rol(val, r_bits, max_bits=128):
    mask = (1 << max_bits) - 1
    r_bits %= max_bits
    return ((val << r_bits) | (val >> (max_bits - r_bits))) & mask


def scramblekey(key_x, key_y):
    return _rol(((_rol(key_x, 2, 128) ^ key_y) + SCRAMBLE_CONST) & ((1 << 128) - 1), 87, 128)


def to_bytes(n, length, endianess="big"):
    if n < 0:
        n &= (1 << (length * 8)) - 1
    out = n.to_bytes(length, endianess)
    return out if endianess == "big" else out[::-1]


def from_bytes(data, endianess="big"):
    return int.from_bytes(bytes(data), endianess)


def align(x, y):
    return (x + (y - 1)) & ~(y - 1)


# ---------------------------------------------------------------------------
# Header parsing (struct instead of ctypes)
# ---------------------------------------------------------------------------

class NcchHeader(object):
    """Offsets are from the NCCH 3DS format, 0x200 bytes total."""

    _LAYOUT = [
        ("magic", 0x100, "4s"),
        ("ncchSize", 0x104, "<I"),
        ("titleId", 0x108, "8s"),
        ("makerCode", 0x110, "<H"),
        ("formatVersion", 0x112, "B"),
        ("formatVersion2", 0x113, "B"),
        ("seedcheck", 0x114, "4s"),
        ("programId", 0x118, "8s"),
        ("productCode", 0x150, "16s"),
        ("exhdrSize", 0x180, "<I"),
        ("flags", 0x188, "8s"),
        ("logoOffset", 0x198, "<I"),
        ("logoSize", 0x19C, "<I"),
        ("exefsOffset", 0x1A0, "<I"),
        ("exefsSize", 0x1A4, "<I"),
        ("romfsOffset", 0x1B0, "<I"),
        ("romfsSize", 0x1B4, "<I"),
    ]

    def __init__(self, buf):
        if len(buf) < 0x200:
            raise ValueError("NCCH header too small")
        self.signature = buf[0x000:0x010]
        for name, off, fmt in self._LAYOUT:
            setattr(self, name, struct.unpack_from(fmt, buf, off)[0])

    def flag(self, index):
        return self.flags[index]


class NcsdHeader(object):
    def __init__(self, buf):
        if len(buf) < 0x200:
            raise ValueError("NCSD header too small")
        self.signature = buf[0x000:0x100]
        self.magic = buf[0x100:0x104]
        self.titleId = buf[0x108:0x110]
        self.offset_sizeTable = [struct.unpack_from("<II", buf, 0x120 + 8 * i) for i in range(8)]


# ---------------------------------------------------------------------------
# seeddb.bin (9.6.0-24 seed crypto)
# ---------------------------------------------------------------------------

class SeedError(Exception):
    pass


def _load_seeddb(path):
    seeds = {}
    if not path or not os.path.exists(path):
        return seeds
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 16:
        return seeds
    seedcount = struct.unpack_from("<I", blob, 0)[0]
    pos = 16
    for _ in range(seedcount):
        if pos + 32 > len(blob):
            break
        key = blob[pos:pos + 8][::-1].hex()
        seeds[key] = blob[pos + 8:pos + 24]
        pos += 32
    return seeds


def get_new_key_y(key_y, header, title_id_hex, seeddb_path, allow_online=False, log=print):
    seeds = _load_seeddb(seeddb_path)
    if title_id_hex not in seeds and allow_online:
        log("    **********************************")
        log("    Couldn't find seed in seeddb, checking online...")
        log("    **********************************")
        seed = _fetch_online_seed(title_id_hex, log)
        if seed:
            seeds[title_id_hex] = seed

    if title_id_hex in seeds:
        seedcheck = struct.unpack(">I", header.seedcheck)[0]
        digest = sha256(seeds[title_id_hex] + unhexlify(title_id_hex)[::-1]).hexdigest()
        if int(digest[:8], 16) == seedcheck:
            keystr = sha256(to_bytes(key_y, 16, "big") + seeds[title_id_hex]).hexdigest()[:32]
            return from_bytes(unhexlify(keystr), "big")
        raise SeedError("Seed check fail, wrong seed?")
    raise SeedError("No seed for title %s (not in seeddb.bin, and online lookup is disabled)"
                    % title_id_hex)


def _fetch_online_seed(title_id_hex, log):
    import ssl
    from urllib.request import urlopen
    ctx = ssl._create_unverified_context()
    for country in (12, 13, 14, 15, 16, 17, 18):
        url = "https://kagiya-ctr.cdn.nintendo.net/title/0x%s/ext_key?country=%s" % (title_id_hex, country)
        try:
            resp = urlopen(url, context=ctx, timeout=15)
            if resp.getcode() == 200:
                return resp.read()
        except Exception as exc:                      # noqa: BLE001 - best effort
            log("    online lookup failed: %s" % exc)
            return None
    return None


# ---------------------------------------------------------------------------
# Random-access reader for CIA content (AES-CBC, 64-byte aligned)
# ---------------------------------------------------------------------------

class CiaReader(object):
    """Random-access reader over an AES-CBC encrypted CIA content.

    CBC is chained: each read continues from the previous ciphertext block.
    The original kept a live cipher object for this; here the running chain
    block is tracked explicitly so that the stateless AES backends work.
    """

    def __init__(self, fhandle, encrypted, titkey, c_idx, content_off):
        self.fhandle = fhandle
        self.encrypted = encrypted
        self.name = fhandle.name
        self.c_idx = c_idx
        self.content_off = content_off
        self.titkey = titkey
        self._chain = self._initial_iv()

    def _initial_iv(self):
        return to_bytes(self.c_idx, 2, "big") + b"\x00" * 14

    def seek(self, offs):
        if offs == 0:
            self.fhandle.seek(self.content_off)
            self._chain = self._initial_iv()
        else:
            self.fhandle.seek(self.content_off + offs - 16)
            self._chain = self.fhandle.read(16)

    def read(self, nbytes):
        if nbytes == 0:
            return b""
        data = self.fhandle.read(nbytes)
        if self.encrypted and data:
            plain = AES.cbc_decrypt(data, self.titkey, self._chain)
            self._chain = data[-16:]
            return plain
        return data


# ---------------------------------------------------------------------------
# Parsing / decryption
# ---------------------------------------------------------------------------

def get_ncch_aes_counter(header, section_type):
    counter = bytearray(16)
    if header.formatVersion in (0, 2):
        counter[0:8] = header.titleId[::-1]
        counter[8] = section_type
    elif header.formatVersion == 1:
        x = 0
        if section_type == 1:      # exheader
            x = 512
        elif section_type == 2:    # exefs
            x = header.exefsOffset * MEDIA_UNIT_SIZE
        elif section_type == 3:    # romfs
            x = header.romfsOffset * MEDIA_UNIT_SIZE
        counter[0:8] = header.titleId
        for i in range(4):
            counter[12 + i] = (x >> ((3 - i) * 8)) & 0xFF
    return bytes(counter)


def _reverse_hex(raw):
    """Little-endian u32 array -> big-endian hex string (the original's
    reverseCtypeArray + hexlify)."""
    return bytes(reversed(raw)).hex()


class Decryptor(object):
    def __init__(self, outdir, seeddb, allow_online=False, log=print, quiet=False):
        self.outdir = outdir
        self.seeddb = seeddb
        self.allow_online = allow_online
        self._log_raw = log
        self.quiet = quiet

    def log(self, msg=""):
        if not self.quiet:
            self._log_raw(msg)

    # -- top level dispatch -------------------------------------------------

    def run(self, path):
        with open(path, "rb") as fh:
            fh.seek(0x100)
            magic = fh.read(4)
            if magic == b"NCSD":
                self.parse_ncsd(fh)
            elif magic == b"NCCH":
                fh.seek(0, os.SEEK_END)
                self.parse_ncch(fh, fh.tell(), 0, 0, b"", standalone=True, from_ncsd=0)
            elif path.lower().endswith(".cia"):
                fh.seek(0)
                if fh.read(4) == b"  \x00\x00":
                    self.parse_cia(fh)
                else:
                    self.log('    Unrecognised file type: %s' % os.path.basename(path))
            else:
                self.log('    Unrecognised file type: %s' % os.path.basename(path))

    # -- CIA ----------------------------------------------------------------

    def parse_cia(self, fh):
        self.log('Parsing CIA in file "%s":' % os.path.basename(fh.name))
        fh.seek(0)
        (header_size, _type, _version, cachain_size, tik_size,
         tmd_size, _meta_size, content_size) = struct.unpack("<IHHIIIIQ", fh.read(32))
        cachain_off = align(header_size, 64)
        tik_off = align(cachain_off + cachain_size, 64)
        tmd_off = align(tik_off + tik_size, 64)
        content_offs = align(tmd_off + tmd_size, 64)
        # meta_off = align(content_offs + content_size, 64)  # unused, as in the original

        fh.seek(tik_off + 127 + 320)
        enckey = fh.read(16)
        fh.seek(tik_off + 156 + 320)
        tid = fh.read(8)
        if tid.hex()[:5] == "00048":
            self.log("    Unsupported CIA file (TWL title)")
            return
        fh.seek(tik_off + 177 + 320)
        cmnkeyidx = struct.unpack("B", fh.read(1))[0]
        try:
            ckey = common_key(cmnkeyidx, dev=bool(DEV_KEYS))
        except KeyError as exc:
            self.log("    %s" % exc)
            return
        titkey = AES.cbc_decrypt(enckey, ckey, tid + b"\x00" * 8)

        fh.seek(tmd_off + 518)
        content_count = struct.unpack(">H", fh.read(2))[0]
        next_content_offs = 0
        for i in range(content_count):
            fh.seek(tmd_off + 2820 + 48 * i)
            c_id, c_idx, c_type, c_size = struct.unpack(">IHHQ", fh.read(16))
            c_enc = 1 if (c_type & 1) else 0
            fh.seek(content_offs + next_content_offs)
            if c_enc:
                test = AES.cbc_decrypt(fh.read(512), titkey, to_bytes(c_idx, 2, "big") + b"\x00" * 14)
            else:
                test = fh.read(512)
            if test[256:260] != b"NCCH":
                self.log("  Problem parsing CIA content %d, skipping. Sorry about that :/\n" % i)
                # The original forgot to advance the content offset here, which
                # desynchronised every remaining content in the CIA.  Fixed.
                next_content_offs += align(c_size, 64)
                continue
            fh.seek(content_offs + next_content_offs)
            reader = CiaReader(fh, c_enc, titkey, c_idx, content_offs + next_content_offs)
            next_content_offs += align(c_size, 64)
            self.parse_ncch(reader, c_size, 0, c_idx, tid, standalone=False, from_ncsd=0)
        return

    # -- NCSD (CCI / .3ds) --------------------------------------------------

    def parse_ncsd(self, fh):
        self.log('Parsing NCSD in file "%s":' % os.path.basename(fh.name))
        fh.seek(0)
        header = NcsdHeader(fh.read(0x200))
        for i in range(len(header.offset_sizeTable)):
            offset, size = header.offset_sizeTable[i]
            if offset:
                self.parse_ncch(fh, size * MEDIA_UNIT_SIZE, offset * MEDIA_UNIT_SIZE, i,
                                bytes(reversed(header.titleId)), standalone=False, from_ncsd=1)

    # -- NCCH ---------------------------------------------------------------

    def parse_ncch(self, fh, fsize, offs=0, idx=0, title_id=b"", standalone=True, from_ncsd=0):
        tab = "  " if standalone else "    "
        if not standalone and from_ncsd:
            self.log("  Parsing %s NCCH" % NCSD_PARTITIONS[idx])
        elif not standalone:
            self.log("  Parsing NCCH %d" % idx)
        else:
            self.log('Parsing NCCH in file "%s":' % os.path.basename(fh.name))

        fh.seek(offs)
        header = NcchHeader(fh.read(0x200))
        if title_id == b"":
            title_id = bytes(reversed(header.programId))
        ncch_key_y = from_bytes(header.signature[:16], "big")

        self.log(tab + "Product code: " + header.productCode.decode("ascii", "replace").rstrip("\x00"))
        self.log(tab + "KeyY: %032X" % ncch_key_y)
        self.log(tab + "Title ID: %s" % _reverse_hex(header.titleId))
        self.log(tab + "Format version: %d" % header.formatVersion)

        uses_extra_crypto = header.flag(3)
        if uses_extra_crypto:
            self.log(tab + "Uses Extra NCCH crypto, keyslot 0x%X" % {1: 37, 10: 24, 11: 27}[uses_extra_crypto])
        fixed_crypto = 0
        encrypted = 1
        if header.flag(7) & 1:
            fixed_crypto = 2 if header.titleId[3] & 16 else 1
            self.log(tab + "Uses fixed-key crypto")
        if header.flag(7) & 4:
            encrypted = 0
            self.log(tab + "Not Encrypted")
        use_seed_crypto = bool(header.flag(7) & 32)

        key_y = ncch_key_y
        if use_seed_crypto:
            try:
                key_y = get_new_key_y(ncch_key_y, header, title_id.hex(), self.seeddb,
                                      allow_online=self.allow_online, log=self.log)
                self.log(tab + "Uses 9.6 NCCH Seed crypto with KeyY: %032X" % key_y)
            except SeedError as exc:
                self.log(tab + "Seed crypto failed: %s" % exc)
                return
        self.log("")

        suffix = idx if not from_ncsd else NCSD_PARTITIONS[idx]
        base = os.path.join(self.outdir, "tmp.%s.ncch" % suffix)
        with open(base, "wb") as out:
            fh.seek(offs)
            hdr = bytearray(fh.read(0x200))
            # Clear the "extra/fixed crypto" + "not encrypted" flag bits so the
            # rebuilt NCCH advertises itself as decrypted (original behaviour).
            hdr[0x18F] = (hdr[0x18F] & 2) | 4
            out.write(bytes(hdr))

            if header.exhdrSize != 0:
                counter = get_ncch_aes_counter(header, 1)
                self._dump_section(out, fh, 0x200, header.exhdrSize * 2, 1, counter,
                                   uses_extra_crypto, fixed_crypto, encrypted,
                                   [ncch_key_y, key_y], use_seed_crypto, tab)
            if header.exefsSize != 0:
                counter = get_ncch_aes_counter(header, 2)
                self._dump_section(out, fh, header.exefsOffset * MEDIA_UNIT_SIZE,
                                   header.exefsSize * MEDIA_UNIT_SIZE, 2, counter,
                                   uses_extra_crypto, fixed_crypto, encrypted,
                                   [ncch_key_y, key_y], use_seed_crypto, tab)
            if header.romfsSize != 0:
                counter = get_ncch_aes_counter(header, 3)
                self._dump_section(out, fh, header.romfsOffset * MEDIA_UNIT_SIZE,
                                   header.romfsSize * MEDIA_UNIT_SIZE, 3, counter,
                                   uses_extra_crypto, fixed_crypto, encrypted,
                                   [ncch_key_y, key_y], use_seed_crypto, tab)
        self.log("")
        return

    def _dump_section(self, out, fh, offset, size, section_type, ctr, uses_extra_crypto,
                      fixed_crypto, encrypted, key_ys, use_seed_crypto, tab):
        crypto_keys = {0: 0, 1: 1, 10: 2, 11: 3}
        names = {1: "ExHeader", 2: "ExeFS", 3: "RomFS"}
        name = names[section_type]
        self.log(tab + "%s offset:  %08X" % (name, offset))
        self.log(tab + "%s counter: %s" % (name, ctr.hex()))
        self.log(tab + "%s size: %d bytes" % (name, size))

        gap = offset - out.tell()
        if gap > 0:
            out.write(fh.read(gap))
        if not encrypted:
            remaining = size
            while remaining:
                block = fh.read(min(0x400000, remaining))
                if not block:
                    break
                out.write(block)
                remaining -= len(block)
            return

        key_0x2c = to_bytes(scramblekey(KEYS[0][0], key_ys[0]), 16, "big")
        ctr_int = from_bytes(ctr, "big")

        if section_type == 1:      # ExHeader
            key = key_0x2c
            if fixed_crypto:
                key = to_bytes(KEYS[1][fixed_crypto - 1], 16, "big")
            out.write(AES.ctr(fh.read(size), key, ctr))

        elif section_type == 2:    # ExeFS
            key = key_0x2c
            if fixed_crypto:
                key = to_bytes(KEYS[1][fixed_crypto - 1], 16, "big")
            exedata = fh.read(size)
            exetmp = bytearray(AES.ctr(exedata, key, ctr))
            if uses_extra_crypto or use_seed_crypto:
                extra_key = to_bytes(scramblekey(KEYS[0][crypto_keys[uses_extra_crypto]], key_ys[1]),
                                     16, "big")
                exetmp2 = AES.ctr(exedata, extra_key, ctr)
                # icon/banner stay under the primary key; everything else was
                # re-encrypted with the extra crypto.
                for i in range(10):
                    fname, foff, fsize = struct.unpack_from("<8sII", bytes(exetmp), i * 16)
                    foff += 0x200
                    if fname.strip(b"\x00") in (b"icon", b"banner"):
                        continue
                    exetmp[foff:foff + fsize] = exetmp2[foff:foff + fsize]
            out.write(bytes(exetmp))

        elif section_type == 3:    # RomFS
            key = to_bytes(scramblekey(KEYS[0][crypto_keys[uses_extra_crypto]], key_ys[1]), 16, "big")
            if fixed_crypto:
                key = to_bytes(KEYS[1][fixed_crypto - 1], 16, "big")
            remaining = size
            done = 0
            while remaining:
                block = fh.read(min(0x400000, remaining))
                if not block:
                    break
                out.write(AES.ctr(block, key, (ctr_int + done // 16).to_bytes(16, "big")))
                remaining -= len(block)
                done += len(block)
        return


# ---------------------------------------------------------------------------
# Self test (NIST SP 800-38A vectors) -- `python3 decrypt_mac.py --selftest`
# ---------------------------------------------------------------------------

def selftest():
    ok = True
    # F.5.1 CTR-AES128
    key = unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    ctr = unhexlify("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plain = unhexlify("6bc1bee22e409f96e93d7e117393172a")
    expect_ctr = unhexlify("874d6191b620e3261bef6864990db6ce")
    # F.2.1 CBC-AES128
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    expect_cbc_plain = plain
    cipher_txt = unhexlify("7649abac8119b246cee98e9b12e9197d")

    # Pure-python primitives
    a = PurePythonAES(key)
    got = a.encrypt_block(plain)
    ok &= got == unhexlify("3ad77bb40d7a3660a89ecaf32466ef97")
    print("  pure-python AES encrypt : %s" % ("PASS" if got == unhexlify("3ad77bb40d7a3660a89ecaf32466ef97") else "FAIL"))
    got = a.decrypt_block(unhexlify("3ad77bb40d7a3660a89ecaf32466ef97"))
    print("  pure-python AES decrypt : %s" % ("PASS" if got == plain else "FAIL"))
    ok &= got == plain

    got = AES.ctr(plain, key, ctr)
    print("  %-23s: %s" % ("backend=%s CTR" % AES.name, "PASS" if got == expect_ctr else "FAIL"))
    ok &= got == expect_ctr
    got = AES.cbc_decrypt(cipher_txt, key, iv)
    print("  %-23s: %s" % ("backend=%s CBC" % AES.name, "PASS" if got == expect_cbc_plain else "FAIL"))
    ok &= got == expect_cbc_plain

    # scramblekey must be a bijection on 128-bit values
    vals = [0, 1, 0xDEADBEEF, KEY_0x2C, FIXED_SYS, (1 << 128) - 1]
    uniq = {scramblekey(v, KEY_0x2C) for v in vals}
    print("  %-23s: %s" % ("scramblekey injective", "PASS" if len(uniq) == len(vals) else "FAIL"))
    ok &= len(uniq) == len(vals)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="macOS port of decrypt.exe from Batch CIA 3DS Decryptor Redux.")
    p.add_argument("files", nargs="*", help="CIA / CCI / 3DS / NCCH files")
    p.add_argument("--outdir", default=os.path.dirname(os.path.realpath(__file__)),
                   help="where to write tmp.*.ncch (default: script directory)")
    p.add_argument("--seeddb", default=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                    "seeddb.bin"),
                   help="path to seeddb.bin for 9.6.0-24+ seed crypto")
    p.add_argument("--allow-online-keys", action="store_true",
                   help="permit an online title-key lookup when a seed is missing locally")
    p.add_argument("--selftest", action="store_true", help="run AES self tests and exit")
    args = p.parse_args(argv)

    if args.selftest:
        print("AES self test (NIST SP 800-38A)")
        return selftest()
    if not args.files:
        p.error("no input files")

    os.makedirs(args.outdir, exist_ok=True)
    dec = Decryptor(args.outdir, args.seeddb, allow_online=args.allow_online_keys)

    existing = []
    for pattern in args.files:
        existing.extend(glob.glob(pattern.replace("[", "[[]")) or [pattern])
    existing = [f for f in existing if os.path.isfile(f)]
    if not existing:
        print("Input files don't exist")
        return 1

    for path in existing:
        try:
            dec.run(path)
        except (ValueError, KeyError, OSError) as exc:
            print("  Error while processing %s: %s" % (os.path.basename(path), exc))
    print("Done!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
