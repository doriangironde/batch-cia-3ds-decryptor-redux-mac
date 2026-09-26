# Third-party components

This repository contains **no third-party binaries**. They are downloaded by
`./setup-macos.sh`, which is the only supported way to install them.

| Component | Version | Author | Source | License |
|---|---|---|---|---|
| `ctrtool` | v1.2.1 | 3DSGuy / JakCron | [3DSGuy/Project_CTR](https://github.com/3DSGuy/Project_CTR) | see upstream |
| `makerom` | v0.18.4 | 3DSGuy / applestash / JakCron | [3DSGuy/Project_CTR](https://github.com/3DSGuy/Project_CTR) | MIT |
| `seeddb.bin` | — | ihaveamac, via the Redux release | [xxmichibxx/Batch-CIA-3DS-Decryptor-Redux](https://github.com/xxmichibxx/Batch-CIA-3DS-Decryptor-Redux) | see upstream |

## Derived work

`bin/decrypt_mac.py` is a Python 3 port of `decrypt.exe`, a PyInstaller-packed
Python 2.7 script by **davidmorom**, obtained by extracting the copy bundled
with [Batch CIA 3DS Decryptor Redux](https://github.com/xxmichibxx/Batch-CIA-3DS-Decryptor-Redux)
by **xxmichibxx** (itself a rewrite of matiffeder's original batch decryptor).

The port keeps the original's crypto and on-disk behaviour. The differences —
three bug fixes, a Python 3 rewrite, and an optional online key lookup that is
off by default — are itemised in `README.md` under "Differences from the
Windows version".

## Licensing

This repository has **no license file**, which means the usual copyright rules
apply: no permission is granted to copy, modify or redistribute it.

That is deliberate. The upstream projects this port is derived from and bundles
do not carry an explicit license, so granting one here is not this repository's
call to make. The original authors are credited above and in `README.md`; if you
want to use or redistribute this, please ask them.

Note that `makerom` is MIT-licensed; the other components are not.
