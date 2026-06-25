<div align="center">

# Vigil

[![Version](https://img.shields.io/badge/version-1.0.8-39ff14.svg?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-00e5ff.svg?style=flat-square)](LICENSE)
[![Language: C++17](https://img.shields.io/badge/language-C%2B%2B17-00599C.svg?style=flat-square&logo=cplusplus&logoColor=white)](https://en.cppreference.com/)
[![Interface: CLI](https://img.shields.io/badge/interface-CLI-555.svg?style=flat-square)](#usage)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-FCC624.svg?style=flat-square&logo=linux&logoColor=black)](https://www.kernel.org/)
[![Signatures: ML-DSA / FIPS 204](https://img.shields.io/badge/signatures-ML--DSA%20(FIPS%20204)-8a2be2.svg?style=flat-square)](https://csrc.nist.gov/pubs/fips/204/final)
[![Hash: SHA3-512](https://img.shields.io/badge/hash-SHA3--512-blueviolet.svg?style=flat-square)](https://csrc.nist.gov/pubs/fips/202/final)
[![KDF: Argon2id](https://img.shields.io/badge/KDF-Argon2id-orange.svg?style=flat-square)](https://www.rfc-editor.org/rfc/rfc9106.html)
[![Build: make](https://img.shields.io/badge/build-make-427819.svg?style=flat-square&logo=gnu)](https://www.gnu.org/software/make/)
[![Post-Quantum](https://img.shields.io/badge/security-Post--Quantum-teal.svg?style=flat-square)](https://openquantumsafe.org/)

**A post-quantum file-integrity monitor for Linux — know exactly what changed, and prove the record wasn't touched.**

</div>

---

**Vigil** walks a directory tree, records a SHA3-512 fingerprint of every file
(plus its type, mode, owner, size and mtime), and seals the whole baseline with
a **post-quantum ML-DSA signature** (NIST FIPS 204). Later, `vigil check`
re-scans the tree and tells you precisely what was **added, removed or
modified** — and refuses to trust a baseline that has itself been tampered with.
`vigil watch` does the same continuously and incrementally via `inotify`.

It is the headless, post-quantum answer to AIDE / Tripwire. The secret signing
key is encrypted at rest with **Argon2id + AES-256-GCM**, so an attacker who
steals `vigil.key` still cannot forge a baseline.

## Contents

- [Why it exists](#why-it-exists)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Installing globally](#installing-globally)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Exit codes](#exit-codes)
- [Live monitoring in depth](#live-monitoring-in-depth)
- [JSON output](#json-output)
- [Running under systemd](#running-under-systemd)
- [How a baseline is sealed](#how-a-baseline-is-sealed)
- [Security model](#security-model)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Why it exists

A signature scanner (rkhunter, chkrootkit) only finds *known* badness. Vigil
answers a different, more fundamental question:

> *"Has anything on this disk changed since the last moment I trusted it?"*

Because the baseline is signed, an attacker who modifies your files **and**
rewrites the baseline to match still fails verification — they would need your
offline, passphrase-protected key. Each baseline can also chain to the Merkle
root of the previous one (`--prev OLD.vgl`), giving a tamper-evident history of
system state over time. The prior baseline's signature is verified before it is
linked, so the chain is self-checking — Vigil refuses to chain onto a forged
predecessor.

**Key properties**

- **Post-quantum signatures** — ML-DSA-44/65/87 (FIPS 204) via [liboqs](https://openquantumsafe.org/).
- **Monitoring needs only the public key** — keep `vigil.key` offline; `check`/`watch` never touch it.
- **Incremental live mode** — `watch` re-hashes only the paths `inotify` reports, so it scales to a whole system.
- **Exclude patterns** — prune volatile trees (`/proc`, caches, logs); the filter is stored in (and signed with) the baseline.
- **No noisy dependencies for hashing** — SHA3-512 is a self-contained C core; only signatures need liboqs.
- **Deterministic & auditable** — records sorted by path, little-endian serialization, reproducible Merkle root.

## Prerequisites

Vigil needs a **C++17 compiler**, **GNU make**, and three libraries located via
`pkg-config`:

| Dependency | Used for | Typical package |
|---|---|---|
| [**liboqs**](https://openquantumsafe.org/) ≥ 0.9 | ML-DSA signatures (FIPS 204) | usually built from source |
| **OpenSSL** ≥ 3.0 | AES-256-GCM + CSPRNG | `libssl-dev` |
| **libargon2** | Argon2id key derivation | `libargon2-dev` |

`inotify` (used by `vigil watch`) is part of the Linux kernel — nothing to install.

### Debian / Ubuntu

```sh
sudo apt update
sudo apt install -y build-essential pkg-config git cmake ninja-build libssl-dev libargon2-dev
```

### Fedora / RHEL

```sh
sudo dnf install -y gcc-c++ make pkgconf-pkg-config git cmake ninja-build openssl-devel libargon2-devel
```

### Arch

```sh
sudo pacman -S --needed base-devel pkgconf git cmake ninja openssl argon2
# liboqs is also available from the AUR as `liboqs`
```

### Building liboqs from source

Most distributions do not ship `liboqs` yet, so build it once (it installs into
`/usr/local` by default):

```sh
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON
ninja -C liboqs/build
sudo ninja -C liboqs/build install
sudo ldconfig
```

Verify all three dependencies are now visible to `pkg-config`:

```sh
pkg-config --exists liboqs openssl libargon2 && echo "all dependencies found"
```

> If you installed liboqs into a **custom prefix**, tell `pkg-config` where to
> find it when building Vigil, e.g.
> `make PKG_CONFIG_PATH=/opt/liboqs/lib/pkgconfig`. Vigil bakes liboqs's library
> directory into the binary as an `rpath`, so you do **not** need to set
> `LD_LIBRARY_PATH` at run time.

## Building

```sh
git clone https://github.com/effjy/vigil
cd vigil
make            # produces ./vigil
```

Optional: build and run the end-to-end test suite (creates throwaway keys and
trees in a temp dir, exercises drift, tamper, watch, chaining, JSON, …):

```sh
make check
```

Other targets: `make clean` removes build artifacts.

## Installing globally

```sh
sudo make install            # installs to /usr/local/bin/vigil (+ man page)
```

Then `vigil` is on your `PATH`:

```sh
vigil version
man vigil
```

To uninstall:

```sh
sudo make uninstall
```

### Install location & packaging

| Variable | Default | Purpose |
|---|---|---|
| `PREFIX` | `/usr/local` | install root (`$PREFIX/bin`, `$PREFIX/share/man`) |
| `DESTDIR` | *(empty)* | staging root for distro packaging |
| `UNITDIR` | `/etc/systemd/system` | where `install-systemd` puts unit files |

```sh
# install into your home without root
make install PREFIX="$HOME/.local"

# stage into a package root
make install DESTDIR=/tmp/pkg PREFIX=/usr
```

You can also override the toolchain (`CXX`, `CC`), `CXXFLAGS`/`CFLAGS`, and
`PKG_CONFIG`.

## Quick start

```sh
# 1. one-time: create a passphrase-protected keypair
vigil keygen -k vigil.key -p vigil.pub

# 2. record a trusted baseline of a tree (reads the secret key once)
vigil baseline /etc -k vigil.key -o etc.vgl

# 3. later — by hand or from cron — check for drift (public key only)
vigil check /etc -p vigil.pub -d etc.vgl

# …or watch the tree live and stream events as they happen
vigil watch /etc -p vigil.pub -d etc.vgl
```

A typical drift report:

```
~ passwd (mode)
~ sshd_config (content,size,mtime)
+ cron.d/.hidden
- issue.net
⚠ drift detected — +1 added, -1 removed, ~2 modified
```

`+` added · `-` removed · `~` modified, with the changed attributes in
parentheses (`content`, `mode`, `uid`, `gid`, `size`, `mtime`, `type`).

## Command reference

Global: `vigil version` prints the version; `vigil help` prints usage. Output is
colorized when stdout is a TTY; set `NO_COLOR=1` to disable.

### `vigil keygen` — create a keypair

```sh
vigil keygen [-a ALG] [-k vigil.key] [-p vigil.pub]
```

Generates an ML-DSA keypair. The **secret key is encrypted at rest** with
AES-256-GCM under a key derived from your passphrase via Argon2id; the public
key is written in the clear.

| Option | Default | Meaning |
|---|---|---|
| `-a`, `--alg ALG` | `ml-dsa-65` | algorithm: `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87` |
| `-k`, `--key FILE` | `vigil.key` | output secret-key file (mode `0600`) |
| `-p`, `--pub FILE` | `vigil.pub` | output public-key file (mode `0644`) |

You are prompted for a passphrase (twice). Set `VIGIL_PASSPHRASE` to skip the
prompt. **Keep `vigil.key` and its passphrase offline** — they are the only
things that can sign a baseline.

### `vigil baseline` — record a signed baseline

```sh
vigil baseline <path> [-k vigil.key] [-o baseline.vgl] \
               [--prev OLD.vgl [--prev-pub OLD.pub]] \
               [-x GLOB ...] [--exclude-from FILE] \
               [-j N] [--one-file-system] [--follow-symlinks]
```

Scans `<path>`, hashes every regular file (in parallel), captures metadata, and
writes a signed `.vgl` baseline. Requires the secret key (and passphrase).

| Option | Default | Meaning |
|---|---|---|
| `-k`, `--key FILE` | `vigil.key` | secret key to sign with |
| `-o`, `--out FILE` | `baseline.vgl` | output baseline file |
| `--prev OLD.vgl` | *(none)* | chain to a prior baseline's Merkle root (its signature is verified first) |
| `--prev-pub OLD.pub` | *(current key)* | public key that signed `--prev`, if it was a now-rotated key |
| `-x`, `--exclude GLOB` | *(none)* | skip matching paths (repeatable); see [Excluding paths](#excluding-paths) |
| `--exclude-from FILE` | *(none)* | read exclude patterns from a file (one per line, `#` comments ok) |
| `-j`, `--jobs N` | CPU count | number of hashing threads |
| `--one-file-system` | off | do not descend into other mount points |
| `--follow-symlinks` | off | follow directory symlinks while walking |

Symlinks are recorded by hashing their **target path** (never followed);
directories and special files carry metadata only.

#### Excluding paths

Real systems have volatile trees you don't want to baseline — `/proc`, `/sys`,
`/dev`, `/run`, caches and logs. Exclude them at baseline time:

```sh
vigil baseline / -k vigil.key -o root.vgl \
  -x proc -x sys -x dev -x run -x tmp \
  -x 'var/cache' -x 'var/log' -x '*.log' \
  --exclude-from /etc/vigil/excludes.txt
```

Pattern rules (`fnmatch` globbing):

- A pattern **without a `/`** matches any single path component, anywhere —
  `*.log` matches every `.log` file, `cache` matches any directory or file named
  `cache` at any depth.
- A pattern **with a `/`** matches the full **relative** path or any ancestor
  prefix — `var/cache` excludes that directory and everything beneath it.
- Matched **directories are pruned** (never descended into), so excluding
  `/proc` costs nothing.

The exclude set is **stored in the signed baseline**, so `check` and `watch`
apply exactly the same filter automatically — you never repeat the patterns, and
the filter itself is covered by the signature.

### `vigil check` — compare a tree to a baseline

```sh
vigil check [<path>] [-p vigil.pub] [-d baseline.vgl] [-j N] [--quiet] [--json]
```

Verifies the baseline's signature, then re-scans and reports differences. If
`<path>` is omitted, the baseline's recorded root is used. **Only the public key
is needed.**

| Option | Default | Meaning |
|---|---|---|
| `-p`, `--pub FILE` | `vigil.pub` | public key to verify the baseline |
| `-d`, `--db FILE` | `baseline.vgl` | baseline to check against |
| `-j`, `--jobs N` | CPU count | hashing threads |
| `--quiet` | off | print only the summary line, not each path |
| `--json` | off | emit one machine-readable JSON object (see below) |

See [Exit codes](#exit-codes). If the signature does not verify, Vigil refuses
to report drift and exits `4`.

### `vigil watch` — live monitoring

```sh
vigil watch [<path>] [-p vigil.pub] [-d baseline.vgl] [-j N] \
            [--json] [--debounce MS] [--resweep S]
```

Verifies the baseline once, then watches the tree with `inotify` and streams
drift events until interrupted (Ctrl-C / `SIGTERM`). Incremental: only changed
paths are re-hashed. See [Live monitoring in depth](#live-monitoring-in-depth).

| Option | Default | Meaning |
|---|---|---|
| `-p`, `--pub FILE` | `vigil.pub` | public key to verify the baseline |
| `-d`, `--db FILE` | `baseline.vgl` | baseline to watch against |
| `--json` | off | emit newline-delimited JSON events (JSONL) |
| `--debounce MS` | `800` | settle time after the first event before evaluating |
| `--resweep S` | `0` (off) | also do a full re-scan every `S` seconds as a safety net |

### `vigil verify` — check a signature only

```sh
vigil verify [-p vigil.pub] [-d baseline.vgl]
```

Verifies the baseline's ML-DSA signature and internal Merkle consistency without
touching the filesystem tree. Exits `0` if valid, `4` if not.

### `vigil show` — inspect a baseline

```sh
vigil show [-d baseline.vgl] [--list]
```

Prints metadata: root, creation time, algorithm, object count, Merkle root, and
the previous-root chain link. With `--list`, prints every recorded object
(`type`, octal mode, path).

## Exit codes

These apply to `check` (and `watch` on its initial verification); other commands
use `0` for success and `1` for errors.

| Code | Meaning |
|---|---|
| `0` | Clean — the tree matches the signed baseline. |
| `2` | **Drift** — one or more objects were added, removed, or modified. |
| `4` | **Bad signature** — the baseline was tampered with, or the wrong/another key was supplied. |
| `1` | Usage or runtime error. |

Distinct codes let cron jobs and alerting react differently to "something
changed" versus "the baseline itself can't be trusted."

## Live monitoring in depth

`vigil watch` adds an `inotify` watch to every directory in the tree and to new
subdirectories as they appear. When events fire, it re-stats — and for regular
files re-hashes — **only the exact paths reported**, comparing each against the
in-memory baseline. Reacting to one changed file therefore costs the same
whether the baseline covers ten files or ten million, which makes it practical
to watch an entire system.

A burst of writes is **debounced** (`--debounce`, default 800 ms) into a single
evaluation. Both new drift and **resolved** changes (a file restored to its
baseline state, or an added file removed) are reported:

```
[2026-06-25T13:19:04-0400] ~ sshd_config (content,size,mtime)
[2026-06-25T13:19:04-0400] - passwd
[2026-06-25T13:19:04-0400] + backdoor.sh
[2026-06-25T13:19:31-0400] = sshd_config (resolved)
```

Memory stays proportional to the *amount of drift*, not the size of the tree:
Vigil keeps the baseline (already loaded) plus the set of currently-drifted
paths. `--resweep S` schedules an occasional full re-scan to reconcile anything
`inotify` may have dropped under extreme churn.

## JSON output

`--json` makes `check` and `watch` emit structured output suitable for a SIEM.

**`check --json`** prints a single object:

```json
{"baseline":"etc.vgl","root":"/etc","algorithm":"ML-DSA-65",
 "signature_valid":true,"clean":false,
 "changes":[{"kind":"modified","path":"sshd_config","detail":"content,size,mtime"}],
 "summary":{"added":0,"removed":0,"modified":1}}
```

**`watch --json`** prints one object per line (JSONL), one per change:

```json
{"ts":"2026-06-25T13:19:04-0400","event":"drift","kind":"modified","path":"sshd_config","detail":"content,size,mtime"}
{"ts":"2026-06-25T13:19:04-0400","event":"drift","kind":"added","path":"backdoor.sh"}
{"ts":"2026-06-25T13:19:31-0400","event":"resolved","path":"sshd_config"}
```

Exit codes are unchanged in JSON mode, so scripts can branch on both the JSON
and the status.

## Running under systemd

Templated units cover periodic checks and live watching, keyed on an instance
name that maps to a config file at `/etc/vigil/<name>.conf`:

```sh
sudo make install install-systemd
sudo install -Dm600 systemd/example.conf /etc/vigil/etc.conf   # then edit paths

sudo systemctl enable --now vigil-check@etc.timer     # hourly integrity check
sudo systemctl enable --now vigil-watch@etc.service   # continuous live monitor

journalctl -u vigil-watch@etc -f                      # JSONL events in the journal
```

An example `/etc/vigil/etc.conf`:

```sh
VIGIL_PATH=/etc
VIGIL_PUB=/etc/vigil/vigil.pub
VIGIL_DB=/etc/vigil/etc.vgl
```

The units run read-only and locked down (`ProtectSystem=strict`,
`ReadOnlyPaths=/`, `NoNewPrivileges`, no network) and reference **only the
public key**, so no secret ever lives in the service environment. Generate the
keypair and baseline by hand first, then keep `vigil.key` offline:

```sh
vigil keygen   -k /etc/vigil/vigil.key -p /etc/vigil/vigil.pub
vigil baseline /etc -k /etc/vigil/vigil.key -o /etc/vigil/etc.vgl
```

Remove the units with `sudo make uninstall-systemd`.

## How a baseline is sealed

```
            ┌──────── signed body ────────┐
records ──▶ │ per-file SHA3-512 + metadata │ ──▶ Merkle root ─┐
            └──────────────────────────────┘                  │
                                                               ▼
                              digest = SHA3-512(body) ──▶ ML-DSA signature
```

Each object becomes a record (path, type, mode, uid, gid, size, mtime, and a
SHA3-512 content/symlink hash). Records are sorted by path and serialized
little-endian; a Merkle tree over them yields a stable root. The signature is
ML-DSA over the SHA3-512 digest of the whole body, so signing cost is
independent of tree size.

Trust is anchored in **your** copy of `vigil.pub`, never the public key embedded
in the file. Verification recomputes the body digest, re-derives the Merkle
root, and checks the ML-DSA signature against the public key you supply.

## Security model

- **What a baseline proves:** that the recorded set of files and metadata is
  exactly what was signed by the holder of the secret key. Any later change to a
  watched file, or to the baseline itself, is detected.
- **Offline key:** `baseline` and `keygen` need the secret key; `check`,
  `watch`, `verify`, and `show` do not. Keep `vigil.key` (and its passphrase)
  off the monitored host — e.g. on removable media — so an attacker who roots
  the box cannot forge a passing baseline.
- **Key at rest:** the secret key is encrypted with AES-256-GCM; the key is
  derived from your passphrase with Argon2id (t=3, 64 MiB). A stolen `vigil.key`
  is useless without the passphrase.
- **Tamper-evident history:** chain baselines with `--prev`; each link's
  signature is verified before it is trusted.
- **mtime is tracked on purpose:** a changed `mtime` is reported (including for
  directories whose contents changed). This catches timestomping; if you find it
  noisy for a given tree, baseline and check more narrowly scoped paths.

## Testing

```sh
make check
```

The suite builds a throwaway tree and keypair in a temp directory and exercises
keygen permissions, baseline/verify, drift detection (add/remove/modify),
baseline tampering, wrong-key and wrong-algorithm rejection, `--name=value`
parsing, exclude patterns (`-x` / `--exclude-from`, applied across `baseline`,
`check`, and `watch`), JSON output, live `watch` (including incremental
recursion into new subdirectories and `resolved` events), resweep
de-duplication, and verified `--prev` chaining. It also builds cleanly under
AddressSanitizer/UBSan.

## Troubleshooting

- **`Package liboqs was not found in the pkg-config search path`** — liboqs
  isn't installed where `pkg-config` looks. Build it (see
  [Prerequisites](#prerequisites)) and run `sudo ldconfig`, or pass
  `make PKG_CONFIG_PATH=/your/prefix/lib/pkgconfig`.
- **`error while loading shared libraries: liboqs.so`** — the runtime linker
  can't find liboqs. Run `sudo ldconfig`, or rebuild so the `rpath` is baked in.
- **`unknown signature algorithm` / `not enabled in liboqs`** — your liboqs
  build doesn't enable ML-DSA. Build a recent liboqs (≥ 0.9) with default
  options.
- **`a passphrase is required but stdin is not a terminal`** — you ran
  `keygen`/`baseline` non-interactively. Export `VIGIL_PASSPHRASE`.
- **`watch` misses changes under heavy churn** — raise `inotify` limits
  (`fs.inotify.max_user_watches`) and/or add `--resweep`.

## License

MIT — © Jean-Francois Lachance-Caumartin. See [LICENSE](LICENSE).
