# One Must Fall: Battlegrounds — Static Recompilation

Static recompilation of **One Must Fall: Battlegrounds** (Diversions
Entertainment, 2003) — the 3D sequel to *One Must Fall 2097* — from its
shipping Win32 binaries to native C.

Built on the [pcrecomp](https://github.com/sp00nznet/pcrecomp) toolchain.

## Project Status: **P0 complete, P1 not started**

Reconnaissance is done and the answer is unusually good. Nothing has been
lifted yet.

### Why this target, and not OMF 2097

OMF 2097 (1994) is already served by [openomf](https://github.com/omf2097/openomf),
a clean-room reimplementation that plays the whole game. Recompiling it would
produce a worse version of something that already exists. **Battlegrounds has
never been reimplemented, reverse-engineered or source-released**, the servers
are long gone, and it does not run cleanly on a modern machine. That is the
one worth the work.

---

## What P0 found

The disc is `Setup/data1.hdr` + `data1.cab` + a 604 MB `data2.cab`, InstallShield
**version 7**. Extracting it needed a toolchain fix (see below). What came out:

| Module | `.text` | Exports | Role |
|--------|--------:|--------:|------|
| `Core.ModuleDLL` | 2,433,409 | 8,320 | The engine. Everything hangs off this. |
| `Direct3D.ModuleDLL` | 1,019,196 | 134 | D3D9 renderer |
| `OMF.ModuleDLL` | 477,879 | 586 | The game itself — robots, arenas, rules |
| `Session.ModuleDLL` | 147,000 | 267 | Match/session state |
| `Creature.ModuleDLL` | 208,824 | 606 | Actor/animation layer |
| `Particles.ModuleDLL` | 110,088 | 338 | Effects |
| `AudioPlayer.ModuleDLL` | 54,488 | 64 | Sound |
| `GameSpy.ModuleDLL` | 37,192 | 21 | Matchmaking (dead service) |
| `Input2.ModuleDLL` | 20,593 | 24 | DirectInput8 |
| `OMFBG.exe` | 53,575 | 14 | Launcher — **SafeDisc-wrapped** |
| **Total** | **4.56 MB** | **10,374** | |

`Data/*.DEObjects` — 88 archives, one per arena, robot, pilot, cinematic and
music track. `DE` is Diversions Entertainment; the format is undocumented and
is the other half of this project.

### Finding 1: the protection covers 1% of the code

`OMFBG.exe` is the only protected binary. It carries SafeDisc's `stxt774` and
`stxt371` sections, its entry point is inside `stxt371`, and its `.text`
entropy is 7.80 — encrypted.

**Every other module is clean.** Entropy 5.2–6.5 across the board, no wrapper
sections, no packed entry points. That is 4.51 MB of the 4.56 MB total sitting
in the open, including the entire engine and the entire game.

The launcher is a 53 KB shell that imports `CORE.MODULEDLL` and
`OMF.MODULEDLL` and calls into them. So the SafeDisc work here is bounded:
recover 53 KB with `tools/drm/safedisc_dump.py`, or skip it entirely and write
a replacement launcher against the two DLL interfaces, which are fully named.

### Finding 2: 10,374 exported, fully mangled C++ symbols

Every single export in every module is an MSVC-mangled C++ name. Not one
ordinal-only export anywhere:

```
?AddData@DE_CChecksumMD5@@QAE...
?ObjAddDescendantsIfAbsent@DE_CObject@@...
?AddDeclDataElements@@YGJPAU_...
```

`Core.ModuleDLL` alone publishes **8,320 named functions** with their class,
their parameter types and their calling convention, all demangleable with
`tools/cpp/msvc_mangler.py`.

This is better ground truth than a linker map. Operation Neptune ships a real
linker map and that is currently the calibration target for
`disasm/score_recovery.py` — it gives names, starts and sizes for one 1991
Borland binary. This gives names *and full type signatures* for 8,320
functions across a 2003 C++ engine, and the class hierarchy falls out of the
names for free before a single instruction is disassembled.

For comparison: Black & White needed the whole of `tools/cpp/` built from
scratch to recover 569 types by hand. Here the type names are in the file.

### Finding 3: every module has a large appended overlay

| Module | Overlay |
|--------|--------:|
| `OMFBG.exe` | 1,126,047 |
| `Direct3D.ModuleDLL` | 603,576 |
| `OMF.ModuleDLL` | 611,819 |
| `Creature.ModuleDLL` | 329,952 |
| `Core.ModuleDLL` | 2,179,580 |

Not yet identified. Most likely a `.DEObjects` blob glued to each module, which
would mean the archive format has to be read before anything renders.

---

## What this shook out of the toolbox

Three fixes went upstream into `pcrecomp` before P0 could finish.

### 1. `assets/isextract.py` could not read InstallShield 7

The extractor was written for the InstallShield v5/v6 discs in Soldier of
Fortune and had one file-descriptor layout. v6 and newer use a completely
different one, and pointing the old parser at this disc walked off the end of
a 20 KB header looking for an offset 33 MB in:

```
struct.error: unpack_from requires a buffer of at least 33563980 bytes
```

v5 reaches each descriptor through an indirection table. **v6+ does not** — it
is a flat array of 0x57-byte records at `file_table_offset2`, with 64-bit
sizes and the fields in a different order:

```
+0x00 u16 flags        +0x02 u64 expanded_size   +0x0a u64 compressed_size
+0x12 u64 data_offset  +0x1a md5[16]             +0x3a u32 name_offset
+0x3e u16 directory_index                        +0x55 u16 volume
```

The md5 offset is the part worth writing down. `+0x1c` looks right — it leaves
a tidy two-byte gap after the offset field — and it extracts files that are
*exactly the right size* with *plausible* content. The only thing that catches
it is the checksum, which came out shifted two bytes and zero-padded:

```
got      3f421e2edc35f6adadd1083996a1c346
expected     1e2edc35f6adadd1083996a1c3460000
```

It is `+0x1a`. All 11 engine binaries now extract with every MD5 verifying.
That check is the reason the bug lasted minutes instead of surfacing later as
a mystery crash in lifted code.

v6+ files can also be byte-scrambled (`FILE_OBFUSCATED`), which none are on
this disc; `deobfuscate()` is wired into the read path against the flag rather
than left for the next project to discover.

### 2. `pe/catalog.py` was hiding the whole game

`catalog.py` picked its targets by extension — `dll`, `exe`, `ocx`, `sys`. This
engine ships its modules as **`.ModuleDLL`**, so the first catalog run on the
extracted install reported *two* binaries: `dbghelp.dll` and `OMFBG.exe`. The
9.5 MB engine core, the renderer and the game were all invisible, and nothing
in the output suggested anything was missing.

It now sniffs for `MZ` and ignores the extension. Plugin engines name their
modules whatever they like — `.ModuleDLL`, `.m8`, `.flt`, `.asi` — and an
extension whitelist fails silently on exactly the half of the install that
matters.

### 3. `pe/analyze_sections.py` called four clean modules protected

The packer scan looks for four-byte markers anywhere in the file. On
multi-megabyte binaries that is noise, and here it was noise with a specific
cause: `Core`, `Creature`, `Direct3D` and `Session` were all reported as
SecuROM on the strength of an `AddD` match, and every one of those matches is
inside a mangled C++ export name —

```
?AddData@DE_CChecksumMD5@@QAE...        ?AddDeclDataElements@@YGJPAU_...
?ObjAddDescendantsIfAbsent@DE_CObject@@  ?ObjAddDescendants@DE_CObject@@
```

A four-byte signature is a hint to go looking, never a verdict. Section names,
entry-point location and entropy are load-bearing; signature hits are now
printed separately and labelled as noise when nothing corroborates them.
Without that split, the triage answer for this project would have been "5 of
10 modules are protected" instead of "1 of 10 is, and it is the smallest one".

---

## Where it goes next (P1)

1. **Demangle the export tables first.** 10,374 names through
   `tools/cpp/msvc_mangler.py` gives the class hierarchy, the vtable shapes and
   ~8,300 confirmed function starts in `Core` before any disassembly. Feed that
   to `disasm/score_recovery.py` as the reference catalog — this is the
   best-instrumented target in the collection and it should be the new
   calibration binary for C++ recovery, the way Operation Neptune is for
   Borland C.
2. **Disassemble `OMF.ModuleDLL` (478 KB) before `Core` (2.4 MB).** It is the
   game, it is the smallest interesting module, and its imports name exactly
   which parts of `Core` and `Session` it needs.
3. **Identify the overlays.** Nothing renders until `.DEObjects` is readable.
4. **Defer the launcher.** The SafeDisc dump is real work for 53 KB of shell
   code whose entire job is `LoadLibrary` + a few calls into named exports.
   A replacement launcher is cheaper and is needed anyway.

`GameSpy.ModuleDLL` talks to a service that shut down in 2013. Whatever
replaces it is a design decision, not a recompilation one.

---

## Layout

```
omfbg/
  original/     the disc: .bin/.cue, and the .iso converted from it
  disc/         the mounted disc tree (Setup/, Demoshield/, SafeDisc files)
  game/Engine/  the 11 extracted binaries
  analysis/     P0 output
  docs/
```

Nothing under `original/`, `disc/` or `game/` is redistributed. Bring your own
disc.

## Credits

One Must Fall: Battlegrounds © 2003 Diversions Entertainment. This project
neither contains nor distributes any part of it.
