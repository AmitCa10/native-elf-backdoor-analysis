# IDA 9.5 batch-analysis validation

IDA 9.5 was run in autonomous batch mode on `evidence/backdoor-unpacked.elf`. The backdoor itself was not executed.

## Reproducible export

Run from the repository root:

```bash
idat -B -S"$PWD/tools/export_ida_analysis.py" evidence/backdoor-unpacked.elf
python3 tools/verify_ida_export.py analysis/ida-functions.json
```

The IDAPython exporter records function boundaries, instruction counts, direct call targets, inbound cross-references, and Hex-Rays pseudocode for eight selected functions. `analysis/ida-functions.json` is publishable structured output. `analysis/ida-pseudocode.txt`, the complete disassembly database, and the IDA database components are local-only.

The exporter uses `idc.qexit(0)` and is intended for batch execution. It does not run the input program.

Generated local database artifacts from the original batch run:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `backdoor-unpacked.elf.asm` | 1,096,662 | `c01503de1dd2ad1e53c204b93d10c2fd355d1dae00d0f3ffd595e8362936aa7d` |
| `backdoor-unpacked.elf.i64` | 1,247,211 | `a32e3f5da22f5a3a7937cef899d86f51382ded0105f0610f182068958780742c` |

The current artifact hashes are recorded in `evidence/manifest.json` because reopening the database can change IDA database files without changing the analyzed program.

## Function boundaries and call structure

| Function | Address | Size | Direct calls relevant to the report |
| --- | ---: | ---: | --- |
| `main` | `0x0804e58e` | 1,795 | `prctl`, `watchdog_maintain`, `initConnection`, `sleep`, `recvLine`, `processCmd` |
| `initConnection` | `0x0804e1d3` | 403 | `socket`, `connectTimeout`, `strchr`, `atol` |
| `getOurIP` | `0x0804e366` | 547 | `socket`, `connect`, `getsockname`, `open`, `fdgets`, `ioctl` |
| `recvLine` | `0x08049389` | 449 | `select`, `recv` |
| `processCmd` | `0x0804bdee` | 9,189 | `httphex`, `udpfl00d`, `sendTCP`, `sendSTD`, `slow`, `Hexed`, `vseattack`, `listFork`, `kill` |
| `toggle_obf` | `0x0804f866` | 240 | None; called by `table_lock_val` and `table_unlock_val` |
| `table_init` | `0x0804f504` | 652 | `add_entry` |
| `watchdog_maintain` | `0x08048388` | 297 | `fork`, `open`, `ioctl`, `sleep`, table lock/unlock routines |

`main` is called by the ELF entry point `start`. `initConnection`, `getOurIP`, `recvLine`, `processCmd`, `table_init`, and `watchdog_maintain` all have inbound cross-references from `main` in the export.

## Additional decompiler findings

- `main` rewrites `argv[0]`, selects an `sshd` or `/usr/sbin/dropbear` display name, and invokes `prctl` with option 15. This supports process-name masquerading, not a claim of successful execution or privilege escalation.
- Failed `initConnection` calls are followed by a five-second sleep and another attempt. A successful connection reaches the receive and command-parsing loop.
- `recvLine` uses `select`, receives one byte at a time, stops on newline, and returns `-1` when `recv` fails.
- `processCmd` compares command tokens and dispatches to named network-attack routines. Its size and direct-call list corroborate the DDoS command interpretation independently of string counting.
- `toggle_obf` applies all four bytes of `table_key` with XOR to each table-entry byte. The report does not claim that this transformation is cryptographically equivalent to a conventional four-byte repeating-key implementation or that plaintext configuration was recovered.

Hex-Rays pseudocode is an approximation and may recover types or expressions imperfectly. Findings were checked against disassembly; the machine-readable export records direct calls rather than relying only on decompiler text.

## Validation boundary

`tools/verify_ida_export.py` checks the unpacked sample hash, IDA version, decompiler availability, all eight function boundaries, required direct calls, and the two `toggle_obf` caller contexts. Its output is stored in `analysis/ida-export-validation.json`.

These checks validate static analysis consistency. They do not establish live C2 activity, dynamic process behavior, or the complete functionality of every called routine.
