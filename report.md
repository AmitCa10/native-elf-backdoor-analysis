# Persirai-family native ELF: static format and behavior analysis

**Author:** [Amit Carmon](https://github.com/AmitCa10)

## Summary

This report analyzes a 42,336-byte 32-bit x86 ELF sample from Intezer's public real-world example set. Its SHA-256 is:

```text
8cb7b286f4284afccee5f9b9e2ac143fc954c377ef2891474feccb0b223a9537
```

The artifact is a UPX-packed, statically linked executable with no section header table. After local UPX decompression, it becomes a 104,380-byte non-stripped ELF with normal sections and symbols.

Static indicators support a **Persirai-family** assessment:

- the unique `npxXoudifFeEgGaACScs` marker;
- DDoS command names and request-building templates;
- a large browser user-agent list;
- host/network discovery paths and SSH-related names;
- network receive, connection, and obfuscation symbols; and
- direct disassembly of the connection and initialization routines.

No backdoor was executed, connected to infrastructure, or detonated.

## Tooling and safety

IDA 9.5 batch analysis was used on the research machine alongside:

- `file` for format identification;
- UPX for local decompression only;
- `objdump` for sections, symbols, and i386 disassembly;
- `nm` for symbol inspection; and
- `strings` for readable indicators.

The original and unpacked samples, the IDA-generated `.asm` and database files, and the full decompiler output are excluded from publication. The IDAPython exporter and structured function/call-graph output are included for reproducibility.

## Format analysis

| Property | Original | Unpacked |
| --- | --- | --- |
| Format | 32-bit little-endian x86 ELF | 32-bit little-endian x86 ELF |
| Linking | Static | Static |
| Size | 42,336 bytes | 104,380 bytes |
| Sections | No section header table | 15 named sections |
| Symbols | No symbol table | Symbol and string tables present |
| UPX | `UPX!` marker present | Decompressed successfully |

The unpacked file includes `.init`, `.text`, `.fini`, `.rodata`, `.data`, `.bss`, `.comment`, `.symtab`, and `.strtab`. The entry point reported by `objdump` is `0x08048168`.

UPX reported a 40.56% output-to-input ratio and recovered the file despite warnings about `b_info` metadata. The unpacked SHA-256 is:

```text
5037b0ca9125f26e34f785c62641998a6e14d70b0440f8492d0e8fab5be4b0ba
```

## Behavior indicators

### Obfuscation

The symbol table contains `toggle_obf` at `0x0804f866`. Its disassembly applies an XOR operation byte by byte to entries in a table. This is direct evidence of a small obfuscation routine rather than an assumption based only on unreadable strings.

Related symbols include `resolv_skip_name`, `add_entry`, `table_init`, `table_lock_val`, `table_unlock_val`, and `table_retrieve_val`, which are consistent with a table-driven configuration or command structure.

### Network initialization and connection

Disassembly provides the following call structure:

- `main` at `0x0804e58e` initializes process state and calls `initConnection` at `0x804e1d3`.
- `initConnection` invokes `socket` at `0x8051dd4`, then calls `connectTimeout` at `0x804954a` with a formatted destination and a 30-second timeout.
- `getOurIP` at `0x804e366` separately invokes `socket` at `0x8051dd4` and `connect` at `0x8051c14`, then uses `getsockname`, `ioctl`, and local file operations.
- `main` later invokes `recvLine` at `0x8049389`.

Other network-related symbols include `inet_pton4`, `inet_ntop4`, `gethostbyname`, `gethostbyname_r`, `connectTimeout`, `socket_connect`, `sendSTD`, `recv`, `send`, `recvfrom`, and `sendto`. These symbols are useful corroboration for network behavior but are not treated as proof of a particular C2 endpoint.

## IDA function-level analysis

`tools/export_ida_analysis.py` uses IDAPython to export function boundaries, instruction counts, direct call targets, inbound cross-references, and Hex-Rays pseudocode. The structured results are published in `analysis/ida-functions.json`; the full pseudocode remains a local analysis artifact.

| Function | Size | Function-level observation |
| --- | ---: | --- |
| `main` | 1,795 bytes | Process renaming, watchdog setup, connection retry, receive loop, and command parsing |
| `initConnection` | 403 bytes | Destination formatting, socket creation, and a 30-second `connectTimeout` call |
| `getOurIP` | 547 bytes | Local-address, route-table, and interface discovery |
| `recvLine` | 449 bytes | `select`-based waiting and byte-wise `recv` until newline or failure |
| `processCmd` | 9,189 bytes | Command dispatch to network-attack and process-control routines |
| `toggle_obf` | 240 bytes | Four-key-byte XOR over an indexed table entry |

The decompiler shows that `main` checks for `/usr/bin/python`, selects either `sshd` or `/usr/sbin/dropbear` as a displayed process name, rewrites `argv[0]`, and calls `prctl` with option 15 (`PR_SET_NAME`). This is static evidence of process-name masquerading. It does not show that the sample gained root or successfully renamed a live process.

The connection loop calls `initConnection` repeatedly and sleeps for five seconds after a failure. `initConnection` formats a destination from four indexed values, creates a socket, and passes a 30-second timeout to `connectTimeout`. After connection, `main` receives lines into a 4,096-byte buffer, trims and tokenizes command text, uppercases the command token, and calls `processCmd`.

`processCmd` has 2,165 disassembled instructions. Its direct callees include `httphex`, `udpfl00d`, `sendTCP`, `sendSTD`, `SendSTDHEX`, `slow`, `Hexed`, `rtcp`, and `vseattack`, as well as `listFork`, `kill`, and `_exit`. The HTTP branch compares the command token with `HTTP` and calls `httphex`; other branches compare against the previously listed command markers. These call relationships substantiate the command-dispatch interpretation beyond the presence of strings.

The `toggle_obf` pseudocode shows four XOR operations per input byte, using each byte of the 32-bit `table_key` in turn. Its only inbound function cross-references are `table_lock_val` and `table_unlock_val`. This establishes the transformation and its call context, but the report does not claim to recover the original plaintext configuration.

Hex-Rays output is a decompiler approximation, not original source code. Each reported finding above was checked against the disassembly and the structured direct-call export.

## HTTP and DDoS indicators

The unpacked strings include request-building templates:

```text
POST
HEAD
%s /%s HTTP/1.1
Host: %s
User-Agent: %s
Connection: close
GET /cdn-cgi/l/chk_captcha HTTP/1.1
```

They also include the command names `CUDP`, `KICK`, `CTCP`, `CXMAS`, `SLOW`, `HEXED`, `XMAS`, and `CVSE`, which are consistent with multiple DDoS modes or commands.

The file contains more than 20 `Mozilla/` user-agent strings covering Internet Explorer, Firefox, Chrome, Safari, Opera, desktop, and mobile platforms. This supports request spoofing or rotation, not an assumption that the sample is a normal browser.

## Host and SSH discovery

Readable indicators include:

- `/proc/net/route`;
- `8.8.8.8`;
- `/usr/bin/python`;
- `sshd`; and
- `/usr/sbin/dropbear`.

These support local network and service discovery. The report does not infer that those programs were executed from these strings alone.

## Family marker

The unique string `npxXoudifFeEgGaACScs` appears in the sample and is independently documented as a Persirai-family indicator by Trend Micro and subsequent research. The combined format, commands, network routines, and marker make the family assessment stronger than any single string.

## Detection and validation

`tools/verify_analysis.py` requires all of these checks before assigning `persirai_family`:

- exact original SHA-256 and byte count;
- UPX marker and larger unpacked file;
- `toggle_obf`, `recvLine`, and `main` symbols;
- the Persirai marker;
- HTTP request templates;
- at least four DDoS command markers;
- host/network discovery strings; and
- at least 20 `Mozilla/` user-agent strings.

`analysis/validation.json` records:

| Input | Result |
| --- | --- |
| Original and unpacked Persirai-family sample | All checks passed |
| `/bin/ls` and its symbols/strings | `not_persirai_family` |

The `/bin/ls` control demonstrates that the assessment depends on the combined indicator set rather than generic ELF, compression, or network-library content.

IDA 9.5 batch analysis confirmed the connection routines, command dispatcher, process-renaming logic, and XOR-based `toggle_obf` routine. `tools/verify_ida_export.py` passes 21 checks covering the unpacked hash, function boundaries, direct calls, and caller contexts. Exact IDA output references and artifact hashes are recorded in `analysis/ida-validation.md`, with structured results in `analysis/ida-functions.json` and validator output in `analysis/ida-export-validation.json`.

## Limitations

- No dynamic execution, C2 contact, credential access, or DDoS behavior was performed.
- This is a static analysis of one public sample, not a claim of discovering the Persirai family or a new variant.
- Plaintext C2 details are not established, and encrypted configuration was not decoded.
- Some function roles are inferred from names and call structure, so the report distinguishes them from independently confirmed behavior.
- The sample's public provenance is Intezer's example repository; this report's contribution is reproducible unpacking, disassembly, IDAPython call-graph validation, indicator checks, and a benign-binary control.

## Reproduce

From this directory:

```bash
upx -d evidence/backdoor.elf -o evidence/backdoor-unpacked.elf
idat -B -S"$PWD/tools/export_ida_analysis.py" evidence/backdoor-unpacked.elf
objdump -h evidence/backdoor-unpacked.elf > analysis/unpacked-sections.txt
objdump -f evidence/backdoor-unpacked.elf > analysis/unpacked-program-headers.txt
objdump -t evidence/backdoor-unpacked.elf > analysis/unpacked-symbols.txt
strings -a evidence/backdoor-unpacked.elf > analysis/unpacked-strings.txt
python3 tools/verify_analysis.py \
  evidence/backdoor.elf \
  evidence/backdoor-unpacked.elf \
  analysis/unpacked-symbols.txt \
  analysis/unpacked-strings.txt
python3 tools/verify_ida_export.py analysis/ida-functions.json
```

For disassembly review, `analysis/main-disassembly.txt`, `analysis/init-connection-disassembly.txt`, `analysis/get-our-ip-disassembly.txt`, `analysis/recv-line-disassembly.txt`, `analysis/process-cmd-disassembly.txt`, and `analysis/toggle-obf-disassembly.txt` contain the exact `objdump` output.

## References

- [Intezer real-world sample repository](https://github.com/intezer/ELF-Malware-Analysis-101)
- [Exact sample source](https://github.com/intezer/ELF-Malware-Analysis-101/blob/master/Part-2-Initial-Analysis/Real-life-examples/Example/8cb7b286f4284afccee5f9b9e2ac143fc954c377ef2891474feccb0b223a9537.sample)
- [Intezer: initial ELF analysis methodology](https://intezer.com/blog/elf-malware-analysis-101-initial-analysis)
- [Trend Micro: Persirai botnet](https://www.trendmicro.com/en/research/17/e/persirai-new-internet-things-iot-botnet-targets-ip-cameras.html)
- [Malpedia: Persirai family and the shared marker](https://malpedia.caad.fkie.fraunhofer.de/details/elf.persirai)
