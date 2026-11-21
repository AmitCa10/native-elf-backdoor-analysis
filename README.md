# Native Persirai-family ELF static analysis

Static, non-executing analysis of a real 32-bit x86 UPX-packed ELF sample from Intezer's real-world example set.

The study uses IDA 9.5 batch analysis and IDAPython alongside `file`, UPX, `objdump`, `nm`, and `strings`. It verifies family indicators, native format changes after unpacking, process-name masquerading, connection retries, command dispatch, network functions, HTTP templates, DDoS command markers, and a benign `/bin/ls` control.

Raw and unpacked malware are excluded through `.gitignore`.

## Reproduce

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

The scanner exits with status 1 when the complete Persirai-family indicator set matches. See `report.md`, `analysis/findings.json`, and `analysis/validation.json` for the evidence and `/bin/ls` negative control.
