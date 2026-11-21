#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_SHA256 = "8cb7b286f4284afccee5f9b9e2ac143fc954c377ef2891474feccb0b223a9537"


def analyze(original, unpacked, symbols_text, strings_text):
    original_raw = original.read_bytes()
    unpacked_raw = unpacked.read_bytes()
    checks = {
        "original_hash_matches": hashlib.sha256(original_raw).hexdigest() == EXPECTED_SHA256,
        "upx_marker_present": b"UPX!" in original_raw,
        "original_size_matches": len(original_raw) == 42336,
        "unpacked_larger": len(unpacked_raw) > len(original_raw),
        "obfuscation_symbol": "toggle_obf" in symbols_text,
        "network_receive_symbol": "recvLine" in symbols_text,
        "main_symbol": " main\n" in symbols_text,
        "persirai_marker": "npxXoudifFeEgGaACScs" in strings_text,
        "http_request_templates": all(
            marker in strings_text
            for marker in ("POST", "HEAD", "%s /%s HTTP/1.1", "Host: %s", "User-Agent: %s")
        ),
        "ddos_command_markers": sum(
            marker in strings_text
            for marker in ("CUDP", "KICK", "CTCP", "CXMAS", "SLOW", "HEXED", "XMAS", "CVSE")
        ) >= 4,
        "host_network_discovery": all(
            marker in strings_text
            for marker in ("/proc/net/route", "8.8.8.8", "/usr/bin/python", "sshd", "/usr/sbin/dropbear")
        ),
        "browser_user_agents": strings_text.count("Mozilla/") >= 20,
    }
    matched = all(checks.values())
    return {
        "sample": str(original),
        "sha256": hashlib.sha256(original_raw).hexdigest(),
        "original_bytes": len(original_raw),
        "unpacked_bytes": len(unpacked_raw),
        "checks": checks,
        "family_assessment": "persirai_family" if matched else "not_persirai_family",
    }


def main():
    parser = argparse.ArgumentParser(description="Verify the native Persirai-family static indicator set")
    parser.add_argument("original", type=Path)
    parser.add_argument("unpacked", type=Path)
    parser.add_argument("symbols", type=Path)
    parser.add_argument("strings", type=Path)
    args = parser.parse_args()
    result = analyze(
        args.original,
        args.unpacked,
        args.symbols.read_text(),
        args.strings.read_text(),
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["family_assessment"] == "persirai_family" else 0)


if __name__ == "__main__":
    main()
