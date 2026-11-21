#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

EXPECTED_SHA256 = "5037b0ca9125f26e34f785c62641998a6e14d70b0440f8492d0e8fab5be4b0ba"
EXPECTED_FUNCTIONS = {
    "main": ("0x0804e58e", 1795),
    "initConnection": ("0x0804e1d3", 403),
    "getOurIP": ("0x0804e366", 547),
    "toggle_obf": ("0x0804f866", 240),
    "recvLine": ("0x08049389", 449),
    "processCmd": ("0x0804bdee", 9189),
    "table_init": ("0x0804f504", 652),
    "watchdog_maintain": ("0x08048388", 297),
}
REQUIRED_CALLS = {
    "main": {"initConnection", "recvLine", "processCmd", "sleep", "prctl"},
    "initConnection": {"socket", "connectTimeout"},
    "getOurIP": {"socket", "connect", "getsockname", "ioctl"},
    "recvLine": {"select", "recv"},
    "processCmd": {
        "httphex",
        "udpfl00d",
        "sendTCP",
        "sendSTD",
        "SendSTDHEX",
        "slow",
        "Hexed",
        "rtcp",
        "vseattack",
        "listFork",
        "kill",
    },
    "table_init": {"add_entry"},
    "watchdog_maintain": {"fork", "open", "ioctl", "sleep"},
}


def verify(export):
    checks = {
        "input_name": export.get("input") == "backdoor-unpacked.elf",
        "unpacked_hash": export.get("sha256") == EXPECTED_SHA256,
        "ida_9_5": export.get("ida_version") == "9.5",
        "decompiler_available": export.get("decompiler_available") is True,
    }
    functions = export.get("functions", {})
    for name, (address, size) in EXPECTED_FUNCTIONS.items():
        record = functions.get(name, {})
        checks[f"{name}_boundary"] = (
            record.get("address") == address and record.get("size") == size
        )
        calls = {call.get("name") for call in record.get("calls", [])}
        checks[f"{name}_calls"] = REQUIRED_CALLS.get(name, set()).issubset(calls)

    toggle_callers = {
        caller.get("name") for caller in functions.get("toggle_obf", {}).get("callers", [])
    }
    checks["toggle_obf_call_context"] = toggle_callers == {
        "table_lock_val",
        "table_unlock_val",
    }
    return {
        "source": "analysis/ida-functions.json",
        "checks": checks,
        "status": "passed" if all(checks.values()) else "failed",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate the native ELF IDAPython export")
    parser.add_argument("export", type=Path)
    args = parser.parse_args()
    result = verify(json.loads(args.export.read_text(encoding="utf-8")))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
