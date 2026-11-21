import hashlib
import json
from pathlib import Path

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc

SELECTED_FUNCTIONS = (
    "main",
    "initConnection",
    "getOurIP",
    "toggle_obf",
    "recvLine",
    "processCmd",
    "table_init",
    "watchdog_maintain",
)


def function_record(func):
    calls = {}
    instruction_count = 0
    for head in idautils.Heads(func.start_ea, func.end_ea):
        instruction_count += 1
        if not idc.print_insn_mnem(head).lower().startswith("call"):
            continue
        for target in idautils.CodeRefsFrom(head, False):
            target_func = ida_funcs.get_func(target)
            target_name = idc.get_func_name(target)
            if target_func or target_name:
                calls[f"0x{target:08x}"] = target_name or f"sub_{target:X}"

    callers = {}
    for xref in idautils.XrefsTo(func.start_ea, 0):
        caller = ida_funcs.get_func(xref.frm)
        if caller:
            callers[f"0x{caller.start_ea:08x}"] = idc.get_func_name(caller.start_ea)

    return {
        "address": f"0x{func.start_ea:08x}",
        "end_address": f"0x{func.end_ea:08x}",
        "size": func.end_ea - func.start_ea,
        "instruction_count": instruction_count,
        "calls": [
            {"address": address, "name": name}
            for address, name in sorted(calls.items(), key=lambda item: (item[1], item[0]))
        ],
        "callers": [
            {"address": address, "name": name}
            for address, name in sorted(callers.items(), key=lambda item: (item[1], item[0]))
        ],
    }


def main():
    idaapi.auto_wait()
    input_path = Path(idc.get_input_file_path()).resolve()
    output_dir = input_path.parent.parent / "analysis"
    output_dir.mkdir(exist_ok=True)

    functions = {}
    for name in SELECTED_FUNCTIONS:
        address = idc.get_name_ea_simple(name)
        func = ida_funcs.get_func(address)
        if address == idc.BADADDR or func is None:
            raise RuntimeError(f"Required function not found: {name}")
        functions[name] = function_record(func)

    decompiler_available = bool(ida_hexrays.init_hexrays_plugin())
    pseudocode = []
    if decompiler_available:
        for name in SELECTED_FUNCTIONS:
            address = idc.get_name_ea_simple(name)
            pseudocode.append(f"/* {name} @ 0x{address:08x} */")
            try:
                pseudocode.append(str(ida_hexrays.decompile(address)))
            except ida_hexrays.DecompilationFailure as error:
                pseudocode.append(f"/* Decompilation failed: {error} */")
            pseudocode.append("")

    result = {
        "input": input_path.name,
        "sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "ida_version": idaapi.get_kernel_version(),
        "decompiler_available": decompiler_available,
        "functions": functions,
    }
    (output_dir / "ida-functions.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    if decompiler_available:
        (output_dir / "ida-pseudocode.txt").write_text(
            "\n".join(pseudocode), encoding="utf-8"
        )
    idc.qexit(0)


main()
