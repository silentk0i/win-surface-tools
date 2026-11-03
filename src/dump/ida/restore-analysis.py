"""Restore analysis of Windows-patched kernel calls in an IDA database.

Run after loading the dump and its matching PDB: File -> Script file.
Only the analysis database is patched. The raw memory capture is never changed.
Optional batch arguments: --input captured.sys --output fixed.sys --report fixes.json
No original/on-disk driver is used, and no external memory is dereferenced.
"""
import argparse
import json
import os
import re
import struct

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_loader
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import idautils
import idc


def _run(input_path=None, output_path=None, report_path=None):
    ida_auto.auto_wait()
    base = ida_nalt.get_imagebase()
    source = input_path or ida_nalt.get_input_file_path()
    for destination in (output_path, report_path):
        if destination and (os.path.exists(destination) or (source and os.path.abspath(destination) == os.path.abspath(source))):
            raise ValueError('Output/report paths must be unused and separate from the capture.')
    manifest_path = source + '.json' if source else ''
    manifest = {}
    if manifest_path and os.path.isfile(manifest_path):
        with open(manifest_path, encoding='utf-8') as stream:
            manifest = json.load(stream)
        if manifest.get('format') != 'WINOBJ_MEMORY_DUMP':
            raise ValueError('Unexpected dump manifest format')
    evidence = {item['iat_rva']: item for item in manifest.get('imports', [])}
    original_base = int(manifest.get('output_base', hex(base)), 16)
    rebase_delta = base - original_base
    imports = {}
    for i in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(i)
        def collect(ea, name, ordinal):
            imports[ea] = (module, name or ('#' + str(ordinal)))
            return True
        ida_nalt.enum_import_names(i, collect)

    result = {'version': 1, 'image_base': hex(base), 'patches': [], 'types': [], 'warnings': []}
    guard_pattern = re.compile(r'^_+guard_dispatch_icall(?:_nop)?(?:\$thunk\$.*)?$')
    guard_entries = {ea for ea, name in idautils.Names() if guard_pattern.fullmatch(name)}

    # PE load-config identifies the dispatch pointer even without a PDB.
    # Do not infer a guard target from an arbitrary external call or a global value.
    try:
        nt = base + ida_bytes.get_dword(base + 0x3c)
        config_rva = ida_bytes.get_dword(nt + 24 + 112 + 10 * 8)
        config = base + config_rva
        if config_rva and ida_bytes.get_dword(config) >= 0x80:
            slot = ida_bytes.get_qword(config + 0x78)
            if ida_segment.getseg(slot):
                dispatcher = ida_bytes.get_qword(slot)
                if ida_segment.getseg(dispatcher):
                    guard_entries.add(dispatcher)
    except Exception:
        result['warnings'].append('Could not read the load-config guard dispatch pointer.')

    def executable(ea, size=1):
        segment = ida_segment.getseg(ea)
        return bool(segment and segment.perm & ida_segment.SEGPERM_EXEC and ea + size <= segment.end_ea)

    def relative_target(ea, data):
        return (ea + 5 + struct.unpack_from('<i', data, 1)[0]) & 0xffffffffffffffff

    guard_targets = set(guard_entries)
    for start in list(guard_entries):
        current = start
        for _ in range(8):
            data = ida_bytes.get_bytes(current, 5) if executable(current, 5) else None
            if not data or data[0] != 0xe9:
                break
            target = relative_target(current, data)
            if target in guard_targets:
                break
            guard_targets.add(target)
            current = target

    def patch(ea, replacement, kind, detail):
        before = ida_bytes.get_bytes(ea, len(replacement))
        if before is None or before == replacement:
            return
        offset = ida_loader.get_fileregion_offset(ea)
        result['patches'].append({'rva': ea - base, 'file_offset': offset, 'before': before.hex(),
                                  'after': replacement.hex(), 'kind': kind, 'detail': detail})
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(replacement))
        ida_bytes.patch_bytes(ea, replacement)
        position = ea
        while position < ea + len(replacement):
            length = ida_ua.create_insn(position)
            if not length:
                break
            position += length
        previous = ida_bytes.get_cmt(ea, False) or ''
        comment = 'WinObjDump analysis fix: ' + detail + '; captured bytes: ' + before.hex()
        ida_bytes.set_cmt(ea, previous + ('\n' if previous else '') + comment, False)

    # Work from decoded instruction boundaries, not a byte-pattern scan of executable data.
    heads = set()
    for function in idautils.Functions():
        heads.update(idautils.FuncItems(function))
    for ea in sorted(heads):
        if not executable(ea) or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        instruction = ida_ua.insn_t()
        length = ida_ua.decode_insn(instruction, ea)
        if length == 7 and executable(ea, 12):
            data = ida_bytes.get_bytes(ea, 12)
            # Windows retpoline/import optimization: mov r10,[IAT]; call/jmp rel32.
            # The retained IAT load provides authoritative import-slot identity.
            if data[:3] == b'\x4c\x8b\x15' and data[7] in (0xe8, 0xe9):
                following = ida_ua.insn_t()
                slot = ea + 7 + struct.unpack_from('<i', data, 3)[0]
                if slot not in imports or ida_ua.decode_insn(following, ea + 7) != 5:
                    continue
                target = relative_target(ea + 7, data[7:])
                recorded = evidence.get(slot - base)
                if recorded and int(recorded['live_address'], 16) != ((target - rebase_delta) & 0xffffffffffffffff):
                    result['warnings'].append('Import target mismatch at ' + hex(ea) + '; retained for review.')
                    continue
                operation = b'\x15' if data[7] == 0xe8 else b'\x25'
                replacement = b'\x48\xff' + operation + struct.pack('<i', slot - (ea + 7)) + b'\x0f\x1f\x44\x00\x00'
                module, name = imports[slot]
                patch(ea, replacement, 'import', module + '!' + name + '; live target ' + hex(target - rebase_delta))
                continue
        if length == 5:
            data = ida_bytes.get_bytes(ea, 5)
            if data[0] in (0xe8, 0xe9) and relative_target(ea, data) in guard_targets:
                # Guard dispatch consumes the target in RAX. Keep the original argument
                # registers and replace only the analysis-time dispatch machinery.
                replacement = (b'\xff\xd0' if data[0] == 0xe8 else b'\xff\xe0') + b'\x90\x90\x90'
                patch(ea, replacement, 'guard-dispatch', 'indirect target in RAX; live dispatcher ' + hex(relative_target(ea, data)))

    # Use only the prefix consumed by generated WPP, not a complete DEVICE_OBJECT.
    # The latter would falsely type adjacent live globals as part of that object.
    wpp = ida_name.get_name_ea(ida_idaapi.BADADDR, 'WPP_GLOBAL_Control')
    if wpp != ida_idaapi.BADADDR:
        value = ida_bytes.get_qword(wpp)
        declaration = 'struct WINOBJ_WPP_CONTROL_VIEW { unsigned char reserved[64]; void *DeviceExtension; unsigned long DeviceType; };'
        ida_typeinf.idc_parse_types(declaration, ida_typeinf.PT_SIL)
        view = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(view, None, 'WINOBJ_WPP_CONTROL_VIEW *WPP_GLOBAL_Control;', ida_typeinf.PT_SIL) and ida_nalt.set_tinfo(wpp, view):
            result['types'].append({'name': 'WPP_GLOBAL_Control', 'type': 'WINOBJ_WPP_CONTROL_VIEW *', 'live_value': hex(value)})
        else:
            result['warnings'].append('Could not apply the WPP control-block prefix view.')

    for ea, (_, name) in imports.items():
        recorded = evidence.get(ea - base)
        if recorded:
            ida_bytes.set_cmt(ea, 'Captured live IAT address: ' + recorded['live_address'] + ' (' + name + ')', True)
    ida_auto.auto_wait()
    if ida_hexrays.init_hexrays_plugin():
        # Also invalidate callers whose prototypes/data types changed.
        ida_hexrays.clear_cached_cfuncs()
    if not guard_entries:
        result['warnings'].append('No guard dispatcher symbols found; load the matching PDB and run again to resolve CFG calls.')

    if output_path:
        if not source or os.path.abspath(source) == os.path.abspath(output_path):
            raise ValueError('Choose a separate output path; the captured input must be preserved.')
        with open(source, 'rb') as stream:
            image = bytearray(stream.read())
        for item in result['patches']:
            offset = item['file_offset']
            old, new = bytes.fromhex(item['before']), bytes.fromhex(item['after'])
            if offset < 0 or image[offset:offset + len(old)] != old:
                raise ValueError('Input does not match database bytes; refusing to export an inconsistent PE.')
            image[offset:offset + len(new)] = new
        with open(output_path, 'xb') as stream:
            stream.write(image)
    if report_path:
        with open(report_path, 'x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
    print('WinObjDump: %d import fixes, %d guard-dispatch fixes; live globals preserved.' % (
        sum(p['kind'] == 'import' for p in result['patches']),
        sum(p['kind'] == 'guard-dispatch' for p in result['patches'])))
    for warning in result['warnings']:
        print('WinObjDump: ' + warning)
    return result


def run(input_path=None, output_path=None, report_path=None):
    # Recovered import prototypes should improve calls without retyping runtime
    # pointers' pointees and swallowing adjacent, already named global variables.
    old_analysis = ida_ida.inf_get_af()
    ida_ida.inf_set_af(old_analysis & ~(ida_ida.AF_REGARG | ida_ida.AF_STKARG))
    try:
        return _run(input_path, output_path, report_path)
    finally:
        ida_ida.inf_set_af(old_analysis)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input')
    parser.add_argument('--output')
    parser.add_argument('--report')
    args = parser.parse_args(idc.ARGV[1:])
    run(args.input, args.output, args.report)
