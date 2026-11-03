"""Optional licensed-IDA integration test on a COPY of the supplied KS database.
idat -A -S"tests/dump/ida-regression.py <report.json> <captured.sys> <fixed.sys>" copy.i64
Run from the repository root. Never pass the original database as copy.i64.
"""
import hashlib
import json
import runpy
import traceback

import ida_auto
import ida_bytes
import ida_hexrays
import ida_nalt
import ida_name
import ida_segment
import idautils
import idc


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def data_hashes():
    return {ea: hashlib.sha256(ida_bytes.get_bytes(ea, ida_segment.getseg(ea).end_ea - ea) or b'').hexdigest()
            for ea in idautils.Segments() if not ida_segment.getseg(ea).perm & ida_segment.SEGPERM_EXEC}


try:
    ida_auto.auto_wait()
    before = data_hashes()
    names = [(ea, name) for ea, name in idautils.Names()
             if ida_segment.getseg(ea) and not ida_segment.getseg(ea).perm & ida_segment.SEGPERM_EXEC]
    base = ida_nalt.get_imagebase()
    source_hash = hashlib.sha256(open(idc.ARGV[2], 'rb').read()).hexdigest()
    scope = runpy.run_path('src/dump/ida/restore-analysis.py')
    fixes = scope['run'](idc.ARGV[2], idc.ARGV[3])
    check(before == data_hashes(), 'Captured non-code section bytes changed')
    check(all(ida_name.get_name(ea) == name for ea, name in names), 'A pre-existing global symbol was lost')
    check(hashlib.sha256(open(idc.ARGV[2], 'rb').read()).hexdigest() == source_hash, 'Original capture changed')
    process = next(ea for ea, name in idautils.Names() if 'Process@CKsFilter' in name)
    check(ida_hexrays.init_hexrays_plugin(), 'Decompiler unavailable')
    pseudocode = str(ida_hexrays.decompile(process))
    check('KeGetCurrentIrql()' in pseudocode, 'Imported call is unresolved')
    check('this->GetStruct(this)' in pseudocode, 'Virtual call is unresolved')
    check('->DeviceExtension' in pseudocode and '->DeviceType' in pseudocode, 'WPP field types are unresolved')
    check('MEMORY[' not in pseudocode, 'Unexpected absolute external call remains')
    second = scope['run'](idc.ARGV[2])
    check(not second['patches'], 'Helper is not idempotent')
    check(before == data_hashes(), 'Second run changed captured data')
    fixes['verification'] = {'globals_preserved': len(names), 'data_hashes_match': True,
                             'idempotent': True, 'process_pseudocode': pseudocode,
                             'input_sha256': source_hash}
    fixes['verification']['live_globals'] = [{ 'name': name, 'rva': ea - base, 'qword': hex(ida_bytes.get_qword(ea)) }
        for ea, name in names if name in ('WPP_GLOBAL_Control', 'WPP_RECORDER_INITIALIZED', 'g_AssertSpinLock', 'g_AssertsOperational')]
    with open(idc.ARGV[1], 'x', encoding='utf-8') as stream:
        json.dump(fixes, stream, indent=2)
    print('KS IDA regression passed: calls, WPP fields, global symbols/bytes, idempotence.')
    idc.qexit(0)
except Exception:
    with open(idc.ARGV[1] + '.error', 'w') as stream:
        stream.write(traceback.format_exc())
    idc.qexit(1)
