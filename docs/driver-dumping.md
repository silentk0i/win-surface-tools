# Loaded driver image dumps

`win-obj-dump.exe` and `win-obj-dump-driver.sys` are separate x64 binaries in this
solution. The client requests a snapshot of a loaded kernel image, writes the raw
memory image, and reconstructs a PE file for IDA. Neither component opens the
original `.sys` file to obtain image bytes or import/export metadata.

```powershell
.\win-obj-dump.exe list
.\win-obj-dump.exe dump PEAuth.sys --out PEAuth.memory.sys
.\win-obj-dump.exe dump '\Device\PEAuth' --out PEAuth.device.sys
.\win-obj-dump.exe dump example.sys --out example.preferred.sys --base preferred
```

Module names are exact, case-insensitive loaded basenames, including their
extension. Use `list` to find them. A device object is not itself a PE image:
device mode opens the named device with `FILE_READ_ATTRIBUTES` and selects the
driver at the **top of that device stack**, as returned by
[`IoGetDeviceObjectPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdeviceobjectpointer).
The selected module path/base is printed before capture. For a particular lower
filter or bus driver, select its loaded module name explicitly. A device whose
stack cannot be opened or whose driver has no listed image produces an error;
the tool does not guess a matching disk filename. Opening a device can run its
create/close handlers; prefer module mode when that is undesirable.

## Build

Use Visual Studio with v145 C++, the Windows SDK, WDK 10.0.26100.0, and the
`WindowsKernelModeDriver10.0` toolset:

```bat
msbuild win-obj-enum.slnx /m /p:Configuration=Release /p:Platform=x64
```

Outputs are in `build\bin\x64\Release`. Debug is also supported. The existing
enumerator retains its Win32 builds; the two dump projects are x64 only and are
excluded from the solution's x86 build. Build `win-obj-enum.vcxproj` directly if
only the original enumerator and SDK are needed.

Runtime support starts at Windows 10 version 2004 (the driver uses `ExAllocatePool2`).
Device resolution obtains the referenced stack driver's loaded path with
`IoQueryFullDriverPath`, then matches its unique basename against the loaded-module
list; duplicate basenames are rejected.

`build-support/wdk-tasks.props` handles an installation mismatch where the VS 18
WDK toolset is present but the WDK supplies only its VS 17 task assembly. The
fallback is conditional and does not modify installed toolchain files.

The default build produces an **unsigned** `.sys`. Signing and kernel loading are
separate deployment steps. Use a properly signed driver accepted by the target
machine's policy; development signing belongs on a configured test machine/VM.
See Microsoft's [driver signing documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing).
The project does not install certificates, change boot policy, or auto-load a driver.

## Load and run

After signing the driver for the target environment, use an elevated terminal:

```powershell
sc.exe create WinObjDump type= kernel start= demand binPath= "C:\absolute\path\win-obj-dump-driver.sys"
sc.exe start WinObjDump
.\win-obj-dump.exe dump example.sys --out example.memory.sys
sc.exe stop WinObjDump
sc.exe delete WinObjDump
```

These are manual deployment commands, not actions performed by the build. The
client enables `SeDebugPrivilege` for the operation and restores its prior state.
The driver's device DACL permits SYSTEM and administrators; each IOCTL also checks
the effective caller's `SeDebugPrivilege`. A duplicated device handle alone does
not bypass that check. No arbitrary-address read/write, physical-memory mapping,
process-memory access, or kernel-write IOCTL is exposed.

## Output and IDA

For `--out example.memory.sys`, the tool writes:

| File | Contents |
| --- | --- |
| `example.memory.sys` | Reconstructed PE32+ analysis file; open this normally in IDA. |
| `example.memory.sys.memory.bin` | Unmodified memory-layout capture: file offset equals RVA. Missing bytes are zero-filled. |
| `example.memory.sys.json` | Loaded base, capture interval (UTC FILETIME), missing byte ranges and NTSTATUS, reconstruction details, import names and original live IAT addresses. |
| `example.memory.sys.ida.py` | Self-contained IDAPython helper for analyzing runtime-patched import and CFG calls. |

Directories must already exist. All four destination paths must be unused;
existing evidence is never overwritten. By default the name is the resolved
module basename followed by `.dump.sys`. The raw capture is saved before PE
reconstruction. If reconstruction cannot complete, raw memory and a manifest
with the reason remain available; no misleading repaired PE is produced.

The default `--base loaded` sets the PE's `ImageBase` to the captured load address.
Already-relocated code/data pointers therefore match their addresses in IDA.
Section RVAs, entry-point RVA, exception tables, and original IAT RVAs remain
unchanged; raw section offsets/sizes and debug raw pointers are rebuilt for a disk
PE layout. Live BSS contents are included as initialized data.

`--base preferred` reverses `DIR64` and `HIGHLOW` base relocations using the loaded
minus preferred-base delta, then records the preferred image base. `ABSOLUTE`
padding is ignored. Reversal requires a complete relocation directory and readable
relocation targets when the delta is nonzero. If those bytes were discarded, use
loaded-base output. It is not possible to reconstruct absent relocation entries
reliably from arbitrary machine code. Runtime-overwritten pointer fields also
cannot always be restored to their original on-disk meaning.

Imports use the original in-memory lookup table where available, including ordinal
imports. Missing lookup entries are recovered by matching live IAT addresses to
the named dependency's **in-memory exports**, including forwarded exports. Loaded
dependencies are captured on demand through the same driver. A new `.wodimp`
section holds descriptors, lookup thunks, and names; original IAT slots receive
their reconstructed lookup values. Thus IDA can identify imports while code keeps
referencing the original IAT locations. The raw file and JSON retain original IAT
addresses, including pointers that may differ from the named import due to hooks.
An intact lookup table preserves declared names; that alone is not verification
that live IAT targets are unmodified. Export aliases may resolve to an equivalent
name rather than the original spelling.

### Runtime-patched calls in IDA

After opening the PE and loading its **matching PDB**, run the accompanying
`.ida.py` through IDA's **File -> Script file**. The helper is also available at
`src/dump/ida/restore-analysis.py` for older dumps. This is a required analysis
step for images whose calls were patched by Windows' retpoline/import optimization
or CFG machinery; rebuilding the PE import directory alone does not undo those
instruction changes.

The helper uses IDA's decoded instruction boundaries and actual import slots to
recognize `mov r10, [IAT]; call/jmp rel32` sequences, then replaces them in the
analysis database with equivalent IAT-indirect calls/jumps. When the manifest is
available it also checks the recorded live target, leaving mismatches for review.
Guard dispatch calls are recognized using matching guard symbols/thunks and the
PE load-config dispatch pointer. Those analysis-time calls become `call rax` or
`jmp rax`, allowing Hex-Rays to recover virtual method calls. Arbitrary external
calls are not assumed to be guard dispatchers. Unsupported instruction patterns,
missing symbols, or lost metadata can leave other external calls unresolved.

Each patch gets a comment recording its original bytes/target. The helper does
not patch the input PE or the raw capture. It preserves captured non-code bytes,
retains global symbols, and supplies a small conventional WPP control-block type
view for readable `DeviceExtension`/`DeviceType` fields. It temporarily disables
IDA argument-type propagation while repairing calls to avoid retyping adjacent
live globals as parts of unrelated structures. It is safe to run again on the
same repaired database; already-normalized instructions are left alone.

Optional IDA batch script arguments `--input capture.sys --output fixed.sys
--report fixes.json` export the instruction changes into a **separate analysis
PE** and a patch ledger. Export requires input bytes to match the database's
pre-patch bytes. The database still supplies types/PDB information, which are
not encoded in a PE; keep the repaired IDB for the best decompiler output.
Neither analysis output is a reloadable driver. No runtime memory is modified.

Names such as `qword_...` indicate IDA naming/type information, not whether the
stored value was captured. Named globals can contain live values too. Inspect
the pointer's data item or raw bytes to see its current value. IAT slots are the
intentional exception: the analysis PE contains lookup thunks there, with original
live addresses retained in the JSON and added as IDA comments. Following pointers
outside the captured image remains outside this feature's scope.

Disk-only certificates, bound imports, and COFF symbol offsets are cleared. The
file is an **analysis artifact**, not a signed or reloadable copy of the driver.
No import execution or kernel mutation is performed during reconstruction.

## Capture limits and incomplete results

- Supported images: AMD64 PE32+, conventional PE sections, at most 128 MiB.
- The source is the loaded virtual image. Windows may page in pageable sections
  while reading them. Discarded/unmapped pages cannot be recovered and are recorded
  explicitly; zeros in missing ranges must not be interpreted as original bytes.
- [`MmCopyMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory)
  reads bounded image ranges page by page, without directly dereferencing possibly
  invalid image addresses. Module identity is checked before and after capture.
- Capture is not atomic. Modules can unload/reload, and writable pages can change
  during the operation. The before/after check detects ordinary disappearance or
  address/size changes, not every unload/reload at the same address. The tool does
  not acquire undocumented loader locks or promise a crash-dump-consistent view.
- Missing PE headers or import descriptors, unresolved imports, unsupported
  relocation types, overlapping sections, malformed tables, and delay imports can
  prevent PE reconstruction. The raw snapshot remains available.
- Images not present in the OS loaded-module list are outside this implementation.
  Device internal state, device memory/BARs, and unrelated pool allocations are not
  part of a loaded driver image dump.

Exit codes: `0` means a PE was written and every image byte was read; `2` means a
capture exists but memory is partial or PE reconstruction failed; `1` means an
argument, driver connection, capture, or output I/O failure. These codes do not
assert that live memory was atomic or that the file is executable.

## Validation

Run `tests\dump\run.cmd` from an x64 Visual Studio Developer Command Prompt (also
included in `tests\run.cmd`). Synthetic fixtures exercise named/ordinal imports,
missing lookup recovery, export names/ordinals/forwarders, DIR64/HIGHLOW reversal,
loaded-base preservation, header growth, live BSS, missing pages, and invalid
tables. `build/tests/dump/reconstructed.sys` is an inspectable synthetic PE.

Kernel runtime validation requires a signed deployment on a test machine. Check
an ordinary loaded module and a device-stack target; verify the resolved module,
load the output in IDA, and compare known exports/imports and section RVAs. Check
that a non-elevated caller is denied, invalid IOCTL lengths are rejected, and
driver unload works after all client handles close. Driver Verifier testing and
live IDA inspection are separate from the synthetic reconstruction tests.

`tests/dump/ida-regression.py` is an optional IDA/Hex-Rays integration test, run on
a copy of the provided KS dump database. It checks that `CKsFilter::Process`
resolves `KeGetCurrentIrql` and its virtual call, that WPP field names are readable,
that non-code bytes and pre-existing global symbols survive, and that a second
helper run makes no further patches. Its module docstring gives the batch command.

The reconstruction follows Microsoft's [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
Module discovery uses [AuxKlibQueryModuleInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/aux_klib/nf-aux_klib-auxklibquerymoduleinformation).
