# Qakbot Version 2.7.23 (BDNIMBUS) Analysis Notes

- **Sample:** `DLLLoader64_B463.exe`
- **Analysis Date:** April 18, 2024
- **Original Base Address:** `0x00007FF705C20000`
- **Status:** Unloaded PE

---

## 1. OEP Version String Identification

During static disassembly at offset `0x1800...`, the OEP loads the internal version and build hash:

```assembly
lea     rax, a27231311026dab ; "2.7.23.13110 26dabe2"
mov     [r8], rax
jmp     short loc_180001CE8
```

**Malware Version**: `2.7.23.13110`

**Campaign Tag**: `BDNIMBUS`

**Build Hash**: `26dabe2`

## 2. API & Memory Execution Flow

### VirtualProtect & Pointer Patching

1. **Memory Allocation/Unprotect**:
Changes permissions on base page `0x7FF74D695000` with size `0x100` bytes.

2. **Atomic Pointer Swapping**:
Executes `cmove rax, rcx` followed by `xchg qword ptr ds:[rsi+r12*8], rax` to rebind API addresses in memory dynamically.

###Environment & Locale Checks

**Command Line Extraction**: Issues `GetCommandLineA` and `GetCommandLineW`, storing output at relative offsets `[+0x2BE8]` and `[+0x2BF0]`.

**Locale Query (`GetACP`)**: Returns `0x4E4` (Code Page `1252` - ANSI Latin 1).

**Module Verification**: Calls `GetModuleFileNameW` to get running path length (`0x2B` bytes).

**External Config Probe**: Calls `CreateFileW` for `Qakbot.ini` (`GENERIC_READ`, `OPEN_EXISTING`).

##3. Indicators of Compromise (IoCs)

Indicator Type   |                   Value ||
Campaign ID         |               `BDNIMBUS`
Version              |              `2.7.23.13110`
Artifact File         |             `Qakbot.ini`
Code Page              |            `1252` (`0x4E4`)









