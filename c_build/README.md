# libcpuid Compilation Guide

This guide covers building the native CPUID helper library used by vm_core.py 
for direct, unforgeable hypervisor detection via raw CPUID instructions.
__ __

<br>
<br>

## Prerequisites

Platform         | Requirement
-----------------|----------------------------------
Linux            | gcc (or clang)
Windows          | MinGW-w64 or MSVC
__ __

Verify your compiler is installed:
```bash
# Linux
gcc --version

# Windows (MinGW)
x86_64-w64-mingw32-gcc --version
```
__ __

<br>
<br>

## Building

### Linux

Run this command in the same directory as `cpuid.c`:

```bash
gcc -shared -fPIC -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong cpuid.c -o libcpuid.so
```
Security Hardening Flags Explained:
  - __fstack-protector-strong__   -> [`Stack buffer overflow protection`]
  - __D_FORTIFY_SOURCE=2__        -> [`Compile-time runtime buffer checking`]
  - __fPIC__                      -> [`Position-independent code (required)`]
  - __O2__                        -> [`Optimization level`]
  - __shared__                    -> [`Produce shared library (.so)`]
  - __o__                         -> [`Output filename`]

<br>

### Windows (MinGW)

```bash
gcc -shared -O2 cpuid.c -o cpuid.dll
```

### Windows (MSVC)

```bat
cl /LD /O2 cpuid.c /Fe:cpuid.dll
```
__ __
> TODO: Work on install script/stuff for windows options.


<br>
<br>

## Verification

After compiling, verify the exported cpuid symbol exists:

### Linux

```bash
nm -D libcpuid.so | grep cpuid
```
> Expected output/format: `0000000000001110 T cpuid` | we are mainly looking for `"T cpuid"`.

<br>

### Windows (MinGW)

```bash
nm cpuid.dll | grep cpuid
```

### Windows (MSVC)

```bat
dumpbin /exports cpuid.dll
```
__ __

<br>
<br>

## Placement

Place the compiled library NEXT TO vm_core.py:

```
PyVM/
├── vm_core.py
├── vm_cli.py
├── libcpuid.so     ← Linux
└── cpuid.dll       ← Windows (if cross-compiling)
```
> The module will auto-detect the library on import, no configuration needed.
__ __

<br>
<br>

## How It Works

```
+-------------+             ctypes.CDLL              +--------------------+
| vm_core.py  | -----------------------------------> | libcpuid.so/dll    |
| Python      |   cpuid(eax, ecx, uint32_t* out)     | Native C           |
| Layer       |       <-- returns (a,b,c,d)          | CPUID instructions |
+-------------+                                      +--------------------+
```

Flow:
  1. Python calls the C function via ctypes.CDLL
  2. C code executes the raw CPUID assembly instruction
  3. Results are written to a 4-element uint32_t array
  4. Python receives (eax, ebx, ecx, edx) as a tuple

This bypasses OS abstractions entirely, the hypervisor cannot intercept this
call path without modifying the CPU itself.
__ __

<br>
<br>

## Fallback Behavior

If the compiled library is MISSING or if it FAILS to LOAD:

Scenario                      | Behavior
------------------------------|-----------------------------------------------
.so/.dll not found            | Falls back to lscpu / wmic (indirect mode)
Load failure                  | Continues with less reliable indirect detection
Wrong architecture            | Gracefully skipped & noted in artifacts result
> NOTE: Indirect mode CAN BE SPOOFED by advanced evasion tools. For maximum detection accuracy, use the compiled library.
__ __

<br>
<br>

## Testing

Quick test after compilation:

```python
python3 -c "
from vm_core import Detector
d = Detector()
d.gather_all_sequential()
print(f'Direct CPUID: {d.art.direct_cpuid_available}')
print(f'CPU Vendor:   {d.art.cpu_vendor}')
print(f'Hypervisor:   {d.art.hypervisor_flag}')
"
```

Expected on bare metal:
  - Direct CPUID: True
  - CPU Vendor:   AuthenticAMD (for example)
  - Hypervisor:   False
__ __

<br>
<br>

## Troubleshooting

Issue                         | Cause               | Fix
------------------------------|---------------------|-----------------------------------------------------
Direct CPUID: False           | Library not found   | Ensure libcpuid.so/dll is in the same dir as vm_core.py
OSError: undefined symbol     | Arch mismatch       | Recompile on the host/target PC
Permission denied             | Not executable      | chmod +x libcpuid.so
Windows: WinError 126         | Missing MinGW       | Install MinGW-w64 or MSVC
__ __
