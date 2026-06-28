<div align="center">

# 🔍 PyVM

### VM Detection Engine - v2.0

*Hiding a VM should be harder than finding one.*

[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Educational-yellow)](#disclaimer)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-success)](#platform-support)
[![Version](https://img.shields.io/badge/Version-2.0-blueviolet)](#changelog)


__ __

## About

This is a silly little script that spiraled completely out of control.

What started as curiosity about VM detection after watching a [YouTube video](https://www.youtube.com/watch?v=-On6bWFXuM8) about a [VM hiding tool](https://github.com/bRootForceOfficial/vbox_stealth) turned into a multi-vector detection engine with tiered confidence scoring, direct CPUID access, parallel artifact gathering, and anti-analysis heuristics.

**The question I had was simple:** *"How can one still detect a VM even if everything gets obfuscated or scrambled?"*
</div>


> [!IMPORTANT]
> This project is foremost a learning exercise. It is **NOT** intended for malicious use. It is for educational/personal use only (or ethical red team tooling, maybe. But idk if this is good enough for that yet lol).

__ __

<br>
<br>

## How It Works

PyVM uses a **three-phase detection pipeline**:

```
┌────────────────────────────────────────────────────────┐
│                   DETECTION PIPELINE                   │
├────────────────────────────────────────────────────────┤
│                                                        │
│  PHASE 1:  GATHER (parallel, ~2s)                      │
│  ├── 10 independent gatherers (ThreadPoolExecutor)     │
│  │   PCI · ACPI · MAC · Disk · GPU · FS · Quirks ·     │
│  │   Cloud · Uptime · Container                        │
│  │                                                     │
│  ├── 9 sequential gatherers (dependency-ordered)       │
│  │   CPUID · BIOS · Processes · Interrupts · Entropy · │
│  │   Topology · Timing · Memory · Nested Virt          │
│  │                                                     │
│  └── Normalize & deduplicate                           │
│                                                        │
│  PHASE 2:  SANDBOX CHECKS                              │
│  ├── Process scanning (30+ signatures)                 │
│  ├── Environment variable inspection                   │
│  ├── Username/hostname heuristics                      │
│  ├── Sleep timing validation                           │
│  └── Debugger/tracer detection                         │
│                                                        │
│  PHASE 3:  TIERED SCORING                              │
│  ├── T1 HARD (1.0×) —> PCI, CPUID, MAC, ACPI           │
│  ├── T2 MEDIUM (0.6×) —> BIOS, Disk, Processes, GPU    │
│  ├── T3 SOFT (0.3×) —> Entropy, Timing, Topology       │
│  └── Sandbox penalties + classification                │
│                                                        │
└────────────────────────────────────────────────────────┘
```
__ __

<br>
<br>

### Tiered Confidence Weighting

Not all evidence is equal. PyVM weighs signals by how hard they are to spoof:

| Tier | Weight | Signals | Spoof Difficulty |
|------|--------|---------|-----------------|
| **T1: Hard** | 1.0× | PCI vendor/device IDs, direct CPUID signatures, MAC OUI prefixes, ACPI tables | Near-impossible (firmware-level) |
| **T2: Medium** | 0.6× | BIOS/SMBIOS strings, disk vendors, VM processes, virtual GPUs | Moderate (requires system editing) |
| **T3: Soft** | 0.3× | Entropy timing, instruction latency, CPU topology, uptime, RAM sizing | Easiest to manipulate |

A default unstealthed VM gets caught by **multiple T1 signals simultaneously** (easily hitting 100%). Even partially stealthed VMs that hide CPUID and spoof BIOS still get caught by PCI vendors and MAC prefixes.
__ __

<br>
<br>

## Features

### Detection Vectors (19 total)
> More to come

<details>
<summary><b>Hardware & Firmware Signatures</b></summary>

| Vector | Method | Tier |
|--------|--------|------|
| PCI vendor/device IDs | sysfs + lspci (Linux), Registry (Windows) | T1 |
| CPUID hypervisor signatures | Native C library (direct CPUID instruction) | T1 |
| CPUID leaf 0x40000000+ | Extended hypervisor vendor strings | T1 |
| CPUID ECX bit 31 | Hypervisor present flag | T3 |
| ACPI table signatures | /sys/firmware/acpi/tables/ | T1 |
| MAC OUI prefixes | psutil network interfaces | T1 |
| BIOS/SMBIOS vendor | dmidecode (sudo-aware) + sysfs fallback | T2 |
| Disk vendor strings | /sys/block + /dev/disk/by-id/ | T2 |
| GPU adapter identification | lspci -v / wmic | T2 |
| Filesystem artifacts | /dev/vda, /proc/xen, VBoxGuest.sys, etc. | T2 |

</details>

<br>

<details>
<summary><b>Behavioral Heuristics</b></summary>

| Vector | Method | What It Detects |
|--------|--------|----------------|
| Entropy timing variance | `os.urandom(16384)` × 8500 samples | VM-exit latency spikes during CSPRNG refilling |
| Instruction timing | `sum(range(50))` × 25 batches of 200 | Privileged operation overhead |
| Interrupt jitter | `time.sleep(0)` × 1000 samples | Abnormally tight scheduling (emulation artifact) |
| CPU topology ratio | Logical/physical core ratio | Suspicious thread-core configurations |
| Memory sizing patterns | Power-of-two allocation detection | Common VM defaults (2/4/8/16/32 GB) |
| Uptime analysis | psutil boot time | Recently booted sandboxes |
| Nested virtualization | VT-x/SVM flags + VirtIO + timing variance | VM-inside-VM scenarios |

</details>

<br>

<details>
<summary><b>Environment Classification</b></summary>

| Vector | Method |
|--------|--------|
| Container detection | /.dockerenv + cgroup ID hashes + docker.sock (multi-signal required) |
| Cloud metadata probing | AWS / Azure / GCP / Alibaba / DigitalOcean endpoints |
| Sandbox/anti-analysis | 30+ process signatures, env vars, debuggers, timing anomalies |
| Sleep timing validation | Detects accelerated/skipped sleeps (sandbox artifact) |

</details>

<br>
<br>

## Installation

### Prerequisites

- Python 3.12+
- `psutil` (required)
- `beaupy` (optional — enables the interactive TUI)
- `requests` (optional — enables cloud metadata probing)
- `gcc` (optional — for compiling the direct CPUID library)

### Quick Start

```bash
# Clone the repo
git clone https://github.com/therealOri/PyVM.git
cd PyVM

# Install Python dependencies
pip install psutil beaupy requests

# (Optional) Compile the direct CPUID library for unforgeable detection
(Build and setup libcpuid)

# Run the TUI
python vm_ui.py

# Or run headless
python vm_core.py
```
[CPUID Build Info](https://github.com/therealOri/PyVM/tree/main/c_build)
__ __

<br>
<br>

## Usage

### Interactive TUI

```bash
python vm_ui.py
```

Provides a beaupy-powered menu with three scan modes:

| Mode | Description |
|------|-------------|
| **Quick Scan** | Fast scan with score breakdown and artifacts |
| **Detailed Scan** | Adds tier-by-tier detection reasoning (T1/T2/T3) |
| **Debug Mode** | Full raw JSON dump of every artifact and signal |
__ __

### Programmatic API

```python
from vm_core import Detector, set_prompt_callbacks

detector = Detector()

# Full scan with explanations
result = detector.detect(parallel=True, explain=True)

print(f"Classification: {result['classification']}")
print(f"Confidence: {result['confidence']}%")
print(f"Best Guess: {result['best_guess']}")

# Access raw scores
for vm, score in sorted(result['scores'].items(), key=lambda x: -x[1]):
    if score > 0:
        print(f"  {vm}: {score}%")

# Check anti-analysis environment
if result['anti_analysis']['detected']:
    print("⚠️  Sandbox detected!")

# Access full artifact data
artifacts = result['artifacts']
print(f"CPUID Signature: {artifacts['cpuid_signature']}")
print(f"Entropy median: {artifacts['entropy_behavior']['median_ns']:,}ns")
```
__ __

<br>
<br>

## 📊 Detection Capability Info

| Hypervisor | Default (No Stealth) | Partial Stealth¹ | Deep Stealth² |
|------------|:-------------------:|:-----------------:|:-------------:|
| **QEMU/KVM** | ✅ 100% | ✅ 90%+ | ⚠️ ~8% |
| **VirtualBox** | ✅ 100% | ✅ 90%+ | ⚠️ ~8% |
| **VMware** | ✅ 100% | ✅ 90%+ | ⚠️ ~8% |
| **Hyper-V** | ✅ 90%+ | ✅ 85%+ | ⚠️ ~8% |
| **Xen** | ✅ 85%+ | ✅ 80%+ | ⚠️ ~8% |

> ¹ *Hides CPUID + spoofs BIOS/MAC*
> ² *Above + spoofs PCI vendors (requires kernel-level hypervisor modifications)*

**Reality check:** No guest-side detection tool catches a fully stealthed hypervisor with all signatures scrubbed. PyVM handles everything up to deep PCI spoofing, which puts it in the top tier of detection tools.
__ __

<br>
<br>

## Platform Support

| Feature | Linux | Windows |
|---------|:-----:|:-------:|
| PCI vendor/device scanning | ✅ | ✅ |
| Direct CPUID access | ✅ (.so) | ✅ (.dll) |
| ACPI table parsing | ✅ | ❌ |
| BIOS/SMBIOS via dmidecode | ✅ | ✅ (wmic) |
| Entropy timing heuristics | ✅ | ✅ |
| Instruction timing | ✅ | ✅ |
| Container detection | ✅ | ❌ |
| Cloud metadata probing | ✅ | ✅ |
| Sandbox/anti-analysis | ✅ | ✅ |
| TUI (beaupy) | ✅ | ✅ |
__ __

<br>
<br>

## Roadmap

<details>
<summary><b>Short-term (v2.1)</b></summary>

- [ ] RDTSC timing (sub-nanosecond via timestamp counter)
- [ ] CPUID leaf 0x40000003 (KVM paravirt feature flags)
- [ ] MSR probing via `/dev/cpu/0/msr`
- [ ] Disk serial number pattern analysis (QM00001, VB00001)
- [ ] DMI table version checking
- [ ] Cache topology analysis (`lscpu --caches`)
- [ ] Cross-validation scoring (inconsistency detection between vectors)

</details>

<details>
<summary><b>Long-term (v3.0)</b></summary>

- [ ] Machine learning classifier on timing distributions
- [ ] TPM remote attestation
- [ ] Windows registry deep-scan
- [ ] TCP/IP stack fingerprinting
- [ ] Side-channel attacks (Flush+Reload, Prime+Probe)
- [ ] Spoofing detection scoring (detect the spoofer, not just the VM)

</details>

__ __

<br>
<br>

## 💜 Support | Buy me a coffee <3

If this project helped you learn something or saved you some time, consider supporting me and helping me get more coffee:

> 💵 Donate via [Cash App](https://cash.app/app/TKWGCRT)

![Cash App](https://user-images.githubusercontent.com/45724082/158000721-33c00c3e-68bb-4ee3-a2ae-aefa549cfb33.png)
__ __

<br>
<br>

## 📜 Changelog

<details>
<summary><b>v2.0 —> Current</b></summary>

- Rewritten scoring engine with tiered confidence weighting (T1/T2/T3)
- Direct CPUID access via native C library
- Parallel artifact gathering (ThreadPoolExecutor)
- Cloud metadata endpoint probing (AWS/Azure/GCP/Alibaba/DigitalOcean)
- Container detection with multi-signal requirement
- Sudo-aware privilege handling with UI callback hooks
- Anti-analysis sandbox heuristics (30+ signatures)
- Entropy timing analysis (VM-exit outlier detection)
- Instruction timing analysis (privileged op overhead)
- Nested virtualization detection
- Beaupy-powered TUI with animated spinner
- False-positive elimination on bare metal (calibrated baselines)

</details>

<details>
<summary><b>v1.0 —> Initial Release</b></summary>

- Basic PCI vendor matching
- CPUID signature checking via /proc/cpuinfo
- MAC OUI prefix detection
- BIOS vendor keyword matching
- Simple additive scoring (no tiers)

</details>

__ __

<div align="center">

<br>
<br>

**Made with curiosity and too much caffeine**

*Got feedback or ideas? Open an issue or reach out! ^-^*

</div>
