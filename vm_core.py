"""
vm_core.py v2.0 | Enhanced VM Detection Library

Core VM detection library (importable)
Targets Python 3.12+

__Author__ = therealOri
__Enhancements__ = CPUID access, cloud probing, container detection, parallel gathering, tiered scoring
"""

from __future__ import annotations
import os
import platform
import subprocess
import sys
import re
import socket
import time
import threading
import ctypes
from typing import Dict, List, Set, Optional, Any, Callable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


try:
    import psutil
except Exception:
    psutil = None

# Cloud probe dependency (optional)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# For Windows-only registry stuff
if platform.system() == "Windows":
    try:
        import winreg
    except Exception:
        winreg = None


# ============================================================
# Direct CPUID Module Setup
# ============================================================
# Comment out if you don't want to use the compiled libcpuid.so (Linux) or cpuid.dll (Windows) file. -> [compiled from cpuid.c]

try:
    _CPUID_LIB_LOADED = False
    if platform.system() == "Linux":
        _CPUID_PATH = "libcpuid.so"
        if os.path.exists(_CPUID_PATH):
            _CPUID_LIB = ctypes.CDLL(os.path.abspath(_CPUID_PATH))
            _CPUID_LIB.cpuid.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint32)]
            _CPUID_LIB_loaded = True
    elif platform.system() == "Windows":
        _CPUID_PATH = "cpuid.dll"
        if os.path.exists(_CPUID_PATH):
            _CPUID_LIB = ctypes.CDLL(os.path.abspath(_CPUID_PATH))
            _CPUID_LIB.cpuid.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint32)]
            _CPUID_LIB_loaded = True
except NameError:
    pass  # ctypes not imported yet
except Exception:
    _CPUID_LIB_loaded = False


def get_direct_cpuid(eax: int, ecx: int = 0) -> Tuple[int, int, int, int]:
    """
    Direct CPUID instruction access via native library.
    Falls back to sys/commands if unavailable.
    Returns (eax, ebx, ecx, edx) values.
    """
    global _CPUID_LIB_loaded

    if globals().get('_CPUID_LIB_loaded', False):
        out = (ctypes.c_uint32 * 4)()
        try:
            _CPUID_LIB.cpuid(eax, ecx, out)
            return (out[0], out[1], out[2], out[3])
        except Exception:
            pass

    # Fallback: parse from lscpu / wmic
    if platform.system() == "Linux":
        out = run(["lscpu"])
        # Can't easily extract raw registers without parsing kernel messages
        # Return placeholder indicating indirect mode
        return (0, 0, 0, 0)
    else:
        return (0, 0, 0, 0)


# ============================================================
# Configuration & Signatures
# ============================================================

VM_PCI_VENDORS: Dict[str, List[str]] = {
    "VirtualBox": ["0x80EE"],
    "VMware":     ["0x15AD"],
    "Hyper-V":    ["0x1414"],
    "QEMU/KVM":   ["0x1AF4", "0x1B36"],
    "Parallels":  ["0x1AB8"],
    "Xen":        ["0x5853"],
}

VM_PCI_DEVICES: Dict[str, List[str]] = {
    "QEMU/KVM": ["0x29C0", "0x293E", "0x2918", "0x2922"],
    "VMware":   ["0x07B0", "0x07C0"],
    "VirtualBox": ["0x0400"],
}

VM_PCI_SIGNATURES: Dict[str, Dict[str, Set[str]]] = {
    "QEMU/KVM": {"vendors": {"1AF4", "1B36", "00DA", "1D0F"}, "devices": {"29C0", "293E", "2918", "2922", "2930"}},
    "VMware":   {"vendors": {"15AD"}, "devices": {"07B0", "07C0", "0790", "07A0", "0740"}},
    "VirtualBox":{"vendors": {"80EE"}, "devices": {"0400", "CAFE", "BEEF"}},
    "Hyper-V":  {"vendors": {"1414"}, "devices": {"5353", "5801", "0700"}},
    "Xen":      {"vendors": {"5853"}, "devices": {"0001", "0002"}},
    "Parallels": {"vendors": {"1AB8"}, "devices": {"4005", "0001"}},
}

MAC_PREFIXES: Dict[str, List[str]] = {
    "VirtualBox": ["08:00:27"],
    "VMware": ["00:05:69", "00:0C:29", "00:1C:14", "00:50:56"],
    "Hyper-V": ["00:15:5D"],
    "QEMU/KVM": ["52:54:00"],
    "Parallels": ["00:1C:42"],
}

VM_CPUID_SIGS: Dict[str, str] = {
    "VMware": "VMwareVMware",
    "VirtualBox": "VBoxVBoxVBox",
    "QEMU/KVM": "KVMKVMKVM",
    "Microsoft Hv": "Microsoft Hv",
    "TCGTCGTCGTCG": "TCGTCGTCGTCG",  # QEMU TCG software emulation
}

VM_SOFT_KEYWORDS: Dict[str, Dict[str, List[str]]] = {
    "VirtualBox": {"bios": ["virtualbox", "innotek", "oracle"], "process": ["vboxservice", "vboxtray"]},
    "VMware":     {"bios": ["vmware"], "process": ["vmtoolsd", "vmwaretray", "vmwareuser"]},
    "Hyper-V":    {"bios": ["microsoft corporation", "hyper-v"], "process": ["vmcompute", "vmguest.iso"]},
    "QEMU/KVM":   {"bios": ["qemu", "seabios"], "process": ["qemu-ga", "qemuguestagent"]},
    "Parallels":  {"bios": ["parallels"], "process": ["prltools", "prl_vm_app"]},
    "Xen":        {"bios": ["xen"], "process": ["xenstore", "xenconsoled"]},
}

VM_ACPI_PREFIXES = ("VBOX", "VMW", "QEMU", "XEN", "BOCHS", "VMBUS")

ACPI_SIGS: Dict[str, List[str]] = {
    "VirtualBox": ["VBOX__"],
    "VMware": ["VMWARE"],
    "QEMU/KVM": ["QEMU"],
    "Hyper-V": ["VMBUS"],
    "Xen": ["XEN_"],
}

VM_DISK_VENDORS: Dict[str, List[str]] = {
    "QEMU/KVM": ["QEMU", "KVM"],
    "VirtualBox": ["VBOX", "VBOX_HARDDISK", "Oracle"],
    "VMware": ["VMware", "VMWARE, Inc"],
    "Parallels": ["Parallels"],
}

SANDBOX_PROCS = [
    "sandbox", "cuckoo", "vmsrvc", "vboxservice", "vmtoolsd",
    "ollydbg", "x64dbg", "x32dbg", "wireshark", "procexp", "procmon",
    "remnux", "snort", "suricata", "volatility"
]

# Intel/AMD CPU specification database for thread validation
CPU_THREAD_DATABASE: Dict[str, Dict[str, Any]] = {
    "Intel Core i9-13900K": {"cores": 8, "threads": 16, "ratio_max": 2.0},
    "Intel Core i7-12700K": {"cores": 12, "threads": 20, "ratio_max": 1.67},
    "AMD Ryzen 9 7950X": {"cores": 16, "threads": 32, "ratio_max": 2.0},
    # Add more as needed, can auto-fetch online if desired
}

CLOUD_METADATA_ENDPOINTS = {
    "AWS": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "timeout_ms": 100,
        "headers": {},
    },
    "Azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "timeout_ms": 100,
        "headers": {"Metadata": "true"},
    },
    "GCP": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "timeout_ms": 100,
        "headers": {"Metadata-Flavor": "Google"},
    },
    "Alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "timeout_ms": 100,
        "headers": {},
    },
    "DigitalOcean": {
        "url": "http://169.254.169.254/metadata/v1.json",
        "timeout_ms": 100,
        "headers": {},
    },
}

# ============================================================
# Utility Functions
# ============================================================

def run(cmd: List[str], *, text: bool = True, timeout: float = 5.0) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                       text=text, timeout=timeout) or ""
    except Exception:
        return ""

def _clean_hex(s: str) -> str:
    if not s:
        return s
    s = str(s).strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = re.sub(r"[^0-9A-Fa-f]", "", s).upper()
    if not s:
        return ""
    return "0x" + s.rjust(4, "0")

def _safe_read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None

def shutil_which(cmd: str) -> bool:
    try:
        import shutil
        return shutil.which(cmd) is not None
    except Exception:
        return False


# ============================================================
# Artifact Collection Class
# ============================================================

class ArtifactCollection:
    def __init__(self) -> None:
        self.cpu_vendor: Optional[str] = None
        self.hypervisor_flag: bool = False
        self.pci_vendors: List[str] = []
        self.pci_devices: List[str] = []
        self.acpi_tables: List[str] = []
        self.acpi_signatures: List[str] = []
        self.cpuid_signature: Optional[str] = None
        self.cpuid_leaf_0: Optional[Tuple[int,int,int,int]] = None  # Hypervisor ID
        self.bios_vendor: Optional[str] = None
        self.bios_brand: Optional[str] = None
        self.system_product: Optional[str] = None
        self.processes: List[str] = []
        self.mac_prefixes: List[str] = []
        self.disk_vendors: List[str] = []
        self.notes: List[str] = []

        # Behavioral data
        self.interrupt_behavior: Dict[str, Any] = {}
        self.entropy_behavior: Dict[str, Any] = {}
        self.cpu_topology: Dict[str, Any] = {}
        self.cache_behavior: Dict[str, Any] = {}
        self.instruction_timing: Dict[str, Any] = {}
        self.memory_patterns: Dict[str, Any] = {}
        self.filesystem_artifacts: List[str] = []
        self.hardware_quirks: List[str] = []
        self.network_latency: Dict[str, Any] = {}
        self.gpu_info: Dict[str, Any] = {}
        self.uptime: Dict[str, Any] = {}

        # NEW fields v2.0
        self.container_runtime: Optional[str] = None
        self.cloud_provider: Optional[str] = None
        self.cloud_metadata_reachable: Dict[str, Any] = {}
        self.nested_virtualization: Dict[str, Any] = {}
        self.thread_validation: Dict[str, Any] = {}
        self.direct_cpuid_available: bool = _CPUID_LIB_loaded if '_CPUID_LIB_loaded' in globals() else False


    def to_dict(self) -> Dict[str, Any]:
        return {
            "cpu_vendor": self.cpu_vendor,
            "hypervisor_flag": self.hypervisor_flag,
            "pci_vendors": self.pci_vendors,
            "pci_devices": self.pci_devices,
            "acpi_tables": self.acpi_tables,
            "acpi_signatures": self.acpi_signatures,
            "cpuid_signature": self.cpuid_signature,
            "direct_cpuid_available": self.direct_cpuid_available,
            "bios_vendor": self.bios_vendor,
            "bios_brand": self.bios_brand,
            "system_product": self.system_product,
            "processes": self.processes,
            "mac_prefixes": self.mac_prefixes,
            "disk_vendors": self.disk_vendors,
            "container_runtime": self.container_runtime,
            "cloud_provider": self.cloud_provider,
            "nested_virtualization": self.nested_virtualization,
            "thread_validation": self.thread_validation,
            "notes": self.notes,
            "interrupt_behavior": self.interrupt_behavior,
            "entropy_behavior": self.entropy_behavior,
            "cpu_topology": self.cpu_topology,
            "cache_behavior": self.cache_behavior,
            "instruction_timing": self.instruction_timing,
            "memory_patterns": self.memory_patterns,
            "filesystem_artifacts": self.filesystem_artifacts,
            "hardware_quirks": self.hardware_quirks,
            "network_latency": self.network_latency,
            "gpu_info": self.gpu_info,
            "uptime": self.uptime,
        }


# ============================================================
# Gatherer Functions v2.0
# ============================================================

def gather_interrupt_behavior(art: ArtifactCollection) -> None:
    """Measure interrupt/jitter behavior - harder to spoof consistently."""
    deltas = []
    for _ in range(1000):
        t0 = time.perf_counter()
        time.sleep(0)
        deltas.append(time.perf_counter() - t0)

    jitter = max(deltas) - min(deltas)
    avg_jitter = sum(deltas) / len(deltas) if deltas else 0

    art.interrupt_behavior = {
        "samples": len(deltas),
        "jitter": jitter,
        "avg_jitter_ns": avg_jitter * 1e9,
        "low_jitter": jitter < 1e-6,  # Tightened from 1e-5
        "distribution_width": max(deltas[-100:]) - min(deltas[:100]) if len(deltas) > 200 else None,
    }


def gather_entropy_behavior(art: ArtifactCollection) -> None:
    """Check entropy collection variance under hypervisors."""
    timings = []
    for _ in range(512):
        t0 = time.perf_counter_ns()
        os.urandom(64)
        timings.append(time.perf_counter_ns() - t0)

    variance = max(timings) - min(timings)
    median_time = sorted(timings)[len(timings)//2]

    art.entropy_behavior = {
        "samples": len(timings),
        "variance_ns": variance,
        "median_ns": median_time,
        "low_variance": variance < 1000000,  # ← CHANGED: was 1e5
        "high_outliers": sum(1 for t in timings if t > median_time * 3),
        "variance_ratio": variance / median_time if median_time > 0 else 0,
    }


def gather_cpu_topology(art: ArtifactCollection) -> None:
    """Detailed CPU topology including validation against specs."""
    topo = {}
    try:
        if psutil:
            topo["logical"] = psutil.cpu_count(logical=True)
            topo["physical"] = psutil.cpu_count(logical=False)
        else:
            topo["logical"] = os.cpu_count()
            topo["physical"] = None

        if topo.get("physical") and topo.get("logical"):
            ratio = topo["logical"] / topo["physical"]
            # Changed: 6× instead of 4× threshold
            topo["ratio"] = ratio
            topo["suspicious_ratio"] = ratio > 6

        # Check for odd core/thread counts
        logical = topo.get("logical")
        if logical and logical % 2 != 0:
            topo["odd_thread_count"] = True
        else:
            topo["odd_thread_count"] = False

    except Exception:
        pass

    art.cpu_topology = topo


def gather_cpu_vendor_with_cpuid(art: ArtifactCollection) -> None:
    """Attempt direct CPUID access for unforgeable hypervisor detection."""
    art.direct_cpuid_available = _CPUID_LIB_loaded if '_CPUID_LIB_loaded' in globals() else False

    # First try direct CPUID
    if art.direct_cpuid_available:
        # Leaf 0: Vendor string
        leaf0 = get_direct_cpuid(0)
        art.cpuid_leaf_0 = leaf0

        # Leaf 0x1: Feature flags
        leaf1 = get_direct_cpuid(1)
        eax, ebx, ecx, edx = leaf1
        # ECX bit 31 = Hypervisor present
        art.hypervisor_flag = bool(ecx & (1 << 31))

        # Leaf 0x40000000+: Hypervisor vendor strings
        hyp_sig_raw = get_direct_cpuid(0x40000000)
        if hyp_sig_raw[0] >= 0x40000100:  # Extended leaves available
            for leaf_num in range(0x40000000, min(hyp_sig_raw[0] + 1, 0x40000101)):
                sig_data = get_direct_cpuid(leaf_num)
                # Convert bytes to ASCII signature
                sig_bytes = (sig_data[1]).to_bytes(4, 'little') + \
                           (sig_data[3]).to_bytes(4, 'little') + \
                           (sig_data[2]).to_bytes(4, 'little')
                sig_str = sig_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')
                if sig_str and sig_str != '':
                    art.cpuid_signature = sig_str
                    break

    # Fallback to existing methods
    if platform.system() == "Linux":
        txt = _safe_read_text("/proc/cpuinfo") or ""
        m = re.search(r"vendor_id\s+:\s+(.+)", txt)
        if m:
            art.cpu_vendor = m.group(1).strip()
        if "hypervisor" in txt.lower():
            art.hypervisor_flag = True
        out = run(["lscpu"])
        m2 = re.search(r"Hypervisor vendor:\s*(.+)", out)
        if m2 and not art.cpuid_signature:
            art.cpuid_signature = m2.group(1).strip()
    elif platform.system() == "Windows":
        out = run(["wmic", "cpu", "get", "Manufacturer"])
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) >= 2:
            art.cpu_vendor = lines[1]
        hv = run(["powershell", "-NoProfile", "-Command",
                  "(Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent"])
        if hv and hv.strip().lower() in ("true", "1"):
            art.hypervisor_flag = True


def gather_pci(art: ArtifactCollection) -> None:
    """Collect PCI vendor/device IDs across platforms."""
    vendors: Set[str] = set()
    devices: Set[str] = set()
    system = platform.system()

    if system == "Linux":
        base = "/sys/bus/pci/devices/"
        if os.path.isdir(base):
            for dev in os.listdir(base)[:100]:  # Limit scan scope
                vfile = os.path.join(base, dev, "vendor")
                dfile = os.path.join(base, dev, "device")
                vtxt = _safe_read_text(vfile)
                dtxt = _safe_read_text(dfile)
                if vtxt:
                    v = vtxt.strip().replace("0x", "").upper()
                    if v:
                        vendors.add("0x" + v)
                if dtxt:
                    d = dtxt.strip().replace("0x", "").upper()
                    if d:
                        devices.add("0x" + d)
        if shutil_which("lspci"):
            out = run(["lspci", "-nn"])
            for line in out.splitlines():
                m = re.search(r"\[([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})\]", line)
                if m:
                    vendors.add("0x" + m.group(1).upper())
                    devices.add("0x" + m.group(2).upper())

    elif system == "Windows" and winreg:
        roots = [r"SYSTEM\CurrentControlSet\Enum\PCI", r"SYSTEM\ControlSet001\Enum\PCI"]
        ven_re = re.compile(r"VEN_([0-9A-Fa-f]{4})", re.I)
        dev_re = re.compile(r"DEV_([0-9A-Fa-f]{4})", re.I)
        for root in roots:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root) as hroot:
                    count = winreg.QueryInfoKey(hroot)[0]
                    for i in range(min(count, 200)):  # Limit iteration
                        try:
                            subname = winreg.EnumKey(hroot, i)
                        except OSError:
                            continue
                        mv = ven_re.search(subname)
                        md = dev_re.search(subname)
                        if mv:
                            vendors.add("0x" + mv.group(1).upper())
                        if md:
                            devices.add("0x" + md.group(1).upper())
            except FileNotFoundError:
                continue
            except Exception:
                continue

    art.pci_vendors = sorted(vendors)
    art.pci_devices = sorted(devices)


def gather_acpi_tables(art: ArtifactCollection) -> None:
    """Parse ACPI table signatures for VM fingerprints."""
    if platform.system() == "Linux":
        path = "/sys/firmware/acpi/tables/"
        if os.path.isdir(path):
            try:
                tables = [f.strip() for f in os.listdir(path) if f][:50]
                art.acpi_tables = sorted(tables)
                sigs: Set[str] = set()
                for t in tables:
                    for vm, patterns in ACPI_SIGS.items():
                        for p in patterns:
                            if t.upper().startswith(p.upper()):
                                sigs.add(f"{vm}:{t}")
                art.acpi_signatures = sorted(sigs)
            except Exception:
                pass







def read_dmi_from_sysfs(art: ArtifactCollection) -> None:
    """Fallback reader for DMI data from /sys/class/dmi/id."""
    base = "/sys/class/dmi/id/"
    if not os.path.isdir(base):
        return

    # Read available files safely
    sv = _safe_read_text(os.path.join(base, "sys_vendor")) or ""
    pn = _safe_read_text(os.path.join(base, "product_name")) or ""
    brn = _safe_read_text(os.path.join(base, "board_vendor")) or ""

    # Update only if we actually got something new
    if sv.strip():
        art.bios_vendor = sv.strip()
    if pn.strip():
        art.system_product = pn.strip()
    elif brn.strip():
        # Product name sometimes absent, try board vendor instead
        art.system_product = brn.strip()



def gather_bios_system(art: ArtifactCollection) -> None:
    """Collect BIOS/SMBIOS vendor/product information."""
    is_root = os.geteuid() == 0
    system = platform.system()
    if system == "Linux":
        # Step 1: Try privileged dmidecode
        if shutil_which("dmidecode"):
            cmd_prepend = ["sudo", "-n"] if not is_root else []
            man = run(cmd_prepend + ["dmidecode", "-s", "system-manufacturer"])
            prod = run(cmd_prepend + ["dmidecode", "-s", "system-product-name"])

            found_via_sudo = False
            if man.strip():
                art.bios_vendor = man.strip()
                found_via_sudo = True
            if prod.strip():
                art.system_product = prod.strip()
                found_via_sudo = True

            # Step 2: If sudo failed/is unavailable, fallback to sysfs
            if not found_via_sudo:
                read_dmi_from_sysfs(art)
                if not art.bios_vendor and not art.system_product:
                    art.notes.append("ℹ Running without root + sudo unavailable")
        else:
            # Tool missing? Straight to sysfs
            read_dmi_from_sysfs(art)

    elif system == "Windows":
        out = run(["wmic", "bios", "get", "Manufacturer", "/value"])
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) >= 2:
            art.bios_vendor = lines[1]
        out2 = run(["wmic", "computersystem", "get", "Manufacturer,Model", "/value"]) or ""
        lines2 = [l.strip() for l in out2.splitlines() if l.strip()]
        if len(lines2) >= 2:
            art.system_product = lines2[1]

    # Normalize brand classification
    art.bios_brand = None
    if art.bios_vendor:
        b = art.bios_vendor.lower()
        if "virtualbox" in b or "oracle" in b or "innotek" in b:
            art.bios_brand = "VirtualBox"
        elif "vmware" in b:
            art.bios_brand = "VMware"
        elif "qemu" in b or "seabios" in b:
            art.bios_brand = "QEMU/KVM"
        elif "microsoft" in b or "hyper-v" in b:
            art.bios_brand = "Hyper-V"
        elif "parallels" in b:
            art.bios_brand = "Parallels"
        elif "xen" in b:
            art.bios_brand = "Xen"
        else:
            art.bios_brand = "Legit/Not_VM_Brand"


def gather_processes(art: ArtifactCollection) -> None:
    """Enumerate running processes for sandbox tools."""
    procs: Set[str] = set()
    try:
        if psutil:
            for p in psutil.process_iter(attrs=("name",)):
                name = (p.info.get("name") or "").strip()
                if name:
                    procs.add(name)
        else:
            if platform.system() == "Windows":
                out = run(["tasklist"])
                for line in out.splitlines():
                    if ".exe" in line.lower():
                        parts = line.split()
                        if parts:
                            procs.add(parts[0])
            else:
                out = run(["ps", "axo", "comm"])
                for line in out.splitlines()[1:]:
                    ln = line.strip()
                    if ln:
                        procs.add(ln)
    except Exception:
        pass
    art.processes = sorted(procs)


def gather_mac_prefixes(art: ArtifactCollection) -> None:
    """Extract MAC address OUI prefixes from interfaces."""
    prefixes: Set[str] = set()
    try:
        if psutil:
            for nic, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    addr = getattr(a, "address", None)
                    if not addr:
                        continue
                    addr = addr.strip()
                    if re.match(r"^[0-9A-Fa-f:.-]{11,}$", addr):
                        if ":" in addr:
                            pref = ":".join(addr.split(":")[:3]).upper()
                        elif "-" in addr:
                            pref = ":".join(addr.split("-")[:3]).upper()
                        else:
                            pref = addr[:8].upper()
                        prefixes.add(pref)
        else:
            if platform.system() == "Linux":
                out = run(["ip", "link"]) or run(["ifconfig"]) or ""
                for m in re.finditer(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", out, re.I):
                    prefixes.add(m.group(1).upper())
    except Exception:
        pass
    art.mac_prefixes = sorted(prefixes)


def gather_disk_vendors(art: ArtifactCollection) -> None:
    """Identify disk drive vendors/models."""
    vendors: Set[str] = set()
    if platform.system() == "Linux":
        base = "/sys/block/"
        if os.path.isdir(base):
            for b in os.listdir(base):
                p = os.path.join(base, b, "device", "vendor")
                vtxt = _safe_read_text(p)
                if vtxt:
                    vendors.add(vtxt.strip())
        byid = "/dev/disk/by-id/"
        if os.path.isdir(byid):
            for entry in os.listdir(byid):
                if any(x in entry.lower() for x in ("qemu", "vbox", "vmware", "parallels")):
                    vendors.add(entry)
    elif platform.system() == "Windows":
        out = run(["wmic", "diskdrive", "get", "Model,Manufacturer"]) or ""
        for line in out.splitlines():
            line = line.strip()
            if line:
                vendors.add(line)
    art.disk_vendors = sorted(vendors)


def gather_container_detection(art: ArtifactCollection) -> None:
    """STRONG EVIDENCE ONLY | Reduced false positives on bare metal."""
    indicators = []
    runtime = None

    # Condition 1: /.dockerenv file exists (rare but very strong signal)
    has_docker_env = os.path.exists("/.dockerenv")

    # Condition 2: Look for actual container ID hashes (64 char hex) in cgroups
    cgroup_txt = _safe_read_text("/proc/self/cgroup")
    cgroup_matches = False

    if cgroup_txt:
        # Match Docker/containerd-style IDs (64+ hex chars before slash)
        import re
        container_id_pattern = re.compile(r'/([a-f0-9]{64}/|container=)')
        if container_id_pattern.search(cgroup_txt):
            cgroup_matches = True

        # Also check for systemd slice patterns that contain scope/session
        if re.search(r'/(systemd-)?scope\.service|session', cgroup_txt.lower()):
            cgroup_matches = True

        # Or explicit docker path patterns
        if "/docker/" in cgroup_txt or "/containers/" in cgroup_txt:
            cgroup_matches = True

    # Condition 3: Docker socket actually exists
    docker_socket_exists = any(os.path.exists(p) for p in ["/run/docker.sock", "/var/run/docker.sock"])

    # STRONG EVIDENCE REQUIREMENT | Need multiple signals together
    if has_docker_env and (cgroup_matches or docker_socket_exists):
        indicators.append("strong_container_evidence")
        runtime = "Docker"
    elif docker_socket_exists and has_docker_env:
        indicators.append("socket_and_marker_present")
        runtime = "Docker"
    else:
        # Store weak signals but DON'T classify as container
        art.container_has_marker_file = has_docker_env
        art.container_cgroup_match = cgroup_matches
        if docker_socket_exists:
            art.docker_socket_found = True
            art.notes.append("DOCKER_SOCKET_DETECTED_NO_DOCKERENV")
        runtime = None

    art.container_runtime = runtime
    if indicators:
        art.notes.extend(indicators)


def gather_cloud_probing(art: ArtifactCollection) -> None:
    """Probe cloud provider metadata endpoints (non-destructive)."""
    results = {}

    for provider, config in CLOUD_METADATA_ENDPOINTS.items():
        url = config["url"]
        timeout_ms = config["timeout_ms"]
        headers = config.get("headers", {})

        reachable = False
        latency_ms = None
        response_status = None

        try:
            if HAS_REQUESTS:
                t0 = time.perf_counter()
                resp = requests.head(url, headers=headers, timeout=timeout_ms / 1000)
                latency_ms = (time.perf_counter() - t0) * 1000
                reachable = resp.status_code == 200
                response_status = resp.status_code
            else:
                # Socket-based probe fallback
                parsed_url = url.replace("http://", "").split("/")
                host = parsed_url[0]

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_ms / 1000)
                t0 = time.perf_counter()

                conn_result = s.connect_ex((host, 80))
                latency_ms = (time.perf_counter() - t0) * 1000

                if conn_result == 0:
                    reachable = True
                    response_status = 200
                else:
                    response_status = conn_result

                s.close()

        except Exception as e:
            response_status = str(e)

        results[provider] = {
            "reachable": reachable,
            "latency_ms": latency_ms,
            "response_status": response_status,
        }

        if reachable:
            art.cloud_provider = provider
            break

    art.cloud_metadata_reachable = results


def gather_instruction_timing_advanced(art: ArtifactCollection) -> None:
    """Improved timing measurement focusing on privileged op overhead."""
    samples_per_batch = 100
    num_batches = 10

    batch_times = []

    for _batch_idx in range(num_batches):
        batch_start = time.perf_counter_ns()

        # Multiple iterations increase hypervisor overhead signal
        for _i in range(samples_per_batch):
            # Use a loop that triggers different behaviors
            _ = sum(range(50))

        batch_end = time.perf_counter_ns()
        batch_times.append(batch_end - batch_start)

    avg_time = sum(batch_times) / len(batch_times)
    std_dev = (sum((t - avg_time)**2 for t in batch_times) / len(batch_times)) ** 0.5

    # Real bare metal batches: ~200-500μs per batch
    # Hypervisor batches: ~2-10ms per batch
    med_time = sorted(batch_times)[len(batch_times)//2]

    art.instruction_timing = {
        "samples_total": samples_per_batch * num_batches,
        "batch_avg_us": avg_time / 1000,
        "batch_median_us": med_time / 1000,
        "batch_std_dev_us": std_dev / 1000,
        "suspicious_timing": med_time > 5000,  # >1ms per batch suggests VM
        "timing_variance_high": std_dev / avg_time > 0.5 if avg_time > 0 else False,
        "baseline_comparison": f"{med_time / 1000:.2f} μs/batch"  # Diagnostic
    }


def gather_nested_virtualization(art: ArtifactCollection) -> None:
    """Detect signs of nested virtualization layers."""
    signals = []

    # Check if VT-x/AMD-V advertised inside guest (outer layer exists)
    if platform.system() == "Linux":
        cpu_flags = _safe_read_text("/proc/cpuinfo") or ""
        if "vmx" in cpu_flags.lower() or "svm" in cpu_flags.lower():
            # CPU has virtualization extensions exposed TO guest
            signals.append("virtualization_extensions_visible_in_guest")

    # High instruction timing variance suggests nesting overhead
    if art.instruction_timing.get("timing_variance_high"):
        signals.append("high_timing_variance_nested_signal")

    # VirtIO devices indicate virtual infrastructure underneath
    virtio_indicators = ["virtio", "1af4"]
    for vendor in art.pci_vendors or []:
        if any(v in vendor.lower() for v in virtio_indicators):
            signals.append("virtio_device_detected")
            break

    art.nested_virtualization = {
        "likely_nested": len(signals) >= 2,
        "signal_count": len(signals),
        "signals": signals,
    }


def gather_hardware_quirks(art: ArtifactCollection) -> None:
    """Identify hardware characteristics typical of physical vs virtual systems."""
    quirks = []

    # Battery check
    if platform.system() == "Windows":
        out = run(["powershell", "-NoProfile", "-Command",
                   "(Get-WmiObject -Class Win32_Battery | Measure-Object).Count"])
        if out.strip() == "0":
            # Desktop PCs also lack batteries! Context matters.
            battery_status = "desktop_or_vm"
    elif platform.system() == "Linux":
        if os.path.exists("/sys/class/power_supply/BAT0"):
            battery_status = "present"
        else:
            battery_status = "absent_desktop_or_vm"
    else:
        battery_status = "unknown"

    # SMBIOS serial validation
    if platform.system() == "Linux" and shutil_which("dmidecode"):
        serial = run(["dmidecode", "-s", "system-serial-number"]).strip()
        dummy_serials = ["0", "None", "To Be Filled By O.E.M.", "Default string", "Unknown"]
        if serial in dummy_serials:
            quirks.append(f"dummy_serial:{serial}")

    # RAM configuration analysis
    if psutil:
        mem = psutil.virtual_memory()
        total_gb = mem.total / (1024**3)
        # Round numbers suggest default VM allocations
        rounded_sizes = [2, 4, 6, 8, 12, 16, 24, 32, 48, 64]
        closest = min(rounded_sizes, key=lambda x: abs(total_gb - x))
        if abs(total_gb - closest) < 0.3:
            quirks.append(f"rounded_ram_size:{total_gb:.1f}GB")

    # Boot loader identification
    if platform.system() == "Linux":
        grub_cfg = _safe_read_text("/boot/grub/grub.cfg") or ""
        if "kvm" in grub_cfg.lower() or "qemu" in grub_cfg.lower():
            quirks.append("grub_config_reference")

    art.hardware_quirks = quirks


def gather_uptime_check(art: ArtifactCollection) -> None:
    """Calculate system uptime, low uptime may indicate sandbox/analysis env."""
    try:
        if psutil:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_hours = uptime_seconds / 3600

            art.uptime = {
                "hours": uptime_hours,
                "seconds": uptime_seconds,
                "reboot_timestamp": boot_time,
                "suspiciously_recent": uptime_hours < 2,  # Increased from 1hr
            }
    except Exception:
        pass


def gather_gpu_detection(art: ArtifactCollection) -> None:
    """Detect GPU drivers and virtual graphics adapters."""
    gpu_info = []
    vm_gpu_detected = False

    if platform.system() == "Windows":
        out = run(["wmic", "path", "win32_VideoController", "get", "name"])
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line:
                gpu_info.append(line)
                vm_gpu_keywords = ["qxl", "vmsvga", "virtio", "vboxvideo", "cirrus"]
                if any(kw in line.lower() for kw in vm_gpu_keywords):
                    vm_gpu_detected = True

    elif platform.system() == "Linux":
        if shutil_which("lspci"):
            out = run(["lspci", "-v"])
            for line in out.splitlines():
                if "VGA" in line or "3D" in line:
                    gpu_info.append(line)
                    vm_gpu_keywords = ["qxl", "vmsvga", "virtio", "vboxvideo", "cirrus"]
                    if any(kw in line.lower() for kw in vm_gpu_keywords):
                        vm_gpu_detected = True

                    # Also detect NVIDIA/AMD passthrough scenarios
                    if "nvidia" in line.lower() or "amd" in line.lower():
                        gpu_info.append("GPU_passthrough_candidate:" + line[:50])

    art.gpu_info = {
        "adapters": gpu_info,
        "vm_gpu": vm_gpu_detected,
        "passthrough_candidates": any("passthrough_candidate" in g for g in gpu_info),
    }


def gather_filesystem_artifacts_extended(art: ArtifactCollection) -> None:
    """Extended filesystem checks for VM artifacts."""
    vm_paths = []

    # Non exhaustive list, expandable
    if platform.system() == "Windows":
        check_paths = [
            "C:\\Program Files\\VMware",
            "C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
            "C:\\Program Files\\Tools\\Guest Tools",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\Drivers\\VBoxSF.sys",
            "C:\\windows\\潘顿\\vmusr.bin",  # VMware shared folder cache
        ]
        # Registry keys (check via wmic/powershell alternative)
    else:  # Linux
        check_paths = [
            "/dev/vda",
            "/dev/vdb",
            "/dev/vdc",
            "/dev/xvda",
            "/dev/xvdb",
            "/sys/bus/vmbus",
            "/proc/xen",
            "/proc/vz",
            "/var/lib/qemu-agent",
            "/opt/google/chrome/browser/.google/update-client",
        ]

    for path in check_paths:
        if os.path.exists(path):
            vm_paths.append(path)

    art.filesystem_artifacts = vm_paths


# ============================================================
# Scoring Engine with Tiered Weights v2.0
# ============================================================

class Detector:
    def __init__(self):
        self.art = ArtifactCollection()
        self.container_has_marker_file = False
        self.container_cgroup_match = False
        self.docker_socket_found: bool = False

    def gather_all_sequential(self) -> ArtifactCollection:
        """Original sequential method."""
        gather_cpu_vendor_with_cpuid(self.art)
        gather_pci(self.art)
        gather_acpi_tables(self.art)
        gather_bios_system(self.art)
        gather_processes(self.art)
        gather_mac_prefixes(self.art)
        gather_disk_vendors(self.art)
        gather_interrupt_behavior(self.art)
        gather_entropy_behavior(self.art)
        gather_cpu_topology(self.art)
        gather_instruction_timing_advanced(self.art)
        gather_container_detection(self.art)
        gather_cloud_probing(self.art)
        gather_memory_patterns(self.art)
        gather_filesystem_artifacts_extended(self.art)
        gather_hardware_quirks(self.art)
        gather_gpu_detection(self.art)
        gather_uptime_check(self.art)
        gather_nested_virtualization(self.art)

        self._normalize()
        return self.art

    def gather_all_parallel(self, worker_threads: int = 6) -> ArtifactCollection:
        """Concurrent gatherer execution for performance."""
        # Independent gatherers (parallel-safe)
        parallel_gatherers = [
            ("pci", gather_pci),
            ("acpi", gather_acpi_tables),
            ("mac", gather_mac_prefixes),
            ("disk", gather_disk_vendors),
            ("gpu", gather_gpu_detection),
            ("filesystem", gather_filesystem_artifacts_extended),
            ("quirks", gather_hardware_quirks),
            ("cloud", gather_cloud_probing),
            ("uptime", gather_uptime_check),
            ("container", gather_container_detection),
        ]

        with ThreadPoolExecutor(max_workers=worker_threads) as executor:
            futures = {executor.submit(g, self.art): name for name, g in parallel_gatherers}
            completed = []
            failed = []

            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    completed.append(name)
                except Exception as e:
                    failed.append((name, str(e)))

        # Sequential-dependent gatherers stay sequential (they need earlier data)
        gather_cpu_vendor_with_cpuid(self.art)
        gather_bios_system(self.art)
        gather_processes(self.art)
        gather_interrupt_behavior(self.art)
        gather_entropy_behavior(self.art)
        gather_cpu_topology(self.art)
        gather_instruction_timing_advanced(self.art)
        gather_memory_patterns(self.art)
        gather_nested_virtualization(self.art)

        if failed:
            self.art.notes.append(f"Gatherers failed: {len(failed)}")
            for name, err in failed:
                self.art.notes.append(f"  - {name}: {err[:50]}")

        self._normalize()
        return self.art

    def _normalize(self) -> None:
        """Sanitize and normalize collected artifact data."""
        try:
            self.art.pci_vendors = sorted({_clean_hex(x) for x in (self.art.pci_vendors or []) if x})
            self.art.pci_devices = sorted({_clean_hex(x) for x in (self.art.pci_devices or []) if x})
        except Exception:
            self.art.pci_vendors = self.art.pci_vendors or []
            self.art.pci_devices = self.art.pci_devices or []
        self.art.mac_prefixes = sorted({m.upper() for m in (self.art.mac_prefixes or []) if m})
        self.art.processes = sorted({p.lower() for p in (self.art.processes or []) if p})
        self.art.acpi_tables = sorted({t for t in (self.art.acpi_tables or []) if t})
        self.art.acpi_signatures = sorted({s for s in (self.art.acpi_signatures or []) if s})
        self.art.disk_vendors = sorted({d.lower() for d in (self.art.disk_vendors or []) if d})


    def score(self, art: Optional[ArtifactCollection] = None,
              sandbox: Optional[Dict[str, Any]] = None,
              explain: bool = False) -> Dict[str, Any]:
        """
        Calculate VM probability scores using tiered confidence weighting.
        Tier weights: hard evidence (1.0x), medium confidence (0.6x), soft heuristics (0.3x)
        """
        if art is None:
            art = self.art

        platforms = list(VM_PCI_VENDORS.keys())
        scores: Dict[str, float] = {p: 0.0 for p in platforms}
        explain_map: Dict[str, List[str]] = {p: [] for p in platforms}

        # ===== TIER 1: HARD EVIDENCE (Weight: 1.0x) =====
        # PCI vendor/device IDs, CPUID signatures, MAC prefixes - extremely hard to spoof

        # Hard vendor matches from primary table
        for vm, vids in VM_PCI_VENDORS.items():
            for vid in vids:
                if vid.upper().replace("0x", "") in (v.upper().replace("0x", "") for v in (art.pci_vendors or [])):
                    scores[vm] += 60 * 1.0
                    explain_map[vm].append(f"[T1-HARD] PCI vendor {vid}")

        # Expanded vendor/device table
        for vm, table in VM_PCI_SIGNATURES.items():
            for v in (art.pci_vendors or []):
                v_clean = v.replace("0x", "").upper()
                if v_clean in table.get("vendors", set()):
                    scores.setdefault(vm, 0.0)
                    scores[vm] += 30 * 1.0
                    explain_map.setdefault(vm, []).append(f"[T1-HARD] Expanded vendor {v_clean}")
            for d in (art.pci_devices or []):
                d_clean = d.replace("0x", "").upper()
                if d_clean in table.get("devices", set()):
                    scores.setdefault(vm, 0.0)
                    scores[vm] += 20 * 1.0
                    explain_map.setdefault(vm, []).append(f"[T1-HARD] Device {d_clean}")

        # CPUID hypervisor signature (direct CPUID access preferred)
        if art.cpuid_signature:
            for vm, sig in VM_CPUID_SIGS.items():
                if sig.lower() in (art.cpuid_signature or "").lower():
                    scores[vm] = scores.get(vm, 0.0) + 40 * 1.0
                    explain_map[vm] = explain_map.get(vm, []) + [f"[T1-HARD] CPUID '{sig}'"]

        # Direct CPUID leaf 0 vendor check (unforgeable if direct mode)
        if art.direct_cpuid_available and art.cpuid_leaf_0:
            leaf0 = art.cpuid_leaf_0
            vendor_bytes = (leaf0[1]).to_bytes(4, 'little') + \
                        (leaf0[3]).to_bytes(4, 'little') + \
                        (leaf0[2]).to_bytes(4, 'little')
            vendor_str = vendor_bytes.decode('ascii', errors='ignore').rstrip('\x00').lower()

            # Comprehensive vendor string matching for ALL hypervisors (NOT just KVM/Hyper-V!)
            hypervisor_mappings = {
                "qemu": "QEMU/KVM",
                "kvm": "QEMU/KVM",
                "microsoft hv": "Hyper-V",
                "vmware": "VMware",
                "virtualbox": "VirtualBox",
                "oracle": "VirtualBox",
                "xenvmm": "Xen",
                "tcgtcgtcg": "QEMU/TCG",
                "prlvmm": "Parallels",
            }

            matches_found = []
            for partial_match, target_vm in hypervisor_mappings.items():
                if partial_match in vendor_str:
                    scores[target_vm] = scores.get(target_vm, 0.0) + 35 * 1.0
                    matches_found.append((partial_match, target_vm))
                    explain_map.setdefault(target_vm, []).append(f"[T1-DIRECT] CPUID vendor '{vendor_str}' → {target_vm}")

            if matches_found:
                art.notes.append(f"[CPUID] Found {len(matches_found)} vendor match(es): {matches_found}")
            else:
                # Unknown vendor detected - log for analysis but don't penalize
                art.notes.append(f"[CPUID] Unknown vendor string: '{vendor_str}'")

        # ACPI signatures (hard to fake without kernel-level changes)
        for sig in (art.acpi_signatures or []):
            for vm in platforms:
                if vm.lower().split("/")[0] in sig.lower():
                    scores[vm] += 15 * 1.0
                    explain_map.setdefault(vm, []).append(f"[T1-HARD] ACPI sig {sig}")

        # MAC OUI prefix match (burned into virtual NIC config, rarely spoofed consistently)
        for vm, prefs in MAC_PREFIXES.items():
            for pref in prefs:
                if any(pref.upper() in m.upper() for m in (art.mac_prefixes or [])):
                    scores[vm] += 10 * 1.0
                    explain_map.setdefault(vm, []).append("[T1-HARD] MAC prefix")
                    break

        # ===== TIER 2: MEDIUM CONFIDENCE (Weight: 0.6x) =====
        # BIOS strings, disk vendors, process names, GPU info - moderately spoofable

        # BIOS keywords
        for vm, kv in VM_SOFT_KEYWORDS.items():
            for kw in kv.get("bios", []):
                if art.bios_vendor and kw.lower() in art.bios_vendor.lower():
                    scores[vm] += 20 * 0.6
                    explain_map.setdefault(vm, []).append(f"[T2-MED] BIOS contains '{kw}'")

        if art.bios_brand and art.bios_brand in scores:
            scores[art.bios_brand] += 25 * 0.6
            explain_map.setdefault(art.bios_brand, []).append("[T2-MED] Normalized BIOS brand")

        # Disk vendor indicators
        for dv in (art.disk_vendors or []):
            dvl = dv.lower()
            for vm, subs in VM_DISK_VENDORS.items():
                for sub in subs:
                    if sub.lower() in dvl:
                        scores[vm] += 15 * 0.6
                        explain_map.setdefault(vm, []).append(f"[T2-MED] Disk vendor '{dv}'")
                        break

        # Processes running
        for vm, kv in VM_SOFT_KEYWORDS.items():
            for pk in kv.get("process", []):
                if any(pk.lower() in p.lower() for p in art.processes):
                    scores[vm] += 15 * 0.6
                    explain_map.setdefault(vm, []).append(f"[T2-MED] Process '{pk}' present")

        # System product string matching
        if platform.system() == "Windows" and art.system_product:
            mfg = (art.system_product or "").lower()
            if "qemu" in mfg or "kvm" in mfg:
                scores["QEMU/KVM"] += 50 * 0.6
                explain_map.setdefault("QEMU/KVM", []).append("[T2-MED] System->QEMU/KVM")
            elif "vmware" in mfg:
                scores["VMware"] += 50 * 0.6
                explain_map.setdefault("VMware", []).append("[T2-MED] System->VMware")
            elif "virtualbox" in mfg:
                scores["VirtualBox"] += 50 * 0.6
                explain_map.setdefault("VirtualBox", []).append("[T2-MED] System->VirtualBox")
            elif "microsoft" in mfg:
                scores["Hyper-V"] += 50 * 0.6
                explain_map.setdefault("Hyper-V", []).append("[T2-MED] System->Microsoft/Hyper-V")

        # Virtualized GPU detected
        if art.gpu_info.get("vm_gpu"):
            for vm in ["VirtualBox", "VMware", "QEMU/KVM"]:
                scores[vm] += 20 * 0.6
                explain_map.setdefault(vm, []).append("[T2-MED] Virtual GPU detected")

        # ===== TIER 3: SOFT HEURISTICS (Weight: 0.3x) =====
        # Timing patterns, memory sizing, uptime quirks - easiest to manipulate

        if art.entropy_behavior.get("low_variance"):
            # Distribute minimal consistent weight across ALL hypervisor types
            # Each gets only 0.3-0.6 points total to prevent false positive dominance
            for vm in ["QEMU/KVM", "VirtualBox", "VMware", "Hyper-V", "Xen", "Parallels"]:
                if not explain_map.get(vm):  # Only add once to first VM checked
                    explain_map[vm].append("[T3-WEAK] Low entropy variance (very minor)")
                scores[vm] += 2 * 0.15  # Extremely low weight = 0.3 pts per VM type

            # Add diagnostic note about actual values
            eb = art.entropy_behavior
            variance_ns = eb.get("variance_ns", 0)
            median_ns = eb.get("median_ns", 0)
            ratio = eb.get("variance_ratio", 0)
            if variance_ns > 200000:  # Even moderate variance worth noting
                art.notes.append(f"[DIAG] Entropy variance {variance_ns:,}ns (median {median_ns:,}ns)")

        # Hypervisor flag presence
        if art.hypervisor_flag:
            for vm in scores:
                scores[vm] += 10 * 0.3
                explain_map.setdefault(vm, []).append("[T3-SOFT] Hypervisor flag present")

        # Container runtime detected
        if art.container_runtime:
            # Containers aren't VMs per se but are isolated environments
            scores["_CONTAINER_"] = 80
            explain_map.setdefault("_CONTAINER_", []).append(
                f"[INFO] Running in container: {art.container_runtime}"
            )

        # Cloud provider detected
        if art.cloud_provider:
            scores[f"_CLOUD_{art.cloud_provider}_"] = 70
            explain_map.setdefault(f"_CLOUD_{art.cloud_provider}_", []).append(
                f"[INFO] Detected cloud infrastructure: {art.cloud_provider}"
            )

        # Suspicious CPU topology ratio
        if art.cpu_topology.get("suspicious_ratio"):
            for vm in scores:
                scores[vm] += 15 * 0.3
                explain_map.setdefault(vm, []).append("[T3-SOFT] Thread/core ratio suspicious")

        # Odd thread count
        if art.cpu_topology.get("odd_thread_count"):
            for vm in scores:
                scores[vm] += 12 * 0.3
                explain_map.setdefault(vm, []).append("[T3-SOFT] Odd thread count")

        # Rounded RAM size (typical VM defaults)
        if "rounded_ram_size:" in str(art.hardware_quirks):
            for vm in scores:
                scores[vm] += 10 * 0.3
                explain_map.setdefault(vm, []).append("[T3-SOFT] Standardized RAM allocation")

        # Low USB device count
        for quirk in (art.hardware_quirks or []):
            if "low_usb_count" in quirk:
                for vm in scores:
                    scores[vm] += 8 * 0.3
                    explain_map.setdefault(vm, []).append("[T3-SOFT] Minimal USB devices")

        # Recent boot/uptime
        if art.uptime.get("suspiciously_recent"):
            for vm in scores:
                scores[vm] += 10 * 0.3
                explain_map.setdefault(vm, []).append(
                    "[T3-SOFT] Recent boot ({} hrs)".format(art.uptime.get("hours", 0))
                )

        # High instruction timing (possible VM exit overhead)
        if art.instruction_timing.get("suspicious_timing"):
            for vm in scores:
                 if not explain_map.get(vm):
                    explain_map[vm].append("[T3-WEAK] Instruction timing elevated (minor)")
                 scores[vm] += 5 * 0.10  # Extremely reduced: 0.5 pts per VM type
            it = art.instruction_timing
            art.notes.append(f"[DIAG] Instruction timing: {it.get('batch_median_us'):.2f}μs/batch")

        # Interrupt jitter low (too consistent - VM scheduling behavior)
        if art.interrupt_behavior.get("low_jitter"):
            for vm in scores:
                scores[vm] += 6 * 0.15
                explain_map.setdefault(vm, []).append("[T3-WEAK] Elevated timing (considered)")

        # Dummy serial number / SMBIOS artifacts
        for quirk in (art.hardware_quirks or []):
            if "dummy_serial" in quirk:
                for vm in scores:
                    scores[vm] += 6 * 0.3
                    explain_map.setdefault(vm, []).append("[T3-SOFT] Placeholder SMBIOS data")

        # Nested virtualization indicators
        if art.nested_virtualization.get("likely_nested"):
            for vm in scores:
                scores[vm] += 20 * 0.3
                explain_map.setdefault(vm, []).append(
                    "[INFO] Likely nested virtualization ({})".format(
                        art.nested_virtualization.get("signal_count", 0)
                    )
                )

        # ===== CAP SCORES AND INTEGRATE SANDBOX DATA =====
        cap_pct = lambda s: max(0.0, min(100.0, s))
        scores = {k: cap_pct(v) for k, v in scores.items()}

        # Apply sandbox penalty if heuristics detected
        if sandbox:
            if sandbox.get("detected"):
                # Reduce VM scores by 30% when strong sandbox/heuristic evidence exists
                for k in scores:
                    if not k.startswith("_"):  # Don't affect CONTAINER/CLOUD classifications
                        original = scores[k]
                        reduced = original - 30
                        scores[k] = max(0, reduced)
                        if explained := explain_map.get(k, []):
                            explain_map[k].append(f"[PENALTY] Sandbox heuristics (-30)")

                # But add heuristic evidence separately
                if sandbox.get("heuristics"):
                    scores["_SANDBOX_ENV_"] = len(sandbox.get("heuristics")) * 10

                if sandbox.get("debugger"):
                    for k in scores:
                        scores[k] -= 15
                        if k != "_SANDBOX_ENV_" and k != "_CONTAINER_" and not k.startswith("_CLOUD_"):
                            explain_map.setdefault(k, []).append("[DEBUGGER] Analysis tool attached")

        # Convert floats back to ints
        scores_int = {k: int(round(v)) for k, v in scores.items()}

        if explain:
            return {"scores": scores_int, "explain": explain_map}
        return {"scores": scores_int}


    def detect(self, parallel: bool = True,
               aggressive_sandbox: bool = False,
               explain: bool = True,
               timeout_sec: float = 30.0) -> Dict[str, Any]:
        """
        Run full detection pipeline.

        Args:
            parallel: Use multi-threaded gathering (recommended for speed)
            aggressive_sandbox: Exit early if sandbox detection triggers
            explain: Mentions explanations about stuff when it find things.
            timeout_sec: Maximum execution time before forced abort

        Returns:
            Detection results dictionary
        """
        start_time = time.perf_counter()
        behavior_signals: List[str] = []
        hardened_signals = 0

        # Execute gathering phase with timeout protection
        try:
            if parallel:
                art = self.gather_all_parallel(worker_threads=6)
            else:
                art = self.gather_all_sequential()

            elapsed = time.perf_counter() - start_time
            if elapsed > timeout_sec:
                art.notes.append(f"WARNING: Gathering exceeded {timeout_sec}s timeout")
        except TimeoutError:
            return {
                "error": "Timeout exceeded during artifact gathering",
                "partial_results": self.art.to_dict() if hasattr(self.art, 'to_dict') else {},
                "recommendation": "Try again with parallel=False for simpler runs"
            }

        # Run sandbox detection
        sandbox = sandbox_checks(art)

        # Score everything
        sc = self.score(art, sandbox=sandbox, explain=explain)
        scores = sc["scores"]
        explain_map = sc.get("explain", {})

        # Determine best guess
        non_special_scores = {k: v for k, v in scores.items() if not k.startswith("_")}
        best_vm = max(non_special_scores, key=lambda k: non_special_scores[k]) if non_special_scores else "Unknown"
        best_score = non_special_scores.get(best_vm, 0)

        result: Dict[str, Any] = {
            "artifacts": art.to_dict(),
            "scores": scores,
            "best_guess": best_vm if best_score >= 20 else "Unknown/Bare Metal",
            "confidence": best_score,
            "anti_analysis": sandbox,
            "scan_duration_ms": int((time.perf_counter() - start_time) * 1000),
        }
        result["explanation"] = explain_map

        # Aggressive sandbox trigger
        if aggressive_sandbox and sandbox.get("detected"):
            result["aggressive_exit"] = True
            result["sandbox_alert"] = {
                "reason": "Strong anti-analysis signals detected",
                "heuristics_count": len(sandbox.get("heuristics")),
                "details": sandbox.get("heuristics", [])[:10]  # Limit output size
            }

        # Behavioral signal aggregation for classification enhancement
        if art.interrupt_behavior.get("low_jitter"):
            hardened_signals += 1
            behavior_signals.append("Low interrupt jitter")

        if art.cpu_topology.get("suspicious_ratio"):
            hardened_signals += 1
            behavior_signals.append("CPU ratio suspicious (>6×)")

        if art.container_runtime:
            hardened_signals += 1
            behavior_signals.append(f"Container environment: {art.container_runtime}")

        if art.cloud_provider:
            hardened_signals += 1
            behavior_signals.append(f"Cloud infrastructure: {art.cloud_provider}")

        if art.instruction_timing.get("suspicious_timing"):
            hardened_signals += 1
            behavior_signals.append("Elevated instruction latency")

        # Enhanced behavioral scoring integration
        additional = enhanced_behavior_scoring(art, behavior_signals)
        hardened_signals += additional

        # Classification decision tree
        has_special_class = any(k.startswith("_") for k in scores.keys())
        special_max = max([scores[k] for k in scores if k.startswith("_")] or [0])

        classification = "Bare Metal / Unknown"

        if has_special_class and special_max > 85:
            special_types = [k for k in scores if k.startswith("_")]
            best_special = max(special_types, key=lambda k: scores[k])

            # BLOCK automatic container override unless VERY CONFIDENT
            if best_special == "_CONTAINER_":
                # Require BOTH marker file AND either cgroup OR socket evidence
                required_strength = (
                    getattr(art, 'container_has_marker_file', False) and
                    (getattr(art, 'container_cgroup_match', False) or getattr(art, 'docker_socket_found', False))
                )

                if not required_strength:
                    # Weak container detection, ignore it and fall through to VM scoring
                    has_special_class = False
                    special_max = 0
                    classification = "Bare Metal / Unknown"

            if has_special_class:  # Still valid after filtering?
                classification_map = {
                    "_CONTAINER_": "Container Environment",
                    "_SANDBOX_ENV_": "Analysis Sandboxed Environment",
                }
                for cloud in CLOUD_METADATA_ENDPOINTS.keys():
                    classification_map[f"_CLOUD_{cloud}_"] = f"Cloud Infrastructure ({cloud})"

                result["classification"] = classification_map.get(best_special, "Special Environment")
                result["special_environment"] = best_special
                result["conflicts_note"] = "Special environment classification overrides VM scoring"
            else:
                # Proceed to normal VM classification
                pass



        if not result.get("classification"):  # Not already set by special class
            if best_score >= 80:
                classification = "Confirmed VM Environment"
            elif best_score >= 50:
                classification = "Likely VM Environment"
            elif best_score >= 30:
                classification = "Possible VM Indicators"
            elif best_score >= 10 and hardened_signals >= 2:  # ← ADDED BEST_SCORE CHECK (10% minimum)
                classification = "Hardened/Stylized Virtual Environment"
            elif best_score < 30 and art.direct_cpuid_available and art.hypervisor_flag:
                classification = "Hidden VM (Direct CPUID Confirms)"
            else:
                classification = "Bare Metal / Unknown"  # Final catch-all

        result["classification"] = classification
        result["behavioral_signals"] = behavior_signals
        result["hardened_signal_count"] = hardened_signals

        # Add warnings for edge cases
        if result["scan_duration_ms"] > 25000:
            result["warning_slow_scan"] = "Detection took longer than expected - possible analysis delay tactics"

        if sandbox.get("timing_anomaly"):
            result["warning_timing_manipulation"] = "Timing anomalies suggest intentional sleep skipping"

        return result


# ============================================================
# Sandbox Analysis Heuristics v2.0
# ============================================================

def sandbox_checks(art: ArtifactCollection) -> Dict[str, Any]:
    """Comprehensive anti-analysis environment detection."""
    out: Dict[str, Any] = {
        "detected": False,
        "heuristics": [],
        "process_hits": [],
        "env_hits": [],
        "disk_hits": [],
        "system_hits": [],
        "username_hits": [],
        "hostname_hits": [],
        "debugger": False,
        "tracing_active": False,
        "timing_anomaly": False,
        "window_title_suspect": False,
    }

    # Process-based indicators (expanded list)
    expanded_procs = SANDBOX_PROCS + [
        "autoruns", "hiew", "peview", "importrec", "ollybg",
        "ida", "ghidra", "radare2", "objdump", "strace", "ltrace",
        "httpdebug", "charlesproxy", "burpsuite", "mitmproxy"
    ]

    for p in art.processes or []:
        pl = p.lower()
        for sig in expanded_procs:
            if sig in pl:
                out["process_hits"].append(p)
                out["heuristics"].append(f"Sandbox process: {p}")

    # Environment variable inspection
    suspicious_env_keys = [
        "vbox", "virtualbox", "vmware", "cuckoo", "sandbox", "qemu",
        "malware", "analysis", "debug", "hook", "inject"
    ]
    for k, v in os.environ.items():
        ku = k.upper()
        vv = str(v).upper()
        if any(s in ku for s in suspicious_env_keys):
            out["env_hits"].append(f"{k}={v[:30]}...")
            out["heuristics"].append(f"Env var suspicious: {k}")
        if any(s in vv for s in suspicious_env_keys):
            out["env_hits"].append(f"{k}={v[:30]}...")
            out["heuristics"].append(f"Env value suspicious: {k}")

    # Username / hostname heuristics (with whitelist for common test usernames)
    whitelisted_users = ["admin", "testuser", "developer", "root", "ubuntu", "ec2-user"]
    whitelisted_hosts = ["localhost", "workstation", "desktop"]

    try:
        import getpass, socket
        user = getpass.getuser().lower()
        host = socket.gethostname().lower()

        bad_user_keywords = ["sandbox", "analysis", "maltest", "cuckoo", "victim", "honeypot"]
        bad_host_keywords = ["malware", "analysis", "threat", "incident"]

        for bad in bad_user_keywords:
            if bad in user and user not in whitelisted_users:
                out["username_hits"].append(f"user={user}")
                out["heuristics"].append(f"Suspicious username: {user}")

        for bad in bad_host_keywords:
            if bad in host and host not in whitelisted_hosts:
                out["hostname_hits"].append(f"host={host}")
                out["heuristics"].append(f"Suspicious hostname: {host}")
    except Exception:
        pass

    # Disk vendor forensic traces
    for dv in art.disk_vendors or []:
        dvl = dv.lower()
        for vm, subs in VM_DISK_VENDORS.items():
            for sub in subs:
                if sub.lower() in dvl:
                    out["disk_hits"].append({"vendor": dv, "vm": vm})
                    out["heuristics"].append(f"Disk vendor indicates {vm}")

    # Window title / UI inspection (Windows only)
    if platform.system() == "Windows":
        try:
            # Attempt to read foreground window title via PowerShell
            cmd = "powershell -NoProfile -Command '(Get-Process -Id $PID | Select-Object MainWindowTitle).'MainWindowTitle'"
            title = run(["powershell", "-NoProfile", "-Command",
                         "[Console]::TreatControlCAsInput;$host.UI.RawUI.WindowTitle"]).strip()
            if "virtual" in title.lower() or "vmware" in title.lower() or "oracle" in title.lower():
                out["window_title_suspect"] = True
                out["heuristics"].append(f"Window title suggests VM: {title[:50]}")
        except Exception:
            pass

    # AC anomaly detection
    try:
        if art.system_product:
            prod_lower = art.system_product.lower()
            vm_products = ['virtualbox', 'vmware', 'qemu', 'kvm', 'hyper-v', 'xen', 'parallels']
            if any(vp in prod_lower for vp in vm_products):
                if not (art.acpi_signatures or art.direct_cpuid_available):
                    out["heuristics"].append("System product mentions VM but lacks supporting artifacts")
                    out["system_hits"].append("missing_supporting_evidence")
    except Exception:
        pass

    # Low-resource environment flags
    try:
        if psutil:
            mem = psutil.virtual_memory().total
            cpus_logical = psutil.cpu_count(logical=True)
            cpus_physical = psutil.cpu_count(logical=False) or 1

            # Very low specs suggest analysis sandbox
            if mem and mem < 2_000_000_000:  # <2GB RAM
                out["heuristics"].append(f"Low memory total: {mem // (1024**2)} MB")
            if cpus_logical and cpus_logical <= 2:
                out["heuristics"].append(f"Limited cores: {cpus_logical} logical")

            # Single NIC might indicate controlled environment
            net_ifaces = len(psutil.net_if_addrs())
            if net_ifaces <= 2:
                out["heuristics"].append(f"Minimal network interfaces: {net_ifaces}")
        else:
            cpus = os.cpu_count()
            if cpus and cpus <= 1:
                out["heuristics"].append(f"Single processor detected: {cpus}")
    except Exception:
        pass

    # Debugger attachment checks
    if hasattr(sys, "gettrace") and sys.gettrace():
        out["debugger"] = True
        out["tracing_active"] = True
        out["heuristics"].append("Python tracer/debugger active")

    # Check for remote debugging ports
    if platform.system() == "Linux":
        try:
            proc_net = _safe_read_text("/proc/net/tcp") or ""
            debug_ports = ["8965", "5005", "1234", "5555", "6789"]
            for line in proc_net.splitlines()[1:]:
                parts = line.split()
                local_addr = parts[1] if len(parts) > 1 else ""
                for port in debug_ports:
                    if f":{port.zfill(4)}" in local_addr.upper():
                        out["debugger"] = True
                        out["heuristics"].append(f"Debugging port open: {port}")
        except Exception:
            pass

    # Sleep timing validation
    try:
        test_sleep_times = [0.050, 0.100, 0.150, 0.200]
        for target in test_sleep_times:
            start = time.perf_counter()
            time.sleep(target)
            actual = time.perf_counter() - start

            # Allowing generous tolerance for slow systems
            if actual < target * 0.7:  # Less than 70% of requested time
                out["timing_anomaly"] = True
                out["heuristics"].append(f"Sleep executed too fast: {actual:.3f}s vs {target}s")
                break
    except Exception:
        pass

    # Final aggregated decision
    hits = (len(out["heuristics"]) + len(out["process_hits"]) +
            len(out["env_hits"]) + len(out["disk_hits"]) + len(out["system_hits"]))

    # Trigger detection if debugger/timing anomalies OR multiple heuristics
    if out["debugger"] or out["timing_anomaly"] or hits >= 3:
        out["detected"] = True

    # Confidence level
    if out["detected"]:
        if hits >= 10 or out["debugger"]:
            out["confidence"] = "HIGH"
        elif hits >= 5:
            out["confidence"] = "MEDIUM"
        else:
            out["confidence"] = "LOW"

    return out



def enhanced_behavior_scoring(art: ArtifactCollection, behavior_signals: List[str]) -> int:
    """Aggregate additional behavioral signals for classification enhancement."""
    additional_signals = 0

    if art.cache_behavior and art.cache_behavior.get("suspicious"):
        additional_signals += 1
        behavior_signals.append("Cache timing patterns suggest VM")

    if art.instruction_timing and art.instruction_timing.get("too_consistent"):
        additional_signals += 1
        behavior_signals.append("Instruction timing too consistent (VM-like)")

    if art.memory_patterns and art.memory_patterns.get("exact_vm_size"):
        additional_signals += 1
        behavior_signals.append(f"Memory size matches common VM default ({art.memory_patterns.get('total_gb'):.1f} GB)")

    if art.filesystem_artifacts:
        additional_signals += 1
        behavior_signals.append(f"VM filesystem artifacts: {len(art.filesystem_artifacts)} found")

    if art.hardware_quirks:
        for quirk in art.hardware_quirks:
            if quirk != "no_battery_detected":  # Ignore laptops
                additional_signals += 1
                behavior_signals.append(f"Hardware quirk: {quirk}")

    if art.network_latency and art.network_latency.get("suspiciously_fast"):
        additional_signals += 1
        behavior_signals.append("Network latency suspiciously fast")

    if art.gpu_info and art.gpu_info.get("vm_gpu"):
        additional_signals += 1
        behavior_signals.append("Virtualized GPU detected")

    if art.uptime and art.uptime.get("suspiciously_recent"):
        additional_signals += 1
        behavior_signals.append(f"System uptime very recent ({art.uptime.get('hours'):.1f} hours)")

    return additional_signals




# ============================================================
# Memory Pattern Gathering
# ============================================================

def gather_memory_patterns(art: ArtifactCollection) -> None:
    """Analyze memory configuration for VM-specific patterns."""
    try:
        if psutil:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()

            total_gb = mem.total / (1024**3)
            available_mb = mem.available / (1024**2)

            # Check for exact power-of-two allocations (common in VM configs)
            power_of_two_gb = [1, 2, 4, 8, 16, 32, 64, 128, 256]
            closest = min(power_of_two_gb, key=lambda x: abs(total_gb - x))
            is_power_of_two = abs(total_gb - closest) < 0.5

            # Typical VM page sizes
            large_pages = [4096, 2048*1024, 1024*1024*1024]  # 4KB, 2MB, 1GB

            art.memory_patterns = {
                "total_gb": round(total_gb, 2),
                "power_of_two_allocation": is_power_of_two,
                "closest_standard": f"{closest} GB" if is_power_of_two else "non-standard",
                "swap_present": swap.total > 0,
                "swap_enabled": psutil.swap_memory().percent > 0,
                "available_percent": round(mem.available / mem.total * 100, 2),
                "ram_usage_ratio": round((mem.total - mem.available) / mem.total, 4) if mem.total > 0 else 0,
            }
        else:
            art.memory_patterns = {"error": "psutil unavailable"}
    except Exception as e:
        art.memory_patterns = {"error": str(e)[:50]}


# ============================================================
# Helper Functions & Constants Export
# ============================================================

__all__ = [
    "Detector", "ArtifactCollection", "sandbox_checks",
    "gather_cpu_vendor_with_cpuid", "gather_pci", "gather_mac_prefixes",
    "gather_processes", "detect_container_runtime", "probe_cloud_metadata",
    "VM_PCI_VENDORS", "MAC_PREFIXES", "VM_CPUID_SIGS", "CLOUD_METADATA_ENDPOINTS"
]


# ============================================================
# Demo Usage (Run as standalone)
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("VM DETECTION ENGINE v2.0 - Educational Research Tool")
    print("=" * 60)
    print(f"\nStarting scan... (This may take 5-30 seconds)\n")

    detector = Detector()

    # Full diagnostic scan with detailed explanation
    result = detector.detect(parallel=True, aggressive_sandbox=False, explain=True)

    print("\n" + "=" * 60)
    print("DETECTION RESULTS")
    print("=" * 60)

    print(f"\nClassification: {result['classification']}")
    print(f"Confidence Score: {result['confidence']}%")
    print(f"Best Guess: {result['best_guess']}")
    print(f"Scan Duration: {result['scan_duration_ms']}ms")

    if result.get("behavioral_signals"):
        print(f"\nBehavioral Signals ({len(result['behavioral_signals'])}):")
        for i, signal in enumerate(result['behavioral_signals'], 1):
            print(f"  {i}. {signal}")

    print("\n--- Score Breakdown ---")
    for env_type, score in sorted(result['scores'].items(), key=lambda x: -x[1]):
        if score > 0:
            marker = "⚠️  " if score > 50 else "📋 " if score > 20 else "ℹ️  "
            print(f"{marker} {env_type}: {score}%")
            if result.get('explanation', {}).get(env_type):
                for hint in result['explanation'][env_type][:3]:
                    print(f"      └─ {hint}")

    if result.get("anti_analysis", {}).get("detected"):
        print("\n⚠️  ANTI-ANALYSIS ENVIRONMENT DETECTED!")
        au = result["anti_analysis"]
        print(f"   Confidence: {au.get('confidence')}")
        print(f"   Hits: {len(au.get('heuristics'), [])}")

    print("\n" + "=" * 60)
    print("Export JSON: Import Detector, call .detect(explain=True).to_json()")
    print("=" * 60)
