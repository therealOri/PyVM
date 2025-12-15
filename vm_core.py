"""
vm_core.py

Core VM detection library (importable)
Targets Python 3.12+

__Author__ = therealOri
"""

from __future__ import annotations
import os
import platform
import subprocess
import sys
import re
from typing import Dict, List, Set, Optional, Any
import time


try:
    import psutil
except Exception:
    psutil = None

# For Windows-only registry stuff
if platform.system() == "Windows":
    try:
        import winreg
    except Exception:
        winreg = None







# ---------------------------
# Signatures & Config
# ---------------------------

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
    "ollydbg", "x64dbg", "x32dbg", "wireshark", "procexp", "procmon"
]




# ---------------------------
# Utilities & Help
# ---------------------------

def run(cmd: List[str], *, text: bool = True) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=text) or ""
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










# ---------------------------
# Artifact container
# ---------------------------

class ArtifactCollection:
    def __init__(self) -> None:
        self.cpu_vendor: Optional[str] = None
        self.hypervisor_flag: bool = False
        self.pci_vendors: List[str] = []
        self.pci_devices: List[str] = []
        self.acpi_tables: List[str] = []
        self.acpi_signatures: List[str] = []
        self.cpuid_signature: Optional[str] = None
        self.bios_vendor: Optional[str] = None
        self.bios_brand: Optional[str] = None
        self.system_product: Optional[str] = None
        self.processes: List[str] = []
        self.mac_prefixes: List[str] = []
        self.disk_vendors: List[str] = []
        self.notes: List[str] = []
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


    def to_dict(self) -> Dict[str, Any]:
        return {
            "cpu_vendor": self.cpu_vendor,
            "hypervisor_flag": self.hypervisor_flag,
            "pci_vendors": self.pci_vendors,
            "pci_devices": self.pci_devices,
            "acpi_tables": self.acpi_tables,
            "acpi_signatures": self.acpi_signatures,
            "cpuid_signature": self.cpuid_signature,
            "bios_vendor": self.bios_vendor,
            "bios_brand": self.bios_brand,
            "system_product": self.system_product,
            "processes": self.processes,
            "mac_prefixes": self.mac_prefixes,
            "disk_vendors": self.disk_vendors,
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





# -----------------
# Gatherers
# -----------------
# > Where we stick our grubby little paws into the system.

def gather_interrupt_behavior(art: ArtifactCollection) -> None:
    deltas = []
    for _ in range(1000):
        t0 = time.perf_counter()
        time.sleep(0)
        deltas.append(time.perf_counter() - t0)

    jitter = max(deltas) - min(deltas)
    art.interrupt_behavior = {
        "samples": len(deltas),
        "jitter": jitter,
        "low_jitter": jitter < 1e-5,
    }



def gather_entropy_behavior(art: ArtifactCollection) -> None:
    timings = []
    for _ in range(512):
        t0 = time.perf_counter()
        os.urandom(64)
        timings.append(time.perf_counter() - t0)

    variance = max(timings) - min(timings)
    art.entropy_behavior = {
        "samples": len(timings),
        "variance": variance,
        "low_variance": variance < 1e-6,
    }



def gather_cpu_topology(art: ArtifactCollection) -> None:
    topo = {}
    try:
        if psutil:
            topo["logical"] = psutil.cpu_count(logical=True)
            topo["physical"] = psutil.cpu_count(logical=False)
        else:
            topo["logical"] = os.cpu_count()
            topo["physical"] = None

        if topo.get("physical") and topo.get("logical"):
            topo["suspicious_ratio"] = topo["logical"] / topo["physical"] > 4
    except Exception:
        pass

    art.cpu_topology = topo



def gather_cpu_vendor(art: ArtifactCollection) -> None:
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
        hv = run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent"])
        if hv and hv.strip().lower() in ("true", "1"):
            art.hypervisor_flag = True



def gather_pci(art: ArtifactCollection) -> None:
    vendors: Set[str] = set()
    devices: Set[str] = set()
    system = platform.system()
    if system == "Linux":
        base = "/sys/bus/pci/devices/"
        if os.path.isdir(base):
            for dev in os.listdir(base):
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
                    for i in range(count):
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
    if platform.system() == "Linux":
        path = "/sys/firmware/acpi/tables/"
        if os.path.isdir(path):
            try:
                tables = [f.strip() for f in os.listdir(path) if f]
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



def gather_cpuid_signature(art: ArtifactCollection) -> None:
    if platform.system() == "Linux":
        out = run(["lscpu"])
        m = re.search(r"Hypervisor vendor:\s*(.+)", out)
        if m:
            art.cpuid_signature = m.group(1).strip()
    elif platform.system() == "Windows":
        out = run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_Processor).Manufacturer"])
        if out:
            art.cpuid_signature = out.strip()



def gather_bios_system(art: ArtifactCollection) -> None:
    system = platform.system()
    if system == "Linux":
        if shutil_which("dmidecode"):
            man = run(["dmidecode", "-s", "system-manufacturer"]) or ""
            prod = run(["dmidecode", "-s", "system-product-name"]) or ""
            art.bios_vendor = man.strip() or art.bios_vendor
            art.system_product = prod.strip() or art.system_product
        else:
            base = "/sys/class/dmi/id"
            if os.path.isdir(base):
                sv = _safe_read_text(os.path.join(base, "sys_vendor")) or ""
                pn = _safe_read_text(os.path.join(base, "product_name")) or ""
                art.bios_vendor = sv.strip() or art.bios_vendor
                art.system_product = pn.strip() or art.system_product

    elif system == "Windows":
        #out = run(["wmic", "bios", "get", "Manufacturer"]) or ""
        out = run(["wmic", "bios", "get", "Manufacturer", "/value"])
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) >= 2:
            art.bios_vendor = lines[1]
        out2 = run(["wmic", "computersystem", "get", "Manufacturer,Model", "/value"]) or ""
        lines2 = [l.strip() for l in out2.splitlines() if l.strip()]
        if len(lines2) >= 2:
            art.system_product = lines2[1]

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



def gather_processes(art: ArtifactCollection) -> None:
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



def gather_cpu_cache_behavior(art: ArtifactCollection) -> None:
    data = bytearray(1024 * 1024)  # 1MB
    timings = []

    for _ in range(100):
        t0 = time.perf_counter()
        # Force cache miss by accessing random locations
        for i in range(0, len(data), 4096):
            data[i] = (data[i] + 1) % 256
        timings.append(time.perf_counter() - t0)

    avg = sum(timings) / len(timings)
    variance = max(timings) - min(timings)

    art.cache_behavior = {
        "avg_time": avg,
        "variance": variance,
        "suspicious": variance > avg * 2  # High variance suggests VM
    }



def gather_instruction_timing(art: ArtifactCollection) -> None:
    rdtsc_timings = []
    for _ in range(1000):
        t0 = time.perf_counter()
        # Simulate an expensive operation
        _ = sum(range(100))
        rdtsc_timings.append(time.perf_counter() - t0)

    # VMs happen to show more consistent (less noisy) timings often
    std_dev = (sum((x - sum(rdtsc_timings)/len(rdtsc_timings))**2 for x in rdtsc_timings) / len(rdtsc_timings)) ** 0.5

    art.instruction_timing = {
        "samples": len(rdtsc_timings),
        "std_dev": std_dev,
        "too_consistent": std_dev < 1e-7  # Suspiciously consistent
    }



def gather_memory_patterns(art: ArtifactCollection) -> None:
    try:
        if psutil:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Check for unusual memory configurations
            total_gb = mem.total / (1024**3)

            suspicious_sizes = [
                2.0, 4.0, 8.0, 16.0, 32.0  # Common VM default sizes
            ]

            is_exact_match = any(abs(total_gb - size) < 0.1 for size in suspicious_sizes)

            art.memory_patterns = {
                "total_gb": total_gb,
                "exact_vm_size": is_exact_match,
                "swap_present": swap.total > 0,
                "available_percent": mem.available / mem.total * 100
            }
    except Exception:
        pass



def gather_filesystem_artifacts(art: ArtifactCollection) -> None:
    """
    Check for VM-specific files and directories that are hard to hide.
    """
    # > Non exhaustive, can be added on to and updated.

    vm_paths = []
    if platform.system() == "Windows":
        check_paths = [
            "C:\\Program Files\\VMware",
            "C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        ]
    else:  # Linux
        check_paths = [
            "/dev/vda",
            "/dev/vdb",
            "/dev/xvda",
            "/sys/bus/vmbus",
            "/proc/xen",
            "/proc/vz",
        ]

    for path in check_paths:
        if os.path.exists(path):
            vm_paths.append(path)

    art.filesystem_artifacts = vm_paths



def gather_hardware_quirks(art: ArtifactCollection) -> None:
    """
    Check for hardware quirks that real systems have but VMs often lack.
    """
    # > This does not mean that the system being scanned is a VM or not. Just that usually VMs lack some of these quirks or have some of these quirks.
    # > More quirks can be added later on.

    quirks = []

    # Check for battery (VMs usually don't have one or the system is a desktop PC)
    if platform.system() == "Windows":
        out = run(["powershell", "-NoProfile", "-Command",
                   "(Get-WmiObject -Class Win32_Battery | Measure-Object).Count"])
        if out.strip() == "0":
            quirks.append("no_battery_detected")
    elif platform.system() == "Linux":
        if not os.path.exists("/sys/class/power_supply/BAT0"):
            quirks.append("no_battery_detected")

    # Check for unusual USB device count (VMs often have very few or the system is a laptop)
    if platform.system() == "Linux":
        try:
            usb_devices = len(os.listdir("/sys/bus/usb/devices"))
            if usb_devices < 5:
                quirks.append(f"low_usb_count_{usb_devices}")
        except Exception:
            pass

    # Check for SMBIOS serial numbers (VMs often have dummy values)
    if platform.system() == "Linux" and shutil_which("dmidecode"):
        serial = run(["dmidecode", "-s", "system-serial-number"]).strip()
        if serial in ["0", "None", "To Be Filled By O.E.M.", "Default string"]:
            quirks.append("dummy_serial_number")

    art.hardware_quirks = quirks



def gather_network_latency(art: ArtifactCollection) -> None:
    import socket

    timings = []
    try:
        for _ in range(10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            t0 = time.perf_counter()
            try:
                s.connect(("127.0.0.1", 65535))  # Connect to a closed port
            except:
                pass
            timings.append(time.perf_counter() - t0)
            s.close()

        avg_latency = sum(timings) / len(timings)
        art.network_latency = {
            "avg_ms": avg_latency * 1000,
            "suspiciously_fast": avg_latency < 0.0001  # Too fast for real hardware
        }
    except Exception:
        pass


def gather_gpu_detection(art: ArtifactCollection) -> None:
    """
    Looking for virtualized GPU or GPU passthrough indicators.
    """
    gpu_info = []

    if platform.system() == "Windows":
        out = run(["wmic", "path", "win32_VideoController", "get", "name"])
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line:
                gpu_info.append(line)

    elif platform.system() == "Linux":
        if shutil_which("lspci"):
            out = run(["lspci", "-v"])
            for line in out.splitlines():
                if "VGA" in line or "3D" in line:
                    gpu_info.append(line)

    # Checking for VM-specific GPU adapters
    vm_gpu_keywords = ["qxl", "vmsvga", "virtio", "vboxvideo", "cirrus"]
    vm_gpu_detected = any(
        any(kw in gpu.lower() for kw in vm_gpu_keywords)
        for gpu in gpu_info
    )

    art.gpu_info = {
        "adapters": gpu_info,
        "vm_gpu": vm_gpu_detected
    }



def gather_uptime_check(art: ArtifactCollection) -> None:
    """
    VMs (especially sandboxes) typically have a very low uptime.
    """
    try:
        if psutil:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_hours = uptime_seconds / 3600

            art.uptime = {
                "hours": uptime_hours,
                "suspiciously_recent": uptime_hours < 1  # Less than 1 hour | Can be tweaked if needed.
            }
    except Exception:
        pass



def enhanced_behavior_scoring(art: ArtifactCollection, behavior_signals: List[str]) -> int:
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










# ---------------------------
# Sandbox / anti-analysis
# ---------------------------

def sandbox_checks(art: ArtifactCollection) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "detected": False,
        "heuristics": [],
        "process_hits": [],
        "env_hits": [],
        "disk_hits": [],
        "system_hits": [],
        "debugger": False,
        "timing_anomaly": False,
    }

    # Process-based indicators
    for p in art.processes or []:
        pl = p.lower()
        for sig in SANDBOX_PROCS:
            if sig in pl:
                out["process_hits"].append(p)
                out["heuristics"].append(f"sandbox process: {p}")

    # Environment variables
    for k in os.environ.keys():
        ku = k.upper()
        if any(s in ku for s in ("VBOX", "VIRTUALBOX", "VMWARE", "CUCKOO", "SANDBOX", "QEMU")):
            out["env_hits"].append(k)
            out["heuristics"].append(f"env var looks sandboxy: {k}")

    # Username / hostname heuristics
    try:
        import getpass, socket
        user = getpass.getuser().lower()
        host = socket.gethostname().lower()
        for bad in ("sandbox", "analysis", "maltest", "cuckoo", "vm", "test"):
            if bad in user:
                out["system_hits"].append(f"user={user}")
                out["heuristics"].append(f"suspicious username: {user}")
            if bad in host:
                out["system_hits"].append(f"host={host}")
                out["heuristics"].append(f"suspicious hostname: {host}")
    except Exception:
        pass

    # Disk vendor indicators
    for dv in art.disk_vendors or []:
        dvl = dv.lower()
        for vm, subs in VM_DISK_VENDORS.items():
            for sub in subs:
                if sub.lower() in dvl:
                    out["disk_hits"].append({"vendor": dv, "vm": vm})
                    out["heuristics"].append(f"disk vendor '{dv}' indicates {vm}")

    # ACPI anomaly: system product suggests VM but no ACPI signatures found
    try:
        if art.system_product and any(x in (art.system_product or "").lower() for x in ('virtualbox','vmware','qemu','kvm','xen','hyper-v','parallels')):
            if not (art.acpi_signatures or art.acpi_tables):
                out["heuristics"].append("system product suggests VM but ACPI signatures missing")
                out["system_hits"].append("missing_acpi_for_vm_product")
    except Exception:
        pass

    # Low-resources heuristic
    try:
        if psutil:
            mem = psutil.virtual_memory().total
            cpus = psutil.cpu_count(logical=False) or psutil.cpu_count()
            if mem and mem < 1_000_000_000:
                out["heuristics"].append(f"low memory ({mem} bytes)")
            if cpus and cpus <= 1:
                out["heuristics"].append(f"single CPU ({cpus})")
        else:
            # fallback
            cpus = os.cpu_count()
            if cpus and cpus <= 1:
                out["heuristics"].append(f"single CPU ({cpus})")
    except Exception:
        pass

    # Debugger detection
    if hasattr(sys, "gettrace") and sys.gettrace():
        out["debugger"] = True
        out["heuristics"].append("debugger attached")

    # Timing anomaly: a short sleep that sandboxes may skip/fast-forward past
    try:
        start = time.perf_counter()
        time.sleep(0.15)
        delta = time.perf_counter() - start
        if delta < 0.13:
            out["timing_anomaly"] = True
            out["heuristics"].append(f"sleep timing anomaly ({delta:.3f}s)")
    except Exception:
        pass

    # Final detected decision: heuristics count or specific hits
    hits = len(out["heuristics"]) + len(out["process_hits"]) + len(out["env_hits"]) + len(out["disk_hits"]) + len(out["system_hits"])
    if out["debugger"] or out["timing_anomaly"] or hits >= 2:
        out["detected"] = True

    return out










# ---------------------------
# Detector scoring
# ---------------------------

class Detector:
    def __init__(self) -> None:
        self.art = ArtifactCollection()

    def gather_all(self) -> ArtifactCollection:
        gather_cpu_vendor(self.art)
        gather_pci(self.art)
        gather_acpi_tables(self.art)
        gather_cpuid_signature(self.art)
        gather_bios_system(self.art)
        gather_processes(self.art)
        gather_mac_prefixes(self.art)
        gather_disk_vendors(self.art)
        gather_interrupt_behavior(self.art)
        gather_entropy_behavior(self.art)
        gather_cpu_topology(self.art)
        gather_cpu_cache_behavior(self.art)
        gather_instruction_timing(self.art)
        gather_memory_patterns(self.art)
        gather_filesystem_artifacts(self.art)
        gather_hardware_quirks(self.art)
        gather_network_latency(self.art)
        gather_gpu_detection(self.art)
        gather_uptime_check(self.art)
        self._normalize()
        return self.art

    def _normalize(self) -> None:
        try:
            self.art.pci_vendors = sorted({_clean_hex(x) for x in (self.art.pci_vendors or []) if x})
            self.art.pci_devices = sorted({_clean_hex(x) for x in (self.art.pci_devices or []) if x})
        except Exception:
            self.art.pci_vendors = self.art.pci_vendors or []
            self.art.pci_devices = self.art.pci_devices or []
        self.art.mac_prefixes = sorted({m.upper() for m in (self.art.mac_prefixes or []) if m})
        self.art.processes = sorted({p for p in (self.art.processes or []) if p})
        self.art.acpi_tables = sorted({t for t in (self.art.acpi_tables or []) if t})
        self.art.acpi_signatures = sorted({s for s in (self.art.acpi_signatures or []) if s})
        self.art.disk_vendors = sorted({d for d in (self.art.disk_vendors or []) if d})


    def score(self, art: Optional[ArtifactCollection] = None, sandbox: Optional[Dict[str, Any]] = None, explain: bool = False) -> Dict[str, Any]:
        if art is None:
            art = self.art
        platforms = list(VM_PCI_VENDORS.keys())
        scores: Dict[str, int] = {p: 0 for p in platforms}
        explain_map: Dict[str, List[str]] = {p: [] for p in platforms}

        # Hard vendor matches
        for vm, vids in VM_PCI_VENDORS.items():
            for vid in vids:
                if vid.upper() in (v.upper() for v in (art.pci_vendors or [])):
                    scores[vm] += 60
                    explain_map[vm].append(f"PCI vendor {vid}")

        # Expanded vendor/device table | digging deeper
        for vm, table in VM_PCI_SIGNATURES.items():
            for v in (art.pci_vendors or []):
                v_clean = v.replace("0x", "").upper()
                if v_clean in table.get("vendors", set()):
                    scores.setdefault(vm, 0)
                    scores[vm] += 30
                    explain_map.setdefault(vm, []).append(f"Expanded vendor {v}")
            for d in (art.pci_devices or []):
                d_clean = d.replace("0x", "").upper()
                if d_clean in table.get("devices", set()):
                    scores.setdefault(vm, 0)
                    scores[vm] += 20
                    explain_map.setdefault(vm, []).append(f"Expanded device {d}")

        # Legacy PCI device table
        for vm, devs in VM_PCI_DEVICES.items():
            for did in devs:
                if did.upper() in (d.upper() for d in (art.pci_devices or [])):
                    scores[vm] += 20
                    explain_map.setdefault(vm, []).append(f"Legacy device {did}")

        # CPUID
        if art.cpuid_signature:
            for vm, sig in VM_CPUID_SIGS.items():
                if sig.lower() in (art.cpuid_signature or "").lower():
                    scores.setdefault(vm, 0)
                    scores[vm] += 40
                    explain_map.setdefault(vm, []).append(f"CPUID '{sig}'")

        # ACPI signatures
        for sig in (art.acpi_signatures or []):
            for vm in platforms:
                if vm.lower().split("/")[0] in sig.lower():
                    scores[vm] += 15
                    explain_map.setdefault(vm, []).append(f"ACPI sig {sig}")

        # BIOS keywords and normalized brand
        for vm, kv in VM_SOFT_KEYWORDS.items():
            for kw in kv.get("bios", []):
                if art.bios_vendor and kw.lower() in art.bios_vendor.lower():
                    scores[vm] += 20
                    explain_map.setdefault(vm, []).append(f"BIOS contains '{kw}'")
        if art.bios_brand and art.bios_brand in scores:
            scores[art.bios_brand] += 25
            explain_map.setdefault(art.bios_brand, []).append("Normalized BIOS brand")

        # Processes
        for vm, kv in VM_SOFT_KEYWORDS.items():
            for pk in kv.get("process", []):
                if any(pk.lower() in p.lower() for p in art.processes):
                    scores[vm] += 15
                    explain_map.setdefault(vm, []).append(f"Process '{pk}' present")

        # MAC prefixes
        for vm, prefs in MAC_PREFIXES.items():
            if any(pref.upper() in (m.upper() for m in (art.mac_prefixes or [])) for pref in prefs):
                scores[vm] += 10
                explain_map.setdefault(vm, []).append("MAC prefix match")

        # Disk vendors
        for dv in (art.disk_vendors or []):
            dvl = dv.lower()
            for vm, subs in VM_DISK_VENDORS.items():
                for sub in subs:
                    if sub.lower() in dvl:
                        scores[vm] += 15
                        explain_map.setdefault(vm, []).append(f"Disk vendor '{dv}'")

        # Hypervisor flag
        if art.hypervisor_flag:
            for vm in scores:
                scores[vm] += 10
                explain_map.setdefault(vm, []).append("Hypervisor flag present")

        # Windows - strong product indicator
        if platform.system() == "Windows" and art.system_product:
            mfg = (art.system_product or "").lower()
            if "qemu" in mfg or "kvm" in mfg:
                scores["QEMU/KVM"] += 50
                explain_map.setdefault("QEMU/KVM", []).append("System -> QEMU/KVM")
            elif "vmware" in mfg:
                scores["VMware"] += 50
                explain_map.setdefault("VMware", []).append("System -> VMware")
            elif "virtualbox" in mfg:
                scores["VirtualBox"] += 50
                explain_map.setdefault("VirtualBox", []).append("System -> VirtualBox")
            elif "microsoft" in mfg:
                scores["Hyper-V"] += 50
                explain_map.setdefault("Hyper-V", []).append("System -> Microsoft/Hyper-V")

        # Cap
        for k in scores:
            scores[k] = max(0, min(100, int(scores[k])))

        # If sandbox results are provided, integrate them (penalize scores)
        if sandbox:
            if sandbox.get("detected"):
                # Penalize strongly when sandbox heuristics are present
                for k in scores:
                    scores[k] = max(0, scores[k] - 30)
                    explain_map.setdefault(k, []).append("Sandbox heuristics detected -> -30 penalty")
            # optionally add specific heuristics into explain_map
            for k in scores:
                if sandbox.get("process_hits"):
                    explain_map.setdefault(k, []).append(f"sandbox process hits: {len(sandbox.get('process_hits'))}")
                if sandbox.get("timing_anomaly"):
                    explain_map.setdefault(k, []).append("timing anomaly")

        if explain:
            return {"scores": scores, "explain": explain_map}
        return {"scores": scores}



    def detect(self, explain: bool = False, aggressive_sandbox: bool = False) -> Dict[str, Any]:
        """
        Run our gatherers, compute scores, and run sandbox checks. If aggressive_sandbox==True
        and sandbox detection returns detected==True, then the result will include
        'aggressive_exit': True
        """
        art = self.gather_all()
        sandbox = sandbox_checks(art)
        sc = self.score(art, sandbox=sandbox, explain=explain)
        scores = sc["scores"] if explain else sc["scores"]
        explain_map = sc.get("explain", {}) if explain else {}

        best_vm = max(scores, key=lambda k: scores[k])
        best_score = scores[best_vm]

        result: Dict[str, Any] = {
            "artifacts": art.to_dict(),
            "scores": scores,
            "best_guess": best_vm if best_score >= 20 else "Unknown",
            "confidence": best_score,
            "anti_analysis": sandbox,
        }
        if explain:
            result["explain"] = explain_map

        if aggressive_sandbox and sandbox.get("detected"):
            result["aggressive_exit"] = True


        behavior_signals: List[str] = []
        hardened_signals = 0
        if art.interrupt_behavior.get("low_jitter"):
            hardened_signals += 1
            behavior_signals.append("Low interrupt jitter suggests VM")

        if art.entropy_behavior.get("low_variance"):
            hardened_signals += 1
            behavior_signals.append("Low entropy variance suggests VM")

        if art.cpu_topology.get("suspicious_ratio"):
            hardened_signals += 1
            behavior_signals.append("CPU topology ratio suspicious (logical / physical > 4)")

        # Behavioral scoring
        additional_signals = enhanced_behavior_scoring(art, behavior_signals)
        hardened_signals += additional_signals

        if behavior_signals:
            result["behavior_signals"] = behavior_signals

        # Structural behavior indicates virtualization, but vendor confidence is low
        if best_score < 40 and hardened_signals >= 2:
            classification = "Hardened VM"
        elif best_score >= 80:
            classification = "Detected VM"
        elif 40 <= best_score < 80:
            classification = "Likely VM"
        else:
            classification = "Unknown/Bare Metal"

        result["classification"] = classification
        return result

# End of vm_core.py
