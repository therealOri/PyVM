"""
vm_cli.py

Command-line interface for vm_core.Detector
"""

import argparse
import json
import sys
from vm_core import Detector
import os

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'

    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.DIM = ''

# Mojis
ICON_CHECK = "✓"
ICON_CROSS = "✗"
ICON_WARNING = "⚠"
ICON_INFO = "ℹ"
ICON_SHIELD = "🛡"
ICON_CPU = "⚙"
ICON_DISK = "💾"
ICON_NETWORK = "🌐"
ICON_PROCESS = "⚡"

def print_box(title, content=None, color=Colors.OKBLUE):
    """We print our content in a nice pretty box"""
    width = 60
    print(f"\n{color}{'━' * width}{Colors.ENDC}")
    print(f"{color}{Colors.BOLD}  {title}{Colors.ENDC}")
    print(f"{color}{'━' * width}{Colors.ENDC}")
    if content:
        print(content)

def print_separator(char="─", width=60, color=Colors.DIM):
    """separator line"""
    print(f"{color}{char * width}{Colors.ENDC}")

def format_confidence_bar(confidence):
    bar_width = 30
    filled = int((confidence / 100) * bar_width)
    empty = bar_width - filled

    if confidence >= 80:
        color = Colors.FAIL
    elif confidence >= 50:
        color = Colors.WARNING
    else:
        color = Colors.OKGREEN

    bar = f"{color}{'█' * filled}{Colors.DIM}{'░' * empty}{Colors.ENDC}"
    return f"{bar} {color}{confidence}%{Colors.ENDC}"

def format_artifact_summary(art: dict) -> str:
    lines = []

    # CPU Info
    if art.get('cpu_vendor') or art.get('cpuid_signature'):
        lines.append(f"{Colors.OKCYAN}{ICON_CPU} CPU Information{Colors.ENDC}")
        if art.get('cpu_vendor'):
            lines.append(f"  Vendor:     {Colors.BOLD}{art.get('cpu_vendor')}{Colors.ENDC}")
        if art.get('cpuid_signature'):
            lines.append(f"  Signature:  {art.get('cpuid_signature')}")
        if art.get('hypervisor_flag'):
            lines.append(f"  Hypervisor: {Colors.WARNING}{ICON_WARNING} Present{Colors.ENDC}")
        lines.append("")

    # System Info
    if art.get('bios_vendor') or art.get('bios_brand') or art.get('system_product'):
        lines.append(f"{Colors.OKCYAN}{ICON_SHIELD} System Information{Colors.ENDC}")
        if art.get('bios_vendor'):
            lines.append(f"  BIOS Vendor:  {art.get('bios_vendor')}")
        if art.get('bios_brand'):
            lines.append(f"  BIOS Brand:   {art.get('bios_brand')}")
        if art.get('system_product'):
            lines.append(f"  Product:      {art.get('system_product')}")
        lines.append("")

    # Hardware info
    if art.get('pci_vendors') or art.get('pci_devices'):
        lines.append(f"{Colors.OKCYAN}🔌 Hardware{Colors.ENDC}")
        if art.get('pci_vendors'):
            vendors = ', '.join(art.get('pci_vendors'))
            lines.append(f"  PCI Vendors:  {vendors}")
        if art.get('pci_devices'):
            devices = ', '.join(art.get('pci_devices')[:5])
            if len(art.get('pci_devices')) > 5:
                devices += f"... (+{len(art.get('pci_devices')) - 5} more)"
            lines.append(f"  PCI Devices:  {devices}")
        lines.append("")

    # Storage info
    if art.get('disk_vendors') or art.get('acpi_tables'):
        lines.append(f"{Colors.OKCYAN}{ICON_DISK} Storage & ACPI{Colors.ENDC}")
        if art.get('disk_vendors'):
            lines.append(f"  Disk Vendors: {', '.join(art.get('disk_vendors'))}")
        if art.get('acpi_tables'):
            tables = ', '.join(art.get('acpi_tables')[:8])
            if len(art.get('acpi_tables')) > 8:
                tables += "..."
            lines.append(f"  ACPI Tables:  {tables}")
        lines.append("")

    # Network info
    if art.get('mac_prefixes'):
        lines.append(f"{Colors.OKCYAN}{ICON_NETWORK} Network{Colors.ENDC}")
        lines.append(f"  MAC Prefixes: {', '.join(art.get('mac_prefixes'))}")
        lines.append("")

    if art.get('processes'):
        proc_count = len(art.get('processes'))
        lines.append(f"{Colors.OKCYAN}{ICON_PROCESS} Running Processes ({proc_count}){Colors.ENDC}")
        procs = ', '.join(art.get('processes')[:10])
        if proc_count > 10:
            procs += f"... (+{proc_count - 10} more)"
        lines.append(f"  {procs}")

    return "\n".join(lines)

def print_sandbox_diagnostics(sandbox: dict):
    if not sandbox:
        print(f"{Colors.OKGREEN}{ICON_CHECK} No sandbox indicators detected{Colors.ENDC}")
        return

    detected = sandbox.get('detected', False)
    if detected:
        print(f"{Colors.FAIL}{Colors.BOLD}{ICON_WARNING} SANDBOX DETECTED{Colors.ENDC}\n")
    else:
        print(f"{Colors.OKGREEN}{ICON_CHECK} No sandbox detected{Colors.ENDC}\n")

    if sandbox.get("heuristics"):
        print(f"{Colors.WARNING}Heuristics triggered:{Colors.ENDC}")
        for h in sandbox.get("heuristics", []):
            print(f"  {Colors.WARNING}•{Colors.ENDC} {h}")
        print()

    if sandbox.get("process_hits"):
        print(f"{Colors.FAIL}Suspicious processes:{Colors.ENDC}")
        for p in sandbox.get("process_hits"):
            print(f"  {Colors.FAIL}{ICON_CROSS}{Colors.ENDC} {p}")
        print()

    if sandbox.get("env_hits"):
        print(f"{Colors.FAIL}Suspicious environment variables:{Colors.ENDC}")
        for e in sandbox.get("env_hits"):
            print(f"  {Colors.FAIL}{ICON_CROSS}{Colors.ENDC} {e}")
        print()

    if sandbox.get("disk_hits"):
        print(f"{Colors.WARNING}Disk vendor indicators:{Colors.ENDC}")
        for dh in sandbox.get("disk_hits", []):
            print(f"  {Colors.WARNING}•{Colors.ENDC} {dh.get('vendor')} → {dh.get('vm')}")
        print()

    if sandbox.get("debugger"):
        print(f"{Colors.FAIL}{ICON_WARNING} Debugger attached{Colors.ENDC}\n")

    if sandbox.get("timing_anomaly"):
        print(f"{Colors.WARNING}{ICON_WARNING} Timing anomaly detected{Colors.ENDC}\n")


def clear():
    os.system("clear||cls")



def main():
    parser = argparse.ArgumentParser(description="VM detection CLI")
    parser.add_argument("--debug", action="store_true", help="Show full artifact collection and debug info")
    parser.add_argument("--log", action="store_true", help="Alias for --debug")
    parser.add_argument("--explain", action="store_true", help="Show explain map (which artifacts contributed to scores)")
    parser.add_argument("--sandbox-aggressive", action="store_true", help="If sandbox detected, exit silently (no error).")
    parser.add_argument("--raw-json", action="store_true", help="Print raw JSON with results and exit")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    det = Detector()
    res = det.detect(explain=args.explain, aggressive_sandbox=args.sandbox_aggressive)

    # If aggressive, detected -> exit silently (unless debug)
    sandbox = res.get("anti_analysis", {})
    if args.sandbox_aggressive and sandbox and sandbox.get("detected"):
        if args.debug or args.log:
            print(f"{Colors.FAIL}[AGGRESSIVE MODE] Sandbox detected — exiting due to --sandbox-aggressive{Colors.ENDC}")
            print(json.dumps(res, indent=2))
        sys.exit(0)

    if args.raw_json:
        print(json.dumps(res, indent=2))
        return

    # Summary
    best = res.get("best_guess", "Unknown")
    conf = res.get("confidence", 0)
    classification = res.get("classification")


    print_box("VM DETECTION RESULTS", color=Colors.HEADER)
    if best == "Bare Metal" or conf < 30:
        icon = ICON_CHECK
        color = Colors.OKGREEN
    elif conf >= 80:
        icon = ICON_CROSS
        color = Colors.FAIL
    else:
        icon = ICON_WARNING
        color = Colors.WARNING

    print(f"\n{color}{Colors.BOLD}{icon} Environment: {best}{Colors.ENDC}")

    if classification:
        class_color = Colors.WARNING if classification == "Hardened VM" else Colors.OKCYAN
        print(f"{class_color}  Classification: {classification}{Colors.ENDC}")

    print(f"\n  Confidence Level:")
    print(f"  {format_confidence_bar(conf)}")

    if classification == "Hardened VM":
        print(f"\n{Colors.WARNING}{ICON_WARNING} Hardened VM detected (anti-fingerprinting measures present){Colors.ENDC}")

    if not res["artifacts"].get("pci_vendors"):
        print(f"\n{Colors.DIM}{ICON_INFO} Note: No PCI vendor IDs detected (does NOT imply bare metal){Colors.ENDC}")

    print_box("CONFIDENCE BREAKDOWN", color=Colors.OKBLUE)
    scores = res.get("scores", {})
    for k, v in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        if v >= 70:
            color = Colors.FAIL
        elif v >= 40:
            color = Colors.WARNING
        else:
            color = Colors.DIM
        bar_len = int(v / 5)
        bar = "█" * bar_len
        print(f"  {k:<12} {color}{bar:20} {v:>3}%{Colors.ENDC}")

    # Key indicators
    print_box("SYSTEM ARTIFACTS", color=Colors.OKBLUE)
    print(format_artifact_summary(res.get("artifacts", {})))

    # Sandbox diagnostics
    print_box("ANTI-ANALYSIS DETECTION - (basic)", color=Colors.OKBLUE)
    print_sandbox_diagnostics(res.get("anti_analysis", {}))

    if res.get("behavior_signals"):
        print_box("BEHAVIORAL VM INDICATORS", color=Colors.WARNING)
        signals = res.get("behavior_signals", [])
        if signals:
            for s in signals:
                print(f"  {Colors.WARNING}⚡{Colors.ENDC} {s}")
        else:
            print(f"{Colors.OKGREEN}{ICON_CHECK} No behavioral anomalies detected{Colors.ENDC}")
        print()

    # Explanation map if requested
    if args.explain:
        print_box("DETECTION REASONING", color=Colors.OKCYAN)
        explain = res.get("explain", {})
        for vm, reasons in explain.items():
            print(f"\n{Colors.BOLD}{vm}:{Colors.ENDC}")
            for r in reasons:
                print(f"  {Colors.OKCYAN}•{Colors.ENDC} {r}")

    # Debug full JSON if requested
    if args.debug or args.log:
        print_box("DEBUG OUTPUT", color=Colors.DIM)
        print(json.dumps(res, indent=2))

    print()



if __name__ == "__main__":
    clear()
    main()
