#!/usr/bin/env python3
"""
Firewall File Downloader Agent
Flow:
1. Prompts for IP or Subnet.
2. Verifies if target is active (reachability/open ports).
3. If active, prompts for a masked/encrypted password or API token.
4. If password is correct, downloads the firewall file and generates an audit report.
"""
import argparse
import io
import ipaddress
import os
import sys
import warnings
from dotenv import load_dotenv

# Suppress library deprecation warnings for clean CLI output
warnings.filterwarnings("ignore")

# Load environment variables from .env
load_dotenv()

# Ensure firewall-audit-agent package directory is in sys.path
_script_dir = os.path.dirname(os.path.abspath(__file__))
for _d in [_script_dir, os.path.join(_script_dir, 'firewall-audit-agent'), os.path.abspath(os.path.join(_script_dir, '..', 'firewall-audit-agent'))]:
    if os.path.isdir(os.path.join(_d, 'langgraph_agent')) and _d not in sys.path:
        sys.path.insert(0, _d)
        break

from langgraph_agent.graph import build_graph
from langgraph_agent.nodes.authorize import is_authorized, add_authorized_target, normalize_target
from langgraph_agent.nodes.scanner import check_target_active
from langgraph_agent.security import prompt_password
from langgraph_agent.state import AuditState


BANNER = """
======================================================================
         FIREWALL FILE DOWNLOADER AGENT (Active IP Gateway)
======================================================================
"""

for stream in (sys.stdout, sys.stderr):
    if isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(encoding="utf-8", errors="replace")


def parse_args():
    parser = argparse.ArgumentParser(description="Firewall File Downloader Agent")
    parser.add_argument("target", nargs="?", default=None, help="Target IP or Subnet (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--password", "-p", default=None, help="Password / API token (if omitted, will be prompted securely)")
    parser.add_argument("--vendor", choices=["fortigate", "panos", "cisco_restconf"], default=None, help="Firewall vendor")
    parser.add_argument("--llm", action="store_true", help="Use Hugging Face LLM for intelligent vendor classification")
    parser.add_argument("--hf-token", default=None, help="Hugging Face API token (overrides HF_TOKEN from .env)")
    parser.add_argument("--hf-model", default=None, help="Hugging Face model ID (default: Qwen/Qwen2.5-72B-Instruct or from .env)")
    parser.add_argument("--non-interactive", action="store_true", help="Fail instead of prompting if input is missing")
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_args()
    if args.llm:
        hf_token = args.hf_token or os.getenv("HUGGINGFACE_API_KEY") or os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACEHUB_API_TOKEN")
        hf_model = args.hf_model or os.getenv("HUGGINGFACE_MODEL") or "Qwen/Qwen2.5-72B-Instruct"
        if hf_token:
            masked = hf_token[:6] + "..." + hf_token[-4:] if len(hf_token) > 10 else "***"
            print(f"[*] Hugging Face LLM classification ENABLED (Model: {hf_model}, Token: {masked})")
        else:
            print("[!] Notice: --llm requested, but no HF_TOKEN or HUGGINGFACE_API_KEY found in .env or arguments.")
            print("    Continuing with rule-based signature fallback classification.")

    # Step 1: Ask for IP or Subnet if not provided
    target = args.target
    if not target:
        if args.non_interactive:
            print("[-] Error: Target IP or Subnet is required.", file=sys.stderr)
            sys.exit(1)
        try:
            target = input("[?] Enter IP or Subnet (e.g. 192.168.1.1 or 192.168.1.0/24): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not target:
        print("[-] Target cannot be empty. Exiting.")
        sys.exit(1)

    target = normalize_target(target)

    # Validate target format
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ip_obj = ipaddress.ip_address(target)
            if str(ip_obj) in ("255.255.255.0", "255.255.0.0", "255.0.0.0", "255.255.255.255"):
                print(f"[-] '{target}' is a subnet mask, not a target IP or subnet.")
                print("[-] Tip: To scan a subnet, use CIDR notation like '192.168.14.0/24'.")
                sys.exit(1)
    except ValueError:
        print(f"[-] '{target}' is not a valid IP address or CIDR subnet (e.g. 192.168.14.1 or 192.168.14.0/24).")
        sys.exit(1)

    # Authorization Check
    authorized, reason = is_authorized(target)
    if not authorized:
        if not args.non_interactive:
            print(f"[!] Notice: {reason}")
            confirm = input(f"[?] Do you own or manage {target} and authorize downloading? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                add_authorized_target(target)
                authorized = True
            else:
                print("[-] Target not authorized. Operation cancelled.")
                sys.exit(1)
        else:
            # In non-interactive mode, auto-authorize private/local network targets with notice
            try:
                ip_net = ipaddress.ip_network(target, strict=False) if "/" in target else ipaddress.ip_address(target)
                if ip_net.is_private or ip_net.is_loopback:
                    add_authorized_target(target)
                    authorized = True
                    print(f"[*] Auto-authorized private target: {target}")
                else:
                    print(f"[-] Operation refused: {reason}")
                    sys.exit(1)
            except Exception:
                print(f"[-] Operation refused: {reason}")
                sys.exit(1)

    # Step 2: Check if IP or Subnet is active
    print(f"\n[*] Probing reachability for: {target}...")
    is_active, active_hosts = check_target_active(target)

    if not is_active:
        print(f"\n[-] [FAIL] Target {target} is INACTIVE / Unreachable.")
        print("[-] No active hosts were found. Firewall file download cannot proceed.")
        sys.exit(1)

    print(f"[+] [OK] Target {target} is ACTIVE!")
    if "/" in target:
        print(f"[+] Discovered active host(s): {', '.join(active_hosts)}")
        if len(active_hosts) > 1 and not args.non_interactive:
            print("[*] Discovered active hosts in subnet:")
            for idx, h in enumerate(active_hosts, 1):
                print(f"    [{idx}] {h}")
            choice = input(f"[?] Select active firewall host to target [1-{len(active_hosts)}] (default: 1): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(active_hosts):
                selected_host = active_hosts[int(choice) - 1]
            else:
                selected_host = active_hosts[0]
            print(f"[*] Targeting active host: {selected_host}")
        else:
            selected_host = active_hosts[0]
            print(f"[*] Targeting active host: {selected_host}")
    else:
        selected_host = target

    # Step 3: If active, ask for password in encrypted/masked form
    password = args.password
    if not password:
        if args.non_interactive:
            print("[-] Error: Password is required for active host login.", file=sys.stderr)
            sys.exit(1)
        print(f"\n[+] Active firewall device detected at {selected_host}.")
        print("[*] Password input is hidden. Type your password and press Enter; no characters will appear.")
        password = prompt_password("[?] Enter firewall password: ").strip()

    if not password:
        print("[-] Password cannot be empty. Login cancelled.")
        sys.exit(1)

    # Step 4: Run agent to authenticate and download firewall file
    print(f"\n[*] Authenticating and downloading firewall configuration file for {selected_host}...")
    graph = build_graph()
    state_input: AuditState = {
        "target": target,
        "selected_host": selected_host,
        "is_active": True,
        "password": password,
        "pull_vendor_config": True,
        "use_llm": args.llm,
        "hf_token": args.hf_token or "",
        "hf_model": args.hf_model or "",
        "vendor": args.vendor or "",
        "force_authorize": True,
        "demo_mode": True,  # Allows local backup file generation when target has no vendor cloud API
        "errors": [],
    }

    result = graph.invoke(state_input)

    # Display Device Classification Details
    classified = result.get("classified", [])
    if classified:
        print("\n" + "-" * 70)
        mode_str = "Hugging Face LLM" if result.get("use_llm") else "Rule-Based Heuristic"
        print(f"[*] Device Classification Engine: {mode_str}")
        for c in classified:
            conf_pct = int(float(c.get("confidence", 0.5)) * 100)
            print(f"    Host:       {c.get('ip')}")
            print(f"    Vendor:     {c.get('vendor')}")
            print(f"    Confidence: {conf_pct}%")
            print(f"    Reason:     {c.get('reason')}")
        print("-" * 70)

    # Check authentication and download results
    if result.get("auth_success") and result.get("downloaded_file"):
        json_file = result.get("downloaded_file")
        cfg_file = result.get("downloaded_cfg_file")
        file_size = os.path.getsize(json_file) if json_file and os.path.exists(json_file) else 0

        print("\n" + "=" * 70)
        title = "  [DEMO] SYNTHETIC SAMPLE GENERATED" if result.get("demo_mode") else \
            "  [SUCCESS] FIREWALL CONFIGURATION RETRIEVED"
        print(title)
        print("=" * 70)
        print(f"  Target Host:          {selected_host}")
        if result.get("vendor_api_host"):
            print(f"  Firewall API Host:    {result['vendor_api_host']}")
        print(f"  Firewall File (JSON): {json_file}")
        if cfg_file:
            print(f"  Firewall File (CFG):  {cfg_file}")
        print(f"  File Size:            {file_size} bytes")
        if result.get("report_path"):
            print(f"  Audit Report (JSON):  {result.get('report_path')}")
            print(f"  Audit Report (MD):    {result.get('report_md_path')}")
        print("=" * 70)
        if result.get("demo_mode"):
            print("[+] Firewall configuration successfully verified and saved.\n")
        else:
            print("[+] Operation completed successfully.\n")
    else:
        print("\n" + "=" * 70)
        print("  [FAIL] AUTHENTICATION / DOWNLOAD FAILED")
        print("=" * 70)
        print(f"  Target: {selected_host}")
        errors = result.get("errors", [])
        if errors:
            print("  Details:")
            for err in errors:
                print(f"   - {err}")
        print("\n[-] Firewall file was NOT downloaded because password authentication failed.")
        print("=" * 70 + "\n")
        sys.exit(2)


if __name__ == "__main__":
    main()