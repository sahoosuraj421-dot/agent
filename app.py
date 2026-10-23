
import os
import sys
import json
import time
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
import streamlit as st

# =====================================================================
# Path & Environment Setup
# =====================================================================
_script_dir = os.path.dirname(os.path.abspath(__file__))
_possible_roots = [
    _script_dir,
    os.path.join(_script_dir, "firewall-audit-agent"),
    os.path.abspath(os.path.join(_script_dir, "..", "firewall-audit-agent")),
]

AGENT_ROOT = None
for _d in _possible_roots:
    if os.path.isdir(os.path.join(_d, "langgraph_agent")):
        AGENT_ROOT = _d
        if _d not in sys.path:
            sys.path.insert(0, _d)
        break

if not AGENT_ROOT:
    st.error("Error: Could not locate 'firewall-audit-agent' package directory. Please check your workspace structure.")
    st.stop()

# Import Agent Modules
try:
    from langgraph_agent.graph import build_graph
    from langgraph_agent.paths import load_yaml, ROOT
    from langgraph_agent.state import AuditState
    from langgraph_agent.nodes.scanner import check_target_active, _resolve_nmap_bin
    from langgraph_agent.nodes.authorize import (
        is_authorized,
        is_subnet_mask,
        add_authorized_target,
        normalize_target,
    )
    from langgraph_agent.downloader import get_downloads_dir
except Exception as e:
    st.error(f"Failed to load agent core modules: {e}")
    st.stop()

# =====================================================================
# Page Configuration & Styling
# =====================================================================
st.set_page_config(
    page_title="Firewall File Downloader Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for standard, modern, responsive aesthetics
st.markdown("""
<style>
    /* Main Layout & Cards */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
    }
    .main-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        color: #F8FAFC;
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.8rem;
        border: 1px solid #334155;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
    .main-header h1 {
        font-size: 2.1rem;
        font-weight: 700;
        margin: 0;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }
    .main-header p {
        color: #94A3B8;
        font-size: 1.02rem;
        margin-top: 0.4rem;
        margin-bottom: 0;
    }
    .step-pill {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        background: #E2E8F0;
        color: #334155;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    .metric-card {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.8rem;
    }
    .status-badge-active {
        background-color: #DCFCE7;
        color: #166534;
        padding: 0.35rem 0.85rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.9rem;
        border: 1px solid #BBF7D0;
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
    }
    .status-badge-inactive {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 0.35rem 0.85rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.9rem;
        border: 1px solid #FECACA;
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
    }
    .stDownloadButton button {
        width: 100%;
        border-radius: 8px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# =====================================================================
# Session State Initialization
# =====================================================================
if "target_ip" not in st.session_state:
    st.session_state.target_ip = "127.0.0.1"
if "is_active" not in st.session_state:
    st.session_state.is_active = None
if "active_hosts" not in st.session_state:
    st.session_state.active_hosts = []
if "selected_host" not in st.session_state:
    st.session_state.selected_host = "127.0.0.1"
if "auth_result" not in st.session_state:
    st.session_state.auth_result = None
if "demo_mode_toggle" not in st.session_state:
    st.session_state.demo_mode_toggle = True
if "pending_auth_target" not in st.session_state:
    st.session_state.pending_auth_target = None
if "pending_auth_reason" not in st.session_state:
    st.session_state.pending_auth_reason = ""

# =====================================================================
# Sidebar: Settings, Scope, and Diagnostics
# =====================================================================
with st.sidebar:
    st.markdown("### 🛡️ Firewall Agent Settings")
    st.caption("Authenticated Gateway & Security Audit Console")
    
    # Mode Toggle
    demo_mode = st.toggle(
        "Simulation / Demo Mode",
        value=st.session_state.demo_mode_toggle,
        help="When enabled, allows secure verification and synthetic configuration fallback if physical firewall hardware is not directly reachable on this LAN."
    )
    st.session_state.demo_mode_toggle = demo_mode
    if demo_mode:
        os.environ["FIREWALL_DEMO_MODE"] = "true"
        st.info("💡 **Demo Mode Active**: Allows test logins (`admin`, `admin123`, `firewall123`) and generates realistic policy data.")
    else:
        os.environ["FIREWALL_DEMO_MODE"] = "false"
        st.warning("⚠️ **Production Mode**: Requires live reachability to physical firewall management API.")

    st.divider()

    # Vendor Selection
    vendor_choice = st.selectbox(
        "Firewall Vendor Profile",
        options=["Auto-Detect", "Fortinet FortiGate", "Palo Alto PAN-OS", "Cisco RESTCONF"],
        index=0,
        help="Select vendor or allow the agent to detect via port signature and fingerprinting."
    )
    vendor_key_map = {
        "Auto-Detect": "",
        "Fortinet FortiGate": "fortigate",
        "Palo Alto PAN-OS": "panos",
        "Cisco RESTCONF": "cisco_restconf",
    }
    selected_vendor = vendor_key_map.get(vendor_choice, "")

    # LLM Classification: Defaults to FALSE (Pure Rule-Based). Uses LLM ONLY if checked.
    use_llm = st.checkbox(
        "Enable LLM Classification (Hugging Face)",
        value=False,
        help="Check this ONLY if you want to use Hugging Face LLM for classification. When unchecked, runs 100% rule-based without using LLMs."
    )
    hf_token_custom = ""
    selected_hf_model = os.getenv("HUGGINGFACE_MODEL", "Qwen/Qwen2.5-72B-Instruct")
    if use_llm:
        st.markdown("##### 🤖 Hugging Face LLM Settings")
        env_hf_token = (
            os.getenv("HUGGINGFACE_API_KEY")
            or os.getenv("HF_TOKEN")
            or os.getenv("HUGGINGFACEHUB_API_TOKEN")
            or ""
        ).strip()
        if env_hf_token:
            masked = env_hf_token[:4] + "..." + env_hf_token[-4:] if len(env_hf_token) > 8 else "***"
            st.success(f"🔑 Key detected in `.env` (`{masked}`)")
            override_key = st.text_input("Override Token (optional):", type="password", key="hf_token_override")
            hf_token_custom = override_key.strip() if override_key.strip() else env_hf_token
        else:
            st.info("💡 Add `HUGGINGFACE_API_KEY` to `.env` or enter below:")
            hf_token_custom = st.text_input("Hugging Face API Token:", type="password", placeholder="hf_...", key="hf_token_input")

        model_choices = [
            "Qwen/Qwen2.5-72B-Instruct",
            "meta-llama/Llama-3.2-3B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
            "Custom..."
        ]
        chosen_model = st.selectbox("LLM Model", options=model_choices, index=0)
        if chosen_model == "Custom...":
            selected_hf_model = st.text_input("Custom Model ID:", value="Qwen/Qwen2.5-72B-Instruct", key="custom_hf_model")
        else:
            selected_hf_model = chosen_model

    st.divider()

    # Scope & Authorized Targets
    st.markdown("### 📋 Authorized Scope")
    try:
        cfg = load_yaml("authorized_subnets.yaml")
        authorized_cidrs = [e.get("cidr") for e in cfg.get("authorized_subnets", []) if e.get("cidr")]
        authorized_hosts = cfg.get("authorized_hosts", []) or []
        all_authorized = authorized_cidrs + authorized_hosts
    except Exception:
        all_authorized = ["127.0.0.1", "192.168.1.1", "192.168.14.0/24"]

    with st.expander("View Authorized Targets", expanded=False):
        for item in all_authorized:
            st.markdown(f"- `{item}`")

    # Add Target to Scope
    with st.expander("➕ Authorize New Target"):
        new_target = st.text_input("IP or Subnet CIDR:", placeholder="e.g. 192.168.20.1", key="new_scope_target")
        if st.button("Add to Authorized Scope", use_container_width=True):
            if new_target:
                try:
                    norm = normalize_target(new_target.strip())
                    add_authorized_target(norm)
                    st.success(f"Added `{norm}` to authorized scope!")
                    st.rerun()
                except Exception as ex:
                    st.error(f"Error authorizing target: {ex}")

    st.divider()

    # System Status / Diagnostics
    nmap_path = _resolve_nmap_bin()
    st.markdown("### ⚙️ Diagnostics")
    st.write(f"**Scanner Engine**: `{'Nmap Detected' if nmap_path else 'Socket Fallback'}`")
    if nmap_path:
        st.caption(f"Path: `{nmap_path}`")
    downloads_path = ROOT / "downloads"
    reports_path = ROOT / "reports"
    st.write(f"**Downloads**: `{downloads_path.name}/`")
    st.write(f"**Reports**: `{reports_path.name}/`")

    if st.button("🔄 Reset Agent State", use_container_width=True):
        st.session_state.is_active = None
        st.session_state.active_hosts = []
        st.session_state.auth_result = None
        st.session_state.pending_auth_target = None
        st.session_state.pending_auth_reason = ""
        st.rerun()

# =====================================================================
# Main Header
# =====================================================================
st.markdown("""
<div class="main-header">
    <h1>🛡️ Firewall File Downloader & Security Audit Agent</h1>
    <p>Automated reachability verification, authenticated configuration retrieval, and security compliance inspection.</p>
</div>
""", unsafe_allow_html=True)

# Tabs: Main Scanner/Downloader & Backups/History
main_tab, history_tab, guide_tab = st.tabs([
    "🚀 Scan & Download Gateway",
    "📁 Previous Backups & Reports",
    "📖 Help & Usage Guide"
])

# =====================================================================
# TAB 1: Main Scanner & Downloader Flow
# =====================================================================
with main_tab:
    # -------------------------------------------------------------
    # Step 1: Target Definition & Reachability
    # -------------------------------------------------------------
    st.markdown('<span class="step-pill">STEP 1</span> ### 🎯 Target IP / Subnet Reachability', unsafe_allow_html=True)

    c1, c2 = st.columns([3, 1])
    with c1:
        target_val = st.text_input(
            "Enter Target IP Address or CIDR Subnet:",
            value=st.session_state.target_ip,
            placeholder="e.g. 192.168.1.1 or 192.168.14.0/24 or 127.0.0.1",
            help="Provide the gateway IP of your firewall or a subnet to scan for active hosts."
        )
    with c2:
        st.write("")
        st.write("")
        scan_btn = st.button("🔍 Check Reachability", type="primary", use_container_width=True)

    # Preset Quick-Select Chips
    st.markdown("**Quick Preset Targets:**")
    preset_cols = st.columns(4)
    if preset_cols[0].button("🏠 127.0.0.1 (Localhost)", use_container_width=True):
        st.session_state.target_ip = "127.0.0.1"
        st.session_state.is_active = None
        st.session_state.auth_result = None
        st.session_state.pending_auth_target = None
        st.session_state.pending_auth_reason = ""
        st.rerun()
    if preset_cols[1].button("🌐 192.168.1.1 (Gateway)", use_container_width=True):
        st.session_state.target_ip = "192.168.1.1"
        st.session_state.is_active = None
        st.session_state.auth_result = None
        st.session_state.pending_auth_target = None
        st.session_state.pending_auth_reason = ""
        st.rerun()
    if preset_cols[2].button("🏢 10.0.0.1 (Lab Router)", use_container_width=True):
        st.session_state.target_ip = "10.0.0.1"
        st.session_state.is_active = None
        st.session_state.auth_result = None
        st.session_state.pending_auth_target = None
        st.session_state.pending_auth_reason = ""
        st.rerun()
    if preset_cols[3].button("📡 192.168.14.0/24 (Subnet)", use_container_width=True):
        st.session_state.target_ip = "192.168.14.0/24"
        st.session_state.is_active = None
        st.session_state.auth_result = None
        st.session_state.pending_auth_target = None
        st.session_state.pending_auth_reason = ""
        st.rerun()

    def _execute_reachability_scan(target_to_scan: str):
        with st.spinner(f"Probing reachability and active hosts on {target_to_scan}..."):
            is_active, active_hosts = check_target_active(target_to_scan)
            st.session_state.is_active = is_active
            st.session_state.active_hosts = active_hosts
            if active_hosts:
                st.session_state.selected_host = active_hosts[0]
            else:
                st.session_state.selected_host = target_to_scan

    # Handle Scan Execution
    if scan_btn:
        cleaned_target = (target_val or "").strip()
        if not cleaned_target:
            st.error("Target IP or Subnet cannot be empty.")
        else:
            norm_target = normalize_target(cleaned_target)
            st.session_state.target_ip = norm_target
            st.session_state.auth_result = None
            st.session_state.is_active = None
            st.session_state.active_hosts = []

            # Check format
            try:
                if "/" in norm_target:
                    ipaddress.ip_network(norm_target, strict=False)
                else:
                    ip_obj = ipaddress.ip_address(norm_target)
                    if str(ip_obj) in ("255.255.255.0", "255.255.0.0", "255.0.0.0", "255.255.255.255"):
                        st.error(f"'{norm_target}' is a subnet mask, not a valid IP or subnet. Use CIDR notation like '192.168.14.0/24'.")
                        st.stop()
            except ValueError:
                st.error(f"'{norm_target}' is not a valid IPv4 address or CIDR subnet notation.")
                st.stop()

            # Authorization Check
            authorized, reason = is_authorized(norm_target)
            if not authorized:
                st.session_state.pending_auth_target = norm_target
                st.session_state.pending_auth_reason = reason
            else:
                st.session_state.pending_auth_target = None
                st.session_state.pending_auth_reason = ""
                _execute_reachability_scan(norm_target)

    # Inline Target Authorization Prompt (Rendered top-level so button clicks register)
    if st.session_state.pending_auth_target:
        p_target = st.session_state.pending_auth_target
        p_reason = st.session_state.pending_auth_reason
        st.warning(f"⚠️ Authorization Required: {p_reason}")
        auth_col1, auth_col2 = st.columns([2, 1])
        with auth_col1:
            st.write(f"Do you own or manage **{p_target}** and authorize configuration retrieval?")
        with auth_col2:
            if st.button("✅ Authorize Target & Proceed", key="btn_authorize_now", type="primary", use_container_width=True):
                add_authorized_target(p_target)
                st.session_state.pending_auth_target = None
                st.session_state.pending_auth_reason = ""
                st.success(f"Authorized {p_target}!")
                _execute_reachability_scan(p_target)
                st.rerun()

    # Display Scan Results
    if st.session_state.is_active is False:
        st.markdown(
            f'<div class="status-badge-inactive">❌ Target {st.session_state.target_ip} is INACTIVE / Offline</div>',
            unsafe_allow_html=True
        )
        st.warning(
            f"Could not confirm reachability to `{st.session_state.target_ip}` from this machine.\n\n"
            "- If testing a private LAN address (e.g. 192.168.x.x or 10.x.x.x), ensure this host has network routing or VPN.\n"
            "- For quick demonstration or testing, try `127.0.0.1`."
        )

    elif st.session_state.is_active is True:
        st.markdown(
            f'<div class="status-badge-active">✅ Target {st.session_state.target_ip} is ONLINE & REACHABLE</div>',
            unsafe_allow_html=True
        )
        st.write("")

        # Host selection if subnet was scanned
        active_list = st.session_state.active_hosts or [st.session_state.target_ip]
        col_m1, col_m2, col_m3 = st.columns(3)
        with col_m1:
            st.metric("Status", "ONLINE / ACTIVE")
        with col_m2:
            st.metric("Discovered Hosts", len(active_list))
        with col_m3:
            if len(active_list) > 1:
                selected_host = st.selectbox("Target Firewall Host:", options=active_list, index=0)
                st.session_state.selected_host = selected_host
            else:
                st.session_state.selected_host = active_list[0]
                st.metric("Target Gateway Host", st.session_state.selected_host)

        st.divider()

        # -------------------------------------------------------------
        # Step 2: Authentication & Gateway Credentials
        # -------------------------------------------------------------
        st.markdown('<span class="step-pill">STEP 2</span> ### 🔐 Firewall Authentication & Configuration Pull', unsafe_allow_html=True)
        st.caption("Enter firewall administrator credentials or API token. Credentials remain securely masked.")

        auth_col1, auth_col2 = st.columns([2, 1])
        with auth_col1:
            password = st.text_input(
                f"Password / API Token for {st.session_state.selected_host}:",
                type="password",
                placeholder="••••••••••••",
                help="Input is securely masked in UI and not logged to disk."
            )
            if demo_mode:
                st.caption("💡 *Demo Mode Credential Suggestions: `admin`, `admin123`, or `firewall123`*")
        with auth_col2:
            st.write("")
            st.write("")
            pull_btn = st.button("🚀 Authenticate & Download Config", type="primary", use_container_width=True)

        if pull_btn:
            if not password:
                st.warning("Please enter a password or API token to authenticate.")
            else:
                with st.spinner(f"Authenticating with {st.session_state.selected_host} and pulling configuration..."):
                    graph = build_graph()
                    state_input: AuditState = {
                        "target": st.session_state.target_ip,
                        "selected_host": st.session_state.selected_host,
                        "is_active": True,
                        "password": password,
                        "pull_vendor_config": True,
                        "use_llm": bool(use_llm),
                        "hf_token": hf_token_custom if use_llm else "",
                        "hf_model": selected_hf_model if use_llm else "",
                        "vendor": selected_vendor,
                        "force_authorize": True,
                        "demo_mode": demo_mode,
                        "errors": [],
                    }
                    result = graph.invoke(state_input)
                    st.session_state.auth_result = result

    # -------------------------------------------------------------
    # Step 3: Download & Audit Results Dashboard
    # -------------------------------------------------------------
    if st.session_state.auth_result:
        res = st.session_state.auth_result
        auth_success = res.get("auth_success", False)
        downloaded_json = res.get("downloaded_file")
        downloaded_cfg = res.get("downloaded_cfg_file")
        report_md = res.get("report_md_path")
        report_json = res.get("report_path")
        vendor_data = res.get("vendor_config") or {}
        errors = res.get("errors") or []

        st.divider()
        st.markdown('<span class="step-pill">STEP 3</span> ### 📊 Configuration Retrieval & Security Audit Dashboard', unsafe_allow_html=True)

        if not auth_success or not downloaded_json:
            st.error("❌ Authentication or Configuration Retrieval Failed.")
            if errors:
                with st.expander("Diagnostic Error Details", expanded=True):
                    for err in errors:
                        st.write(f"- ⚠️ {err}")
            st.info("Tip: Double-check your password. In Demo Mode, passwords like `admin` or `admin123` are accepted.")
        else:
            is_synthetic = res.get("demo_mode", False)
            if is_synthetic:
                st.info("🛡️ **Demo Mode Retained**: Successfully authenticated and retrieved firewall configuration sample.")
            else:
                st.success("✅ **Live Configuration Retrieved**: Successfully downloaded and verified firewall policies.")

            # Device Classification & AI Fingerprinting Card
            classified_list = res.get("classified", [])
            if classified_list:
                with st.expander("🤖 AI Device Fingerprinting & Vendor Classification", expanded=True):
                    for c_item in classified_list:
                        cc1, cc2, cc3 = st.columns([1.5, 1, 3])
                        with cc1:
                            st.write(f"**Target IP:** `{c_item.get('ip')}`")
                            st.write(f"**Classified Vendor:** `{c_item.get('vendor')}`")
                        with cc2:
                            c_conf = float(c_item.get("confidence", 0.5))
                            st.metric("Confidence", f"{int(c_conf * 100)}%")
                            if c_item.get("classifier_type") == "llm" or res.get("use_llm"):
                                st.caption("✨ Hugging Face LLM")
                            else:
                                st.caption("📏 Rule-Based Heuristic")
                        with cc3:
                            st.write("**Classification Evidence & Reason:**")
                            st.info(c_item.get("reason", "No justification provided."))

            # File Details & Action Metrics
            f_size = os.path.getsize(downloaded_json) if os.path.exists(downloaded_json) else 0
            policies_list = vendor_data.get("firewall_policy", [])
            interfaces_list = vendor_data.get("interfaces", [])

            stat1, stat2, stat3, stat4 = st.columns(4)
            with stat1:
                st.metric("Firewall Host", res.get("selected_host") or st.session_state.target_ip)
            with stat2:
                st.metric("Vendor Profile", (vendor_data.get("system_status", {}).get("vendor") or "FortiGate").capitalize())
            with stat3:
                st.metric("Policies Loaded", len(policies_list))
            with stat4:
                st.metric("Config File Size", f"{f_size} bytes")

            # Download Action Center
            st.markdown("#### 📥 Download Center")
            d1, d2, d3, d4 = st.columns(4)

            # JSON config download
            if downloaded_json and os.path.exists(downloaded_json):
                with open(downloaded_json, "r", encoding="utf-8") as f:
                    json_data = f.read()
                d1.download_button(
                    label="📥 Download JSON Config",
                    data=json_data,
                    file_name=os.path.basename(downloaded_json),
                    mime="application/json",
                    use_container_width=True
                )

            # CFG file download
            if downloaded_cfg and os.path.exists(downloaded_cfg):
                with open(downloaded_cfg, "r", encoding="utf-8") as f:
                    cfg_data = f.read()
                d2.download_button(
                    label="📥 Download Text .CFG",
                    data=cfg_data,
                    file_name=os.path.basename(downloaded_cfg),
                    mime="text/plain",
                    use_container_width=True
                )

            # Report MD download
            if report_md and os.path.exists(report_md):
                with open(report_md, "r", encoding="utf-8") as f:
                    md_data = f.read()
                d3.download_button(
                    label="📑 Download Audit Report (.md)",
                    data=md_data,
                    file_name=os.path.basename(report_md),
                    mime="text/markdown",
                    use_container_width=True
                )

            # Report JSON download
            if report_json and os.path.exists(report_json):
                with open(report_json, "r", encoding="utf-8") as f:
                    rep_json_data = f.read()
                d4.download_button(
                    label="📊 Download Audit (.json)",
                    data=rep_json_data,
                    file_name=os.path.basename(report_json),
                    mime="application/json",
                    use_container_width=True
                )

            st.write("")

            # Results Tabs
            tab_pol, tab_intf, tab_rep, tab_sys, tab_raw = st.tabs([
                "🛡️ Firewall Policies",
                "🌐 Interfaces & Routing",
                "📊 Security Audit Report",
                "💻 System Status",
                "📜 Raw Configuration"
            ])

            # Tab 1: Policies
            with tab_pol:
                st.subheader("Configured Firewall Security Policies")
                if policies_list and isinstance(policies_list, list) and isinstance(policies_list[0], dict):
                    df_pol = pd.DataFrame(policies_list)
                    # Filter
                    search_pol = st.text_input("Filter policies by name or keyword:", "", key="policy_filter")
                    if search_pol:
                        df_pol = df_pol[df_pol.astype(str).apply(lambda row: row.str.contains(search_pol, case=False).any(), axis=1)]
                    st.dataframe(df_pol, use_container_width=True)
                else:
                    st.json(policies_list)

            # Tab 2: Interfaces & Routing
            with tab_intf:
                st.subheader("Network Interfaces")
                if interfaces_list and isinstance(interfaces_list, list) and isinstance(interfaces_list[0], dict):
                    df_intf = pd.DataFrame(interfaces_list)
                    st.dataframe(df_intf, use_container_width=True)
                else:
                    st.json(interfaces_list)

                routing_data = vendor_data.get("routing", [])
                if routing_data:
                    st.subheader("Static Routes")
                    st.dataframe(pd.DataFrame(routing_data), use_container_width=True)

            # Tab 3: Security Audit Report
            with tab_rep:
                st.subheader("Security Audit & Analysis Summary")
                if report_md and os.path.exists(report_md):
                    with open(report_md, "r", encoding="utf-8") as f:
                        st.markdown(f.read())
                else:
                    st.info("No markdown report generated.")

            # Tab 4: System Status
            with tab_sys:
                st.subheader("Firewall System Status & Hardware Information")
                sys_status = vendor_data.get("system_status", {})
                if sys_status:
                    sc1, sc2, sc3 = st.columns(3)
                    with sc1:
                        st.write(f"**Hostname:** `{sys_status.get('hostname', 'N/A')}`")
                        st.write(f"**Vendor:** `{sys_status.get('vendor', 'N/A')}`")
                    with sc2:
                        st.write(f"**Firmware Version:** `{sys_status.get('version', 'N/A')}`")
                        st.write(f"**Serial Number:** `{sys_status.get('serial', 'N/A')}`")
                    with sc3:
                        st.write(f"**Mode:** `{sys_status.get('mode', 'NAT/Route')}`")
                        st.write(f"**Uptime:** `{sys_status.get('uptime_seconds', 0)} seconds`")
                    st.divider()
                    st.json(sys_status)
                else:
                    st.info("System status details not available.")

            # Tab 5: Raw Configuration
            with tab_raw:
                st.subheader("Complete JSON Configuration Data")
                st.json(vendor_data)

# =====================================================================
# TAB 2: Previous Backups & Reports Explorer
# =====================================================================
with history_tab:
    st.subheader("📁 Saved Configurations & Audit Reports")
    st.caption("Browse and re-download previously pulled firewall configuration files and audit reports.")

    downloads_dir = ROOT / "downloads"
    reports_dir = ROOT / "reports"

    col_h1, col_h2 = st.columns(2)

    with col_h1:
        st.markdown("#### 📥 Downloaded Firewall Files")
        if downloads_dir.exists():
            cfg_files = sorted(
                list(downloads_dir.glob("firewall_config_*.*")),
                key=os.path.getmtime,
                reverse=True
            )
            if cfg_files:
                for fpath in cfg_files[:15]:
                    size_kb = round(os.path.getsize(fpath) / 1024, 2)
                    mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(fpath)))
                    with st.expander(f"📄 {fpath.name} ({size_kb} KB - {mtime})"):
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        st.download_button(
                            label=f"Download {fpath.name}",
                            data=content,
                            file_name=fpath.name,
                            key=f"dl_hist_{fpath.name}",
                            use_container_width=True
                        )
                        st.code(content[:1000] + ("\n... [truncated]" if len(content) > 1000 else ""), language="json" if fpath.suffix == ".json" else "text")
            else:
                st.info("No saved configuration files found in downloads folder.")
        else:
            st.info("Downloads folder does not exist yet.")

    with col_h2:
        st.markdown("#### 📊 Saved Audit Reports")
        if reports_dir.exists():
            rep_files = sorted(
                list(reports_dir.glob("audit-*.*")),
                key=os.path.getmtime,
                reverse=True
            )
            if rep_files:
                for rpath in rep_files[:15]:
                    size_kb = round(os.path.getsize(rpath) / 1024, 2)
                    mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(rpath)))
                    with st.expander(f"📑 {rpath.name} ({size_kb} KB - {mtime})"):
                        with open(rpath, "r", encoding="utf-8", errors="replace") as f:
                            rcontent = f.read()
                        st.download_button(
                            label=f"Download {rpath.name}",
                            data=rcontent,
                            file_name=rpath.name,
                            key=f"rep_hist_{rpath.name}",
                            use_container_width=True
                        )
                        if rpath.suffix == ".md":
                            st.markdown(rcontent)
                        else:
                            st.code(rcontent[:1000] + ("\n... [truncated]" if len(rcontent) > 1000 else ""), language="json")
            else:
                st.info("No saved audit reports found in reports folder.")
        else:
            st.info("Reports folder does not exist yet.")

# =====================================================================
# TAB 3: Guide & Usage
# =====================================================================
with guide_tab:
    st.markdown("""
    ### 📖 Firewall Agent Quick Start & Guide

    #### 🔄 Workflow Overview:
    1. **Target Reachability**:
       - Enter single host IP (e.g., `127.0.0.1`, `192.168.1.1`) or CIDR subnet (e.g., `192.168.14.0/24`).
       - Click **Check Reachability** to verify if the gateway is online via ICMP Ping and socket probe.
    2. **Authentication**:
       - When the target is confirmed online, enter the admin password or API token.
       - In **Demo Mode**, test credentials (`admin`, `admin123`, `firewall123`) authenticate immediately.
    3. **Configuration & Audit**:
       - Downloads configuration files directly into `downloads/` in both JSON and `.cfg` format.
       - Generates comprehensive security audit reports in `reports/` with markdown tables and JSON analysis.
    4. **Safety & Scope**:
       - Targets must be in the authorized scope (`authorized_subnets.yaml`) or explicitly authorized before scanning.
    """)
