import sys
sys.path.insert(0, '/home/aditya/sift-sentinel/src')

from sift_sentinel.evidence_graph.models import *
from sift_sentinel.evidence_graph.graph import EvidenceGraphManager

import os
graph_path = '/home/aditya/sentinel-output/evidence_graph.json'
if os.path.exists(graph_path):
    mgr = EvidenceGraphManager.load(graph_path)
else:
    mgr = EvidenceGraphManager("MINI-CASE-001")

# Register evidence sources for the three registry hives
if not mgr.graph.evidence_sources:
    mgr.add_source(
        source_type="registry_hive",
        path="~/cases/mini-case/Registry/SYSTEM",
        sha256="df7a71db7620833bd26c372ae2ea50af37b5373e68596f77baa96f19603299e7",
        mounted_at="~/cases/mini-case/Registry/SYSTEM",
        metadata={"hive": "SYSTEM", "tool": "regripper -a", "exec_id": "exec-rr-system"},
    )
    mgr.add_source(
        source_type="registry_hive",
        path="~/cases/mini-case/Registry/SOFTWARE",
        sha256="0fae27bfd7dfefa70a483bbf96cb4f48e3b2af6350746162f4796b3b9950576f",
        mounted_at="~/cases/mini-case/Registry/SOFTWARE",
        metadata={"hive": "SOFTWARE", "tool": "regripper -a", "exec_id": "exec-rr-software"},
    )
    mgr.add_source(
        source_type="registry_hive",
        path="~/cases/mini-case/Registry/SAM",
        sha256="150661dfad239bc7f5fc990904bc116208f802677cadefad22cb07f02d8e579a",
        mounted_at="~/cases/mini-case/Registry/SAM",
        metadata={"hive": "SAM", "tool": "regripper -a", "exec_id": "exec-rr-sam"},
    )

# --- F1: Local account with weak credential hygiene (SAM) ---
f1 = mgr.add_finding(
    summary=(
        "Local user account 'Aditya' (RID 1001) is configured with 'Password not "
        "required' and carries a password hint reading 'Same as the main google "
        "account pass', indicating the local Windows password is reused for the "
        "user's Google account and that an empty/blank password would be accepted "
        "by policy."
    ),
    category="account_anomaly",
    evidence_anchor=EvidenceAnchor(
        source_id="src-003",
        tool_execution_id="exec-rr-sam",
        artifact_path="SAM\\SAM\\Domains\\Account\\Users\\000003E9",
        log_entry=(
            "Username        : Aditya [1001]\n"
            "Password Hint   : Same as the main google account pass\n"
            "  --> Password not required\n"
            "  --> Password does not expire"
        ),
    ),
)

# --- F2: ngrok tunneling tool downloaded and executed ---
f2 = mgr.add_finding(
    summary=(
        "ngrok.exe (a third-party network tunneling/reverse-proxy utility) was "
        "downloaded to C:\\Users\\Aditya\\Downloads\\ngrok-v3-stable-windows-amd64\\ "
        "and executed under the user's SID (S-1-5-21-861007328-302799644-2273878273-1001) "
        "per the BAM record at 2026-06-08 11:46:12Z. A separate copy was also "
        "extracted/run from a temp zip path on 2026-06-05. ngrok can be used to "
        "expose local services to the internet or establish outbound tunnels, "
        "which is dual-use: legitimate for development but also a common "
        "remote-access/exfiltration technique."
    ),
    category="network_activity",
    evidence_anchor=EvidenceAnchor(
        source_id="src-001",
        tool_execution_id="exec-rr-system",
        artifact_path="\\Device\\HarddiskVolume3\\Users\\Aditya\\Downloads\\ngrok-v3-stable-windows-amd64\\ngrok.exe",
        log_entry=(
            "S-1-5-21-861007328-302799644-2273878273-1001\n"
            "  2026-06-08 11:46:12Z - \\Device\\HarddiskVolume3\\Users\\Aditya\\Downloads\\ngrok-v3-stable-windows-amd64\\ngrok.exe"
        ),
    ),
    mitre_attack=["T1572"],
)

# --- F3: sdbinst.exe execution under SYSTEM context (possible app shim install) ---
f3 = mgr.add_finding(
    summary=(
        "sdbinst.exe (Application Compatibility Database installer, used by "
        "T1546.011 'Application Shimming' persistence) was executed under the "
        "SYSTEM account (S-1-5-18) at 2026-06-13 22:56:07Z per the BAM record. "
        "No custom entries were found under AppCompatFlags\\Layers / Custom "
        "AppCompatDatabase in the SOFTWARE hive, so this is most likely a "
        "legitimate compatibility-shim registration performed by a software "
        "installer rather than malicious persistence, but the specific .sdb "
        "package installed could not be identified from registry data alone."
    ),
    category="persistence",
    evidence_anchor=EvidenceAnchor(
        source_id="src-001",
        tool_execution_id="exec-rr-system",
        artifact_path="\\Device\\HarddiskVolume3\\Windows\\System32\\sdbinst.exe",
        log_entry=(
            "S-1-5-18\n"
            "  2026-06-13 22:56:07Z - \\Device\\HarddiskVolume3\\Windows\\System32\\sdbinst.exe"
        ),
    ),
    mitre_attack=["T1546.011"],
)

# --- F4: VPN interface configured ---
f4 = mgr.add_finding(
    summary=(
        "A VPN network interface (adapter GUID {09DB18D7-2DE2-4430-A758-DAE53C8A58A9}, "
        "VPNInterface=1) is configured under "
        "ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces, last written "
        "2025-06-12 15:18:30Z. This indicates VPN client software has been used "
        "or configured on this host. No DHCP lease information is present for "
        "this adapter, consistent with a VPN tunnel interface rather than a "
        "physical NIC."
    ),
    category="network_activity",
    evidence_anchor=EvidenceAnchor(
        source_id="src-001",
        tool_execution_id="exec-rr-system",
        artifact_path="ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{09DB18D7-2DE2-4430-A758-DAE53C8A58A9}",
        log_entry=(
            "Adapter: {09DB18D7-2DE2-4430-A758-DAE53C8A58A9}\n"
            "LastWrite Time: 2025-06-12 15:18:30Z\n"
            "  VPNInterface                 1"
        ),
    ),
)

# --- F5: Orphaned scheduled task referencing a SID with no matching profile ---
f5 = mgr.add_finding(
    summary=(
        "A scheduled task 'OneDrive Standalone Update Task-S-1-5-21-2789877619-886443328-3103818696-500' "
        "(Task Reg Time 2023-06-08 21:16:22Z, last run 2024-03-12 15:11:29Z) "
        "references SID S-1-5-21-2789877619-886443328-3103818696-500 (RID 500, "
        "i.e. a built-in Administrator account). This SID does not correspond to "
        "any account in ProfileList (the only local profile present is "
        "S-1-5-21-861007328-302799644-2273878273-1001 'Aditya'), and the SID's "
        "machine identifier portion (2789877619-886443328-3103818696) differs "
        "from the current machine SID (861007328-302799644-2273878273). This is "
        "consistent with a leftover scheduled task from a prior Windows "
        "installation/profile that was not cleaned up during reimage or in-place "
        "upgrade."
    ),
    category="account_anomaly",
    evidence_anchor=EvidenceAnchor(
        source_id="src-002",
        tool_execution_id="exec-rr-software",
        artifact_path="Microsoft\\Windows\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
        log_entry=(
            "Path: \\OneDrive Standalone Update Task-S-1-5-21-2789877619-886443328-3103818696-500\n"
            "URI : \\OneDrive Standalone Update Task-S-1-5-21-2789877619-886443328-3103818696-500\n"
            "Task Reg Time : 2023-06-08 21:16:22Z\n"
            "Task Last Run : 2024-03-12 15:11:29Z"
        ),
    ),
)

# --- F6: Services review - no unusual/unauthorized services found ---
f6 = mgr.add_finding(
    summary=(
        "Full review of ControlSet001\\Services (RegRipper 'services' plugin, "
        "~280 entries) found no services with ImagePath values pointing to "
        "user-writable locations (Temp, AppData, Downloads) or unsigned/unknown "
        "binaries. All non-Microsoft services correspond to known legitimate "
        "third-party software already present on this developer/gaming "
        "workstation (NVIDIA, MSI, Adobe, Steam, Docker, PostgreSQL, MySQL, "
        "Splunk, Brave/Edge/Chrome updaters, BattlEye, Windhawk, OpenSSH "
        "ssh-agent, etc.). No suspicious autostart services were identified."
    ),
    category="persistence",
    status=FindingStatus.INFERRED,
    evidence_anchor=EvidenceAnchor(
        source_id="src-001",
        tool_execution_id="exec-rr-system",
        artifact_path="ControlSet001\\Services",
        log_entry="services v.20191024 - Lists services/drivers in Services key by LastWrite times",
    ),
)
mgr.set_reasoning_chain(
    f6.finding_id,
    premises=[
        "RegRipper 'services' plugin enumerated all ControlSet001\\Services subkeys with ImagePath values.",
        "None of the non-Microsoft ImagePath values point to Temp, AppData, Downloads, or other user-writable paths.",
        "All identified third-party services map to software products with corresponding installations/BAM execution evidence on this host.",
    ],
    logic=(
        "Absence of unusual service ImagePaths across a full enumeration is "
        "itself a finding worth recording per analysis rules: it establishes "
        "that no obvious service-based persistence mechanism is present."
    ),
    corroboration_type=CorroborationType.SINGLE_SOURCE_NARRATED,
)

mgr.save(graph_path)
print("Findings added:")
for f in (f1, f2, f3, f4, f5, f6):
    print(f"  {f.finding_id}: {f.summary[:90]}...")
