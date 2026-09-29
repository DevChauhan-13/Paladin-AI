/**
 * Paladin AI SOC Investigation - Forensic Drill-Down View Logic
 * Handles detector-specific Chart.js evidence visualizations,
 * D3.js blast radius node-link graphs, KV feature tables, and "Why Not X" meta-scoring.
 * Fully supports Dark Mode and White/Light Theme dynamically.
 */

(function () {
  'use strict';

  // --- Comprehensive Alert Evidence Store for All 6 Threat Classes ---
  const INVESTIGATION_DATABASE = {
    "ALT-2026-9041": {
      id: "ALT-2026-9041",
      timestamp: "2026-09-28T02:14:15.000Z",
      flow_id: "FLW-88319-TCP",
      threat_class: "Data Exfiltration",
      severity: "critical",
      confidence: 0.96,
      calibration: "Higher than 98% of past confirmed exfiltration events",
      summary: "High-volume outbound byte asymmetry (418 MB out vs 14 KB in) over encrypted tunnel to unindexed IP",
      src_ip: "10.0.12.84",
      src_port: 49822,
      dst_ip: "203.0.113.88",
      dst_port: 443,
      proto: "TCP/TLS 1.3",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      evidence_features: [
        { label: "Flow Duration", value: "142.6 seconds", highlight: false },
        { label: "Outbound Bytes", value: "438,304,768 B (418.0 MB)", highlight: true },
        { label: "Inbound Bytes", value: "14,336 B (14.0 KB)", highlight: false },
        { label: "Asymmetry Ratio", value: "30,573 : 1 (Exfiltration Index > 99.8th percentile)", highlight: true },
        { label: "Payload Entropy", value: "7.94 / 8.00 (High Compression / Ciphertext)", highlight: true },
        { label: "Destination ASN", value: "AS64512 (Uncategorized Bulletproof Hosting)", highlight: true },
        { label: "Zeek Connection State", value: "SF (Normal syn-ack teardown)", highlight: false },
        { label: "Sensor ID", value: "NTRO-DIODE-ZEEK-01", highlight: false }
      ],
      why_not: [
        { threat: "Normal Cloud Backup", reason: "Target IP not registered in approved corporate cloud egress whitelist (S3/Azure/GCS)." },
        { threat: "Software Update Download", reason: "Traffic direction is predominantly outbound (99.996% upload vs 0.004% download)." },
        { threat: "Volumetric DDoS", reason: "Packet arrival rate (312 pps) is within steady-state link capacity; flag is on byte payload asymmetry, not PPS volume." }
      ],
      related_alerts: [
        { id: "ALT-2026-9039", class: "Botnet C2 Beaconing", sev: "high", summary: "Periodic TCP heartbeats from 10.0.12.84 to 198.51.100.44", time: "12m ago" },
        { id: "ALT-2026-8992", class: "Reconnaissance/Port Scanning", sev: "low", summary: "Internal port scan originated from 10.0.12.84 to subnet 10.0.4.0/24", time: "3h ago" }
      ],
      has_blast_radius: true,
      blast_nodes: [
        { id: "10.0.12.84", name: "10.0.12.84 (Compromised Host)", type: "source", active_alert: true },
        { id: "203.0.113.88", name: "203.0.113.88 (Exfil Drop)", type: "external", active_alert: true },
        { id: "198.51.100.44", name: "198.51.100.44 (C2 Staging)", type: "external", active_alert: true },
        { id: "10.0.1.10", name: "10.0.1.10 (Domain Controller)", type: "internal", active_alert: false },
        { id: "10.0.12.1", name: "10.0.12.1 (VLAN Gateway)", type: "internal", active_alert: false },
        { id: "10.0.12.55", name: "10.0.12.55 (Fileserver / SMB)", type: "internal", active_alert: true },
        { id: "10.0.12.92", name: "10.0.12.92 (Workstation)", type: "internal", active_alert: false },
        { id: "10.0.8.20", name: "10.0.8.20 (Database Core)", type: "internal", active_alert: false },
        { id: "10.0.4.119", name: "10.0.4.119 (Jump Host)", type: "internal", active_alert: true },
        { id: "10.0.4.15", name: "10.0.4.15 (Build Server)", type: "internal", active_alert: false },
        { id: "8.8.8.8", name: "8.8.8.8 (Google DNS)", type: "external", active_alert: false },
        { id: "1.1.1.1", name: "1.1.1.1 (Cloudflare DNS)", type: "external", active_alert: false }
      ],
      blast_links: [
        { source: "10.0.12.84", target: "203.0.113.88", label: "HTTPS 418MB" },
        { source: "10.0.12.84", target: "198.51.100.44", label: "TLS/8443 1.2MB" },
        { source: "10.0.12.84", target: "10.0.12.55", label: "SMB/445 422MB" },
        { source: "10.0.12.84", target: "10.0.1.10", label: "Kerberos/88 84KB" },
        { source: "10.0.12.84", target: "10.0.12.1", label: "ARP / Gateway" },
        { source: "10.0.12.84", target: "10.0.12.92", label: "RPC/135 12KB" },
        { source: "10.0.12.84", target: "10.0.8.20", label: "TDS/1433 18MB" },
        { source: "10.0.12.84", target: "10.0.4.119", label: "SSH/22 4KB" },
        { source: "10.0.12.84", target: "8.8.8.8", label: "DNS/53 2KB" },
        { source: "10.0.4.119", target: "10.0.4.15", label: "RDP/3389" }
      ]
    },
    "ALT-2026-9040": {
      id: "ALT-2026-9040",
      timestamp: "2026-09-28T02:13:00.000Z",
      flow_id: "FLW-88314-UDP",
      threat_class: "DGA Domains / DNS Tunneling",
      severity: "critical",
      confidence: 0.94,
      calibration: "Higher than 95% of confirmed DNS tunnel events",
      summary: "High-entropy domain queries (4.38 n-gram) with 380 QPS burst to authoritative server",
      src_ip: "10.0.4.119",
      src_port: 53210,
      dst_ip: "198.51.100.12",
      dst_port: 53,
      proto: "UDP/DNS",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      evidence_features: [
        { label: "Queried Domain", value: "qx9z-v88a-secops-update.dyn-dns.io", highlight: true },
        { label: "Shannon Entropy", value: "4.38 bits/char (Normal Alexa Top 1M = 2.45)", highlight: true },
        { label: "Bi-gram Frequency Score", value: "0.0084 (Extremely abnormal consonant clustering)", highlight: true },
        { label: "Query Rate (QPS)", value: "380 queries/sec (Burst Duration: 4.8s)", highlight: true },
        { label: "Record Type Ratio", value: "88% TXT, 12% A (Signature DNS Tunnel payload)", highlight: true },
        { label: "Authoritative Nameserver", value: "ns1.dyn-dns.io [198.51.100.12]", highlight: false },
        { label: "Suricata Signature ID", value: "2028441 (ET MALWARE DGA Query Pattern)", highlight: false }
      ],
      why_not: [
        { threat: "Legitimate CDN Domain Resolution", reason: "Entropy score 4.38 exceeds 99.9th percentile for commercial CDNs (Akamai/Cloudflare mean 2.8)." },
        { threat: "Anti-Spam RBL Lookup", reason: "Queries directed to single unindexed IP instead of distributed public Spamhaus/Sorbs resolvers." }
      ],
      related_alerts: [
        { id: "ALT-2026-9037", class: "Reconnaissance/Port Scanning", sev: "medium", summary: "Port scan sweep from 10.0.4.119 to subnet 10.0.4.0/24", time: "8m ago" }
      ],
      has_blast_radius: false
    },
    "ALT-2026-9039": {
      id: "ALT-2026-9039",
      timestamp: "2026-09-28T02:11:40.000Z",
      flow_id: "FLW-88299-TCP",
      threat_class: "Botnet C2 Beaconing",
      severity: "high",
      confidence: 0.91,
      calibration: "Higher than 91% of confirmed C2 beacon detections",
      summary: "Periodic TCP heartbeats with low jitter (delta: 60.1s ±0.4s) to external staging IP",
      src_ip: "10.0.12.84",
      src_port: 51240,
      dst_ip: "198.51.100.44",
      dst_port: 8443,
      proto: "TCP/HTTPS",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      evidence_features: [
        { label: "Beacon Interval", value: "60.1 seconds (Strict periodicity)", highlight: true },
        { label: "Timing Jitter", value: "0.65% (Calculated deviation ±0.39s)", highlight: true },
        { label: "Streak Length", value: "24 consecutive intervals observed without drop", highlight: true },
        { label: "Burst Packet Count", value: "4 packets per handshake (184 bytes payload)", highlight: false },
        { label: "Destination Port", value: "8443 (Non-standard TLS service)", highlight: false },
        { label: "TLS SNI Field", value: "telemetry-sync-cdn.xyz", highlight: true }
      ],
      why_not: [
        { threat: "NTP Time Sync", reason: "Protocol is TLS over port 8443, not UDP port 123; fixed payload size differs from RFC 5905 spec." },
        { threat: "Browser Keepalive", reason: "Strict 60.1s regularity maintained for 24 min continuously during zero human user activity hours." }
      ],
      related_alerts: [
        { id: "ALT-2026-9041", class: "Data Exfiltration", sev: "critical", summary: "418 MB byte asymmetry outbound from 10.0.12.84", time: "3m ago" }
      ],
      has_blast_radius: true,
      blast_nodes: [
        { id: "10.0.12.84", name: "10.0.12.84 (Beacon Source)", type: "source", active_alert: true },
        { id: "198.51.100.44", name: "198.51.100.44 (C2 Server)", type: "external", active_alert: true },
        { id: "10.0.1.10", name: "10.0.1.10 (Active Directory)", type: "internal", active_alert: false },
        { id: "10.0.12.1", name: "10.0.12.1 (Core Gateway)", type: "internal", active_alert: false },
        { id: "10.0.12.22", name: "10.0.12.22 (Peer Host)", type: "internal", active_alert: false },
        { id: "10.0.12.90", name: "10.0.12.90 (Finance PC)", type: "internal", active_alert: false },
        { id: "10.0.4.119", name: "10.0.4.119 (Jump Host)", type: "internal", active_alert: true }
      ],
      blast_links: [
        { source: "10.0.12.84", target: "198.51.100.44", label: "Heartbeat/60s" },
        { source: "10.0.12.84", target: "10.0.1.10", label: "Kerberos TGT" },
        { source: "10.0.12.84", target: "10.0.12.1", label: "Default Route" },
        { source: "10.0.12.84", target: "10.0.12.22", label: "RPC / Ping" },
        { source: "10.0.12.84", target: "10.0.12.90", label: "SMB Probe" },
        { source: "10.0.12.84", target: "10.0.4.119", label: "SSH" }
      ]
    },
    "ALT-2026-9038": {
      id: "ALT-2026-9038",
      timestamp: "2026-09-28T02:09:30.000Z",
      flow_id: "FLW-88280-TCP",
      threat_class: "Malware in Encrypted Sessions (TLS/QUIC)",
      severity: "high",
      confidence: 0.88,
      calibration: "Higher than 87% of past malware fingerprint matches",
      summary: "JA3 hash matches known CobaltStrike malleable C2 profile with anomalous initial burst lengths",
      src_ip: "10.0.8.210",
      src_port: 48991,
      dst_ip: "192.0.2.145",
      dst_port: 443,
      proto: "TCP/TLS 1.3",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      evidence_features: [
        { label: "JA3 Fingerprint", value: "a0e9f5d64349fb13191bc781f81f42e8 (CobaltStrike C2 Profile)", highlight: true },
        { label: "JA3S Server Response", value: "ec74a5c5110605f9f8eac32c925904e7 (Known Malicious Daemon)", highlight: true },
        { label: "X.509 Subject", value: "CN=internal-telemetry-cdn.net (Self-signed Untrusted CA)", highlight: true },
        { label: "Cert Validity Period", value: "7 Days (Ephemeral Staging Certificate)", highlight: true },
        { label: "TLS Version", value: "TLSv1.3 (Cipher: TLS_AES_256_GCM_SHA384)", highlight: false },
        { label: "Packet Burst Profile", value: "Micro-bursts of 240, 240, 512, 1024 bytes (Handshake signature)", highlight: true }
      ],
      why_not: [
        { threat: "Standard Chrome / Firefox Session", reason: "JA3 fingerprint does not match any official Chromium or Gecko TLS client hello distributions." },
        { threat: "Legitimate Corporate VPN", reason: "Certificate authority is self-signed and missing root cross-signing in enterprise trust store." }
      ],
      related_alerts: [],
      has_blast_radius: false
    },
    "ALT-2026-9037": {
      id: "ALT-2026-9037",
      timestamp: "2026-09-28T02:06:50.000Z",
      flow_id: "FLW-88250-TCP",
      threat_class: "Reconnaissance/Port Scanning",
      severity: "medium",
      confidence: 0.85,
      calibration: "Higher than 84% of confirmed scan sweeps",
      summary: "Fast horizontal SYN probe against 1,024 destination ports across internal subnet 10.0.4.0/24",
      src_ip: "10.0.4.119",
      src_port: 60102,
      dst_ip: "10.0.4.1/24",
      dst_port: "Multi (1-1024)",
      proto: "TCP/SYN",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      evidence_features: [
        { label: "Probed Ports", value: "1,024 Distinct Ports (1 to 1024 Standard Well-Known Range)", highlight: true },
        { label: "SYN-to-ACK Ratio", value: "0.99 (99% unmatched half-open SYN packets)", highlight: true },
        { label: "Sweep Duration", value: "14.2 seconds (High concurrency thread pool)", highlight: false },
        { label: "Fan-Out Target Count", value: "64 internal host addresses contacted", highlight: true },
        { label: "RST Rate Received", value: "812 RST packets returned from closed endpoints", highlight: false },
        { label: "Scanner Heuristic", value: "Nmap SYN Stealth (-sS) timing template T4 match", highlight: true }
      ],
      why_not: [
        { threat: "Legitimate Nessus / Vulnerability Scanner", reason: "Source host 10.0.4.119 is a workstation jump-box, not a registered Qualys/Nessus security scanner IP." },
        { threat: "Distributed Denial of Service", reason: "Targeting multiple sequential internal ports with single SYN probes rather than flooding single port with high bandwidth." }
      ],
      related_alerts: [
        { id: "ALT-2026-9040", class: "DGA Domains / DNS Tunneling", sev: "critical", summary: "High-entropy DNS queries from 10.0.4.119", time: "6m ago" }
      ],
      has_blast_radius: false
    },
    "ALT-2026-9036": {
      id: "ALT-2026-9036",
      timestamp: "2026-09-28T02:04:10.000Z",
      flow_id: "FLW-88210-UDP",
      threat_class: "Volumetric/Protocol DDoS",
      severity: "critical",
      confidence: 0.97,
      calibration: "Higher than 99% of volumetric anomaly baselines",
      summary: "Abnormal ingress packet surge (14,200 pps) targeting core perimeter routing interface",
      src_ip: "Multiple (Botnet)",
      src_port: 0,
      dst_ip: "10.0.1.1",
      dst_port: 53,
      proto: "UDP/DNS Amplification",
      state: "confirmed",
      analyst_label: "confirmed",
      analyst_note: "Upstream ACL filter engaged at border router",
      evidence_features: [
        { label: "Ingress Packet Rate", value: "14,200 pkts/sec (Normal Baseline: 420 pps)", highlight: true },
        { label: "Source IP Entropy", value: "0.12 (Reflected amplification from fixed reflector pool)", highlight: true },
        { label: "Bandwidth Consumed", value: "1.42 Gbps at physical diode optical interface", highlight: true },
        { label: "Amplification Factor", value: "48x payload multiplier (ANY query response flood)", highlight: true },
        { label: "Target Interface", value: "ETH-CORE-DIODE-INGRESS-01", highlight: false },
        { label: "Mitigation State", value: "Rate-limiting applied at upstream BGP peer", highlight: false }
      ],
      why_not: [
        { threat: "Legitimate Peak Traffic", reason: "3,380% surge over historical 30-day baseline during off-peak maintenance window." },
        { threat: "Internal Network Loop", reason: "Hop count (TTL) indicates packets traversed external WAN autonomous systems." }
      ],
      related_alerts: [],
      has_blast_radius: false
    }
  };

  // Helper to check current theme
  function isLightTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' || document.body.classList.contains('theme-light');
  }

  // Helper to get alert from URL param
  function getActiveAlert() {
    const urlParams = new URLSearchParams(window.location.search);
    const alertId = urlParams.get('alert_id') || 'ALT-2026-9041';
    return INVESTIGATION_DATABASE[alertId] || INVESTIGATION_DATABASE["ALT-2026-9041"];
  }

  // --- 1. Render Investigator Header & Meta ---
  function renderHeader(alert) {
    const titleEl = document.getElementById('invTitle');
    const badgeEl = document.getElementById('invClassBadge');
    const stateEl = document.getElementById('invStateBadge');
    const flowIdEl = document.getElementById('invFlowId');
    const calibEl = document.getElementById('invCalib');
    const timestampEl = document.getElementById('invTimestamp');
    const networkEl = document.getElementById('invNetwork');

    if (titleEl) titleEl.textContent = alert.summary;
    if (badgeEl) {
      badgeEl.className = `soc-threat-badge ${getSevClass(alert.severity)}`;
      badgeEl.textContent = alert.threat_class;
    }
    if (stateEl) {
      if (alert.analyst_label === 'confirmed') {
        stateEl.className = 'soc-state-badge confirmed';
        stateEl.textContent = '✓ CONFIRMED THREAT';
      } else if (alert.analyst_label === 'false_positive') {
        stateEl.className = 'soc-state-badge fp';
        stateEl.textContent = 'FALSE POSITIVE';
      } else {
        stateEl.className = 'soc-state-badge active';
        stateEl.textContent = 'ACTIVE';
      }
    }
    if (flowIdEl) flowIdEl.textContent = alert.flow_id;
    if (calibEl) calibEl.textContent = `Confidence: ${(alert.confidence * 100).toFixed(0)}% — ${alert.calibration}`;
    if (timestampEl) timestampEl.textContent = new Date(alert.timestamp).toUTCString();
    if (networkEl) {
      networkEl.textContent = `${alert.src_ip}:${alert.src_port || 'any'} → ${alert.dst_ip}:${alert.dst_port || 'any'} (${alert.proto})`;
    }

    // JSON Raw Toggle
    const jsonBody = document.getElementById('rawJsonContent');
    if (jsonBody) {
      jsonBody.textContent = JSON.stringify(alert, null, 2);
    }
  }

  // Helper
  function getSevClass(sev) {
    switch (sev) {
      case 'critical': return 'crit';
      case 'high': return 'high';
      case 'medium': return 'med';
      case 'low': return 'low';
      default: return 'low';
    }
  }

  // --- 2. Render Key-Value Forensic Table ---
  function renderKvList(alert) {
    const listEl = document.getElementById('evidenceKvList');
    if (!listEl) return;

    listEl.innerHTML = alert.evidence_features.map(item => `
      <div class="soc-kv-row">
        <span class="soc-kv-label">${item.label}</span>
        <span class="soc-kv-value ${item.highlight ? 'highlight' : ''}">${item.value}</span>
      </div>
    `).join('');
  }

  // --- 3. Render Why-Not Reasoning List ---
  function renderWhyNot(alert) {
    const listEl = document.getElementById('whyNotList');
    if (!listEl) return;

    if (!alert.why_not || alert.why_not.length === 0) {
      listEl.innerHTML = `<div style="font-size: 12px; color: var(--soc-text-dim);">No alternative classifications evaluated by the meta-scorer.</div>`;
      return;
    }

    listEl.innerHTML = alert.why_not.map(item => `
      <div class="soc-why-not-item">
        <span class="soc-why-not-class">NOT ${item.threat}</span>
        <span class="soc-why-not-reason">${item.reason}</span>
      </div>
    `).join('');
  }

  // --- 4. Render Related Alerts ---
  function renderRelatedAlerts(alert) {
    const listEl = document.getElementById('relatedAlertsList');
    if (!listEl) return;

    if (!alert.related_alerts || alert.related_alerts.length === 0) {
      listEl.innerHTML = `<div style="font-size: 12px; color: var(--soc-text-dim);">No correlated alerts detected for this entity in the 24h window.</div>`;
      return;
    }

    listEl.innerHTML = alert.related_alerts.map(rel => `
      <a href="investigation.html?alert_id=${encodeURIComponent(rel.id)}" class="soc-related-item ${getSevClass(rel.sev)}">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="soc-threat-badge ${getSevClass(rel.sev)}" style="font-size: 9px; padding: 2px 6px;">${rel.class}</span>
          <span class="soc-related-summary">${rel.summary}</span>
        </div>
        <span class="soc-related-time">${rel.time}</span>
      </a>
    `).join('');
  }

  // --- 5. Chart.js Detector-Specific Evidence Charts (PRD 2.3) ---
  let activeChartInstance = null;

  function renderEvidenceChart(alert) {
    const canvas = document.getElementById('evidenceChart');
    if (!canvas) return;

    if (activeChartInstance) {
      activeChartInstance.destroy();
    }

    const ctx = canvas.getContext('2d');
    const chartTitleEl = document.getElementById('chartTitle');
    const chartSubtitleEl = document.getElementById('chartSubtitle');

    const isLight = isLightTheme();
    const textColor = isLight ? '#555960' : '#8b949e';
    const gridColor = isLight ? 'rgba(0, 0, 0, 0.08)' : 'rgba(255, 255, 255, 0.06)';

    // Chart.js Theme Defaults
    Chart.defaults.color = textColor;
    Chart.defaults.borderColor = gridColor;
    Chart.defaults.font.family = "'IBM Plex Mono', monospace";
    Chart.defaults.font.size = 10;

    switch (alert.threat_class) {
      // 1. Data Exfiltration: Outbound vs Inbound Asymmetry
      case "Data Exfiltration":
        if (chartTitleEl) chartTitleEl.textContent = "OUTBOUND VS INBOUND BYTE VOLUME ASYMMETRY";
        if (chartSubtitleEl) chartSubtitleEl.textContent = "Observed Flow Time Series (KB/sec) — Red: Outbound, Green: Inbound";

        activeChartInstance = new Chart(ctx, {
          type: 'line',
          data: {
            labels: ['00:00', '00:20', '00:40', '01:00', '01:20', '01:40', '02:00', '02:22'],
            datasets: [
              {
                label: 'Outbound Egress (MB/s)',
                data: [0.1, 1.2, 4.8, 18.2, 38.5, 52.1, 48.0, 12.4],
                borderColor: '#d50f3b',
                backgroundColor: 'rgba(213, 15, 59, 0.15)',
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointRadius: 4,
                pointBackgroundColor: '#d50f3b'
              },
              {
                label: 'Inbound Ingress (KB/s)',
                data: [0.05, 0.08, 0.06, 0.11, 0.15, 0.12, 0.09, 0.04],
                borderColor: '#2ecc71',
                borderWidth: 1.5,
                borderDash: [4, 4],
                fill: false,
                tension: 0.1,
                pointRadius: 2
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'top', labels: { boxWidth: 12, padding: 14 } }
            },
            scales: {
              y: { title: { display: true, text: 'Throughput (MB/s)' }, grid: { color: gridColor } },
              x: { title: { display: true, text: 'Flow Time (MM:SS)' }, grid: { color: gridColor } }
            }
          }
        });
        break;

      // 2. DGA Domains / DNS Tunneling: Entropy & N-Gram Distribution
      case "DGA Domains / DNS Tunneling":
        if (chartTitleEl) chartTitleEl.textContent = "DOMAIN SHANNON ENTROPY VS ALEXA TOP 1M DISTRIBUTION";
        if (chartSubtitleEl) chartSubtitleEl.textContent = "Observed 4.38 Entropy against Normal Baseline (Mean 2.45)";

        activeChartInstance = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['1.0 - 1.5', '1.5 - 2.0', '2.0 - 2.5', '2.5 - 3.0', '3.0 - 3.5', '3.5 - 4.0', '4.0 - 4.5 [FLAGGED]'],
            datasets: [
              {
                label: 'Reference Legitimate Domains',
                data: [120, 480, 1420, 890, 210, 45, 2],
                backgroundColor: isLight ? 'rgba(74, 127, 165, 0.6)' : 'rgba(74, 127, 165, 0.45)',
                borderColor: '#4a7fa5',
                borderWidth: 1
              },
              {
                label: 'Queried Suspicious Cluster',
                data: [0, 0, 0, 0, 14, 88, 380],
                backgroundColor: 'rgba(213, 15, 59, 0.85)',
                borderColor: '#d50f3b',
                borderWidth: 1
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'top', labels: { boxWidth: 12 } }
            },
            scales: {
              y: { title: { display: true, text: 'Query Sample Count' }, grid: { color: gridColor } },
              x: { title: { display: true, text: 'Entropy Bin Range (Bits/Char)' }, grid: { color: gridColor } }
            }
          }
        });
        break;

      // 3. Botnet C2 Beaconing: Inter-Arrival Time Histogram
      case "Botnet C2 Beaconing":
        if (chartTitleEl) chartTitleEl.textContent = "INTER-ARRIVAL TIME INTERVAL HISTOGRAM (BEACON REGULARITY)";
        if (chartSubtitleEl) chartSubtitleEl.textContent = "Clustered tightly at 60.1s ±0.4s indicating automated heartbeat timer";

        activeChartInstance = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['< 30s', '40s - 50s', '58s - 59s', '60.0s - 60.5s [PEAK]', '61s - 62s', '70s - 90s', '> 120s'],
            datasets: [
              {
                label: 'Observed Ping Inter-Arrivals',
                data: [1, 2, 8, 48, 6, 2, 0],
                backgroundColor: '#e07b20',
                borderColor: '#e07b20',
                borderRadius: 2
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false }
            },
            scales: {
              y: { title: { display: true, text: 'Consecutive Occurrences' }, grid: { color: gridColor } },
              x: { title: { display: true, text: 'Heartbeat Delta Seconds' }, grid: { color: gridColor } }
            }
          }
        });
        break;

      // 4. Volumetric DDoS: Packet Arrival Rate vs Baseline Threshold
      case "Volumetric/Protocol DDoS":
        if (chartTitleEl) chartTitleEl.textContent = "INGRESS PACKET RATE (PPS) VS DETECTION THRESHOLD";
        if (chartSubtitleEl) chartSubtitleEl.textContent = "14,200 pps burst breaching the 1,500 pps trigger threshold line";

        activeChartInstance = new Chart(ctx, {
          type: 'line',
          data: {
            labels: ['-5m', '-4m', '-3m', '-2m', '-1m', 'NOW', '+1m (Est)'],
            datasets: [
              {
                label: 'Ingress PPS',
                data: [410, 430, 480, 8900, 14200, 13800, 11500],
                borderColor: '#d50f3b',
                backgroundColor: 'rgba(213, 15, 59, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.2,
                pointRadius: 4
              },
              {
                label: 'Threshold Baseline (1,500 PPS)',
                data: [1500, 1500, 1500, 1500, 1500, 1500, 1500],
                borderColor: '#c9a000',
                borderWidth: 2,
                borderDash: [6, 4],
                fill: false,
                pointRadius: 0
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'top', labels: { boxWidth: 12 } }
            },
            scales: {
              y: { title: { display: true, text: 'Packets Per Second (PPS)' }, grid: { color: gridColor } },
              x: { grid: { color: gridColor } }
            }
          }
        });
        break;

      // 5. Malware in Encrypted Sessions: Packet Sequence & Size Sequence
      case "Malware in Encrypted Sessions (TLS/QUIC)":
        if (chartTitleEl) chartTitleEl.textContent = "ENCRYPTED FLOW PACKET-SIZE & TIMING SEQUENCE";
        if (chartSubtitleEl) chartSubtitleEl.textContent = "JA3 Fingerprint Match: Early micro-handshake bursts characteristic of CobaltStrike";

        activeChartInstance = new Chart(ctx, {
          type: 'line',
          data: {
            labels: ['Pkt 1', 'Pkt 2', 'Pkt 3', 'Pkt 4', 'Pkt 5', 'Pkt 6', 'Pkt 7', 'Pkt 8', 'Pkt 9', 'Pkt 10'],
            datasets: [
              {
                label: 'Client Payload Bytes',
                data: [240, 0, 240, 512, 1024, 0, 180, 0, 240, 180],
                borderColor: '#d50f3b',
                backgroundColor: 'rgba(213, 15, 59, 0.1)',
                borderWidth: 2,
                stepped: true,
                pointRadius: 4
              },
              {
                label: 'Server Response Bytes',
                data: [0, 1420, 0, 0, 280, 1420, 0, 64, 0, 80],
                borderColor: '#4a7fa5',
                borderWidth: 2,
                stepped: true,
                pointRadius: 4
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'top', labels: { boxWidth: 12 } }
            },
            scales: {
              y: { title: { display: true, text: 'Packet Length (Bytes)' }, grid: { color: gridColor } },
              x: { title: { display: true, text: 'Consecutive Packet In Flow' }, grid: { color: gridColor } }
            }
          }
        });
        break;

      // 6. Reconnaissance / Port Scanning: Fan-Out Matrix
      case "Reconnaissance/Port Scanning":
      default:
        if (chartTitleEl) chartTitleEl.textContent = "FAN-OUT HORIZONTAL PORT PROBE DISTRIBUTION";
        if (chartSubtitleEl) chartSubtitleEl.textContent = "Target Subnet 10.0.4.0/24 — High concurrency sweep across standard ports";

        activeChartInstance = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['Port 21 (FTP)', 'Port 22 (SSH)', 'Port 23 (Telnet)', 'Port 80 (HTTP)', 'Port 443 (HTTPS)', 'Port 445 (SMB)', 'Port 3389 (RDP)', 'Port 8080 (Alt)'],
            datasets: [
              {
                label: 'Probed Destination Hosts in Subnet',
                data: [64, 64, 64, 64, 64, 64, 64, 64],
                backgroundColor: '#c9a000',
                borderColor: '#c9a000',
                borderRadius: 2
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false }
            },
            scales: {
              y: { title: { display: true, text: 'Distinct Hosts Probed' }, grid: { color: gridColor } },
              x: { grid: { color: gridColor } }
            }
          }
        });
        break;
    }
  }

  // --- 6. D3.js 2D Node-Link Blast Radius Diagram (PRD 2.2) ---
  function renderBlastRadius(alert) {
    const container = document.getElementById('blastRadiusSection');
    const svgEl = document.getElementById('blastSvg');
    if (!container || !svgEl) return;

    if (!alert.has_blast_radius || !window.d3) {
      container.style.display = 'none';
      return;
    }

    container.style.display = 'block';
    const d3 = window.d3;
    const width = svgEl.clientWidth || 900;
    const height = 360;

    const isLight = isLightTheme();
    const linkStroke = isLight ? 'rgba(0, 0, 0, 0.18)' : 'rgba(255, 255, 255, 0.18)';
    const linkTextColor = isLight ? '#555960' : '#8b949e';
    const internalNodeFill = isLight ? '#ffffff' : '#0d1117';
    const nodeTextColor = isLight ? '#090a0f' : '#ffffff';

    d3.select(svgEl).selectAll('*').remove();

    const svg = d3.select(svgEl)
      .attr('viewBox', [0, 0, width, height]);

    // Graph data deep copy
    const nodes = JSON.parse(JSON.stringify(alert.blast_nodes));
    const links = JSON.parse(JSON.stringify(alert.blast_links));

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(90))
      .force('charge', d3.forceManyBody().strength(-240))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(32));

    // Edge lines
    const link = svg.append('g')
      .attr('stroke', linkStroke)
      .attr('stroke-width', 1.2)
      .selectAll('line')
      .data(links)
      .join('line');

    // Edge text labels
    const linkText = svg.append('g')
      .selectAll('text')
      .data(links)
      .join('text')
      .attr('font-family', "'IBM Plex Mono', monospace")
      .attr('font-size', '8.5px')
      .attr('fill', linkTextColor)
      .attr('text-anchor', 'middle')
      .text(d => d.label || '');

    // Node groups
    const node = svg.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
      );

    // Node circles
    node.append('circle')
      .attr('r', d => d.type === 'source' ? 18 : (d.active_alert ? 14 : 10))
      .attr('fill', d => {
        if (d.type === 'source') return '#d50f3b';
        if (d.active_alert) return 'rgba(213, 15, 59, 0.35)';
        if (d.type === 'external') return '#e07b20';
        return internalNodeFill;
      })
      .attr('stroke', d => {
        if (d.type === 'source') return '#ffffff';
        if (d.active_alert) return '#d50f3b';
        if (d.type === 'external') return '#e07b20';
        return '#4a7fa5';
      })
      .attr('stroke-width', d => d.active_alert ? 2.5 : 1.5);

    // Node labels
    node.append('text')
      .attr('dy', d => d.type === 'source' ? 30 : 24)
      .attr('font-family', "'IBM Plex Mono', monospace")
      .attr('font-size', '10px')
      .attr('font-weight', d => d.active_alert ? '700' : '400')
      .attr('fill', d => d.active_alert ? '#d50f3b' : nodeTextColor)
      .attr('text-anchor', 'middle')
      .text(d => d.name);

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      linkText
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 3);

      node
        .attr('transform', d => `translate(${d.x},${d.y})`);
    });
  }

  // --- 7. Analyst Action Handlers in Investigation View ---
  function setupActions(alert) {
    const confirmBtn = document.getElementById('invConfirmBtn');
    const fpBtn = document.getElementById('invFpBtn');
    const noteInput = document.getElementById('invNoteInput');
    const saveNoteBtn = document.getElementById('invSaveNoteBtn');

    if (confirmBtn) {
      confirmBtn.addEventListener('click', () => {
        alert.analyst_label = 'confirmed';
        alert.state = 'confirmed';
        renderHeader(alert);
      });
    }

    if (fpBtn) {
      fpBtn.addEventListener('click', () => {
        alert.analyst_label = 'false_positive';
        alert.state = 'false_positive';
        renderHeader(alert);
      });
    }

    if (saveNoteBtn && noteInput) {
      if (alert.analyst_note) noteInput.value = alert.analyst_note;
      saveNoteBtn.addEventListener('click', () => {
        alert.analyst_note = noteInput.value.trim();
        saveNoteBtn.textContent = 'Saved!';
        setTimeout(() => { saveNoteBtn.textContent = 'Save Note'; }, 2000);
      });
    }
  }

  // --- Initialization ---
  document.addEventListener('DOMContentLoaded', () => {
    const activeAlert = getActiveAlert();
    renderHeader(activeAlert);
    renderKvList(activeAlert);
    renderWhyNot(activeAlert);
    renderRelatedAlerts(activeAlert);
    renderEvidenceChart(activeAlert);
    renderBlastRadius(activeAlert);
    setupActions(activeAlert);

    // Listen for theme toggle to update Chart.js & D3 dynamically
    document.addEventListener('click', (e) => {
      if (e.target.closest('#themeToggle') || e.target.closest('.theme-toggle-btn')) {
        setTimeout(() => {
          renderEvidenceChart(activeAlert);
          renderBlastRadius(activeAlert);
        }, 50);
      }
    });
  });

})();
