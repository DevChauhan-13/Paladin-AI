const SEED_ALERTS = [
  {
    "id": "ALT-2026-9041",
    "timestamp": "2026-09-29T12:00:48.308Z",
    "flow_id": "FLW-88319-TCP",
    "threat_class": "Data Exfiltration",
    "severity": "critical",
    "confidence": 0.96,
    "calibration": "Higher than 98% of past confirmed exfiltration events",
    "summary": "High-volume outbound byte asymmetry (418 MB out vs 14 KB in) over encrypted tunnel to unindexed IP",
    "src_ip": "10.0.12.84",
    "src_port": 49822,
    "dst_ip": "203.0.113.88",
    "dst_port": 443,
    "proto": "TCP/TLS",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "correlation_count": 5,
    "correlation_window": "15 min",
    "evidence": {
      "bytes_out": 438304768,
      "bytes_in": 14336,
      "ratio": 30573.7,
      "flow_duration_sec": 142,
      "entropy": 7.94
    },
    "evidence_features": [
      {
        "label": "Flow Duration",
        "value": "142.6 seconds",
        "highlight": false
      },
      {
        "label": "Outbound Bytes",
        "value": "438,304,768 B (418.0 MB)",
        "highlight": true
      },
      {
        "label": "Inbound Bytes",
        "value": "14,336 B (14.0 KB)",
        "highlight": false
      },
      {
        "label": "Asymmetry Ratio",
        "value": "30,573 : 1 (Exfiltration Index > 99.8th percentile)",
        "highlight": true
      },
      {
        "label": "Payload Entropy",
        "value": "7.94 / 8.00 (High Compression / Ciphertext)",
        "highlight": true
      },
      {
        "label": "Destination ASN",
        "value": "AS64512 (Uncategorized Bulletproof Hosting)",
        "highlight": true
      },
      {
        "label": "Zeek Connection State",
        "value": "SF (Normal syn-ack teardown)",
        "highlight": false
      },
      {
        "label": "Sensor ID",
        "value": "NTRO-DIODE-ZEEK-01",
        "highlight": false
      }
    ],
    "why_not": [
      {
        "threat": "Normal Cloud Backup",
        "reason": "Target IP not registered in approved corporate cloud egress whitelist (S3/Azure/GCS)."
      },
      {
        "threat": "Software Update Download",
        "reason": "Traffic direction is predominantly outbound (99.996% upload vs 0.004% download)."
      },
      {
        "threat": "Volumetric DDoS",
        "reason": "Packet arrival rate (312 pps) is within steady-state link capacity; flag is on byte payload asymmetry, not PPS volume."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9039",
        "class": "Botnet C2 Beaconing",
        "sev": "high",
        "summary": "Periodic TCP heartbeats from 10.0.12.84 to 198.51.100.44",
        "time": "12m ago"
      },
      {
        "id": "ALT-2026-8992",
        "class": "Reconnaissance/Port Scanning",
        "sev": "low",
        "summary": "Internal port scan originated from 10.0.12.84 to subnet 10.0.4.0/24",
        "time": "3h ago"
      }
    ],
    "has_blast_radius": true,
    "blast_nodes": [
      {
        "id": "10.0.12.84",
        "name": "10.0.12.84 (Compromised Host)",
        "type": "source",
        "active_alert": true
      },
      {
        "id": "203.0.113.88",
        "name": "203.0.113.88 (Exfil Drop)",
        "type": "external",
        "active_alert": true
      },
      {
        "id": "198.51.100.44",
        "name": "198.51.100.44 (C2 Staging)",
        "type": "external",
        "active_alert": true
      },
      {
        "id": "10.0.1.10",
        "name": "10.0.1.10 (Domain Controller)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.1",
        "name": "10.0.12.1 (VLAN Gateway)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.55",
        "name": "10.0.12.55 (Fileserver / SMB)",
        "type": "internal",
        "active_alert": true
      },
      {
        "id": "10.0.12.92",
        "name": "10.0.12.92 (Workstation)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.8.20",
        "name": "10.0.8.20 (Database Core)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.4.119",
        "name": "10.0.4.119 (Jump Host)",
        "type": "internal",
        "active_alert": true
      },
      {
        "id": "10.0.4.15",
        "name": "10.0.4.15 (Build Server)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "8.8.8.8",
        "name": "8.8.8.8 (Google DNS)",
        "type": "external",
        "active_alert": false
      },
      {
        "id": "1.1.1.1",
        "name": "1.1.1.1 (Cloudflare DNS)",
        "type": "external",
        "active_alert": false
      }
    ],
    "blast_links": [
      {
        "source": "10.0.12.84",
        "target": "203.0.113.88",
        "label": "HTTPS 418MB"
      },
      {
        "source": "10.0.12.84",
        "target": "198.51.100.44",
        "label": "TLS/8443 1.2MB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.55",
        "label": "SMB/445 422MB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.1.10",
        "label": "Kerberos/88 84KB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.1",
        "label": "ARP / Gateway"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.92",
        "label": "RPC/135 12KB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.8.20",
        "label": "TDS/1433 18MB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.4.119",
        "label": "SSH/22 4KB"
      },
      {
        "source": "10.0.12.84",
        "target": "8.8.8.8",
        "label": "DNS/53 2KB"
      },
      {
        "source": "10.0.4.119",
        "target": "10.0.4.15",
        "label": "RDP/3389"
      }
    ]
  },
  {
    "id": "ALT-2026-9040",
    "timestamp": "2026-09-29T11:59:43.309Z",
    "flow_id": "FLW-88314-UDP",
    "threat_class": "DGA Domains / DNS Tunneling",
    "severity": "critical",
    "confidence": 0.94,
    "calibration": "Higher than 95% of confirmed DNS tunnel events",
    "summary": "High-entropy domain queries (4.38 n-gram) with 380 QPS burst to authoritative server",
    "src_ip": "10.0.4.119",
    "src_port": 53210,
    "dst_ip": "198.51.100.12",
    "dst_port": 53,
    "proto": "UDP/DNS",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "correlation_count": 3,
    "correlation_window": "10 min",
    "evidence": {
      "domain": "qx9z-v88a-secops-update.dyn-dns.io",
      "entropy": 4.38,
      "qps": 380,
      "txt_record_ratio": 0.88
    },
    "evidence_features": [
      {
        "label": "Queried Domain",
        "value": "qx9z-v88a-secops-update.dyn-dns.io",
        "highlight": true
      },
      {
        "label": "Shannon Entropy",
        "value": "4.38 bits/char (Normal Alexa Top 1M = 2.45)",
        "highlight": true
      },
      {
        "label": "Bi-gram Frequency Score",
        "value": "0.0084 (Extremely abnormal consonant clustering)",
        "highlight": true
      },
      {
        "label": "Query Rate (QPS)",
        "value": "380 queries/sec (Burst Duration: 4.8s)",
        "highlight": true
      },
      {
        "label": "Record Type Ratio",
        "value": "88% TXT, 12% A (Signature DNS Tunnel payload)",
        "highlight": true
      },
      {
        "label": "Authoritative Nameserver",
        "value": "ns1.dyn-dns.io [198.51.100.12]",
        "highlight": false
      },
      {
        "label": "Suricata Signature ID",
        "value": "2028441 (ET MALWARE DGA Query Pattern)",
        "highlight": false
      }
    ],
    "why_not": [
      {
        "threat": "Legitimate CDN Domain Resolution",
        "reason": "Entropy score 4.38 exceeds 99.9th percentile for commercial CDNs (Akamai/Cloudflare mean 2.8)."
      },
      {
        "threat": "Anti-Spam RBL Lookup",
        "reason": "Queries directed to single unindexed IP instead of distributed public Spamhaus/Sorbs resolvers."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9037",
        "class": "Reconnaissance/Port Scanning",
        "sev": "medium",
        "summary": "Port scan sweep from 10.0.4.119 to subnet 10.0.4.0/24",
        "time": "8m ago"
      }
    ],
    "has_blast_radius": false
  },
  {
    "id": "ALT-2026-9039",
    "timestamp": "2026-09-29T11:58:23.309Z",
    "flow_id": "FLW-88299-TCP",
    "threat_class": "Botnet C2 Beaconing",
    "severity": "high",
    "confidence": 0.91,
    "calibration": "Higher than 91% of confirmed C2 beacon detections",
    "summary": "Periodic TCP heartbeats with low jitter (delta: 60.1s ±0.4s) to external staging IP",
    "src_ip": "10.0.12.84",
    "src_port": 51240,
    "dst_ip": "198.51.100.44",
    "dst_port": 8443,
    "proto": "TCP/HTTPS",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "correlation_count": 5,
    "correlation_window": "15 min",
    "evidence": {
      "beacon_interval_sec": 60.1,
      "jitter_percent": 0.65,
      "streak_count": 24,
      "payload_entropy": 7.21
    },
    "evidence_features": [
      {
        "label": "Beacon Interval",
        "value": "60.1 seconds (Strict periodicity)",
        "highlight": true
      },
      {
        "label": "Timing Jitter",
        "value": "0.65% (Calculated deviation ±0.39s)",
        "highlight": true
      },
      {
        "label": "Streak Length",
        "value": "24 consecutive intervals observed without drop",
        "highlight": true
      },
      {
        "label": "Burst Packet Count",
        "value": "4 packets per handshake (184 bytes payload)",
        "highlight": false
      },
      {
        "label": "Destination Port",
        "value": "8443 (Non-standard TLS service)",
        "highlight": false
      },
      {
        "label": "TLS SNI Field",
        "value": "telemetry-sync-cdn.xyz",
        "highlight": true
      }
    ],
    "why_not": [
      {
        "threat": "NTP Time Sync",
        "reason": "Protocol is TLS over port 8443, not UDP port 123; fixed payload size differs from RFC 5905 spec."
      },
      {
        "threat": "Browser Keepalive",
        "reason": "Strict 60.1s regularity maintained for 24 min continuously during zero human user activity hours."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9041",
        "class": "Data Exfiltration",
        "sev": "critical",
        "summary": "418 MB byte asymmetry outbound from 10.0.12.84",
        "time": "3m ago"
      }
    ],
    "has_blast_radius": true,
    "blast_nodes": [
      {
        "id": "10.0.12.84",
        "name": "10.0.12.84 (Beacon Source)",
        "type": "source",
        "active_alert": true
      },
      {
        "id": "198.51.100.44",
        "name": "198.51.100.44 (C2 Server)",
        "type": "external",
        "active_alert": true
      },
      {
        "id": "10.0.1.10",
        "name": "10.0.1.10 (Active Directory)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.1",
        "name": "10.0.12.1 (Core Gateway)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.22",
        "name": "10.0.12.22 (Peer Host)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.90",
        "name": "10.0.12.90 (Finance PC)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.4.119",
        "name": "10.0.4.119 (Jump Host)",
        "type": "internal",
        "active_alert": true
      }
    ],
    "blast_links": [
      {
        "source": "10.0.12.84",
        "target": "198.51.100.44",
        "label": "Heartbeat/60s"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.1.10",
        "label": "Kerberos TGT"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.1",
        "label": "Default Route"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.22",
        "label": "RPC / Ping"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.90",
        "label": "SMB Probe"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.4.119",
        "label": "SSH"
      }
    ]
  },
  {
    "id": "ALT-2026-9038",
    "timestamp": "2026-09-29T11:56:13.309Z",
    "flow_id": "FLW-88280-TCP",
    "threat_class": "Malware in Encrypted Sessions (TLS/QUIC)",
    "severity": "high",
    "confidence": 0.88,
    "calibration": "Higher than 87% of past malware fingerprint matches",
    "summary": "JA3 hash matches known CobaltStrike malleable C2 profile with anomalous initial burst lengths",
    "src_ip": "10.0.8.210",
    "src_port": 48991,
    "dst_ip": "192.0.2.145",
    "dst_port": 443,
    "proto": "TCP/TLS 1.3",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "correlation_count": 1,
    "correlation_window": "10 min",
    "evidence": {
      "ja3": "a0e9f5d64349fb13191bc781f81f42e8",
      "ja3s": "ec74a5c5110605f9f8eac32c925904e7",
      "cert_subject": "CN=internal-telemetry-cdn.net",
      "cert_validity_days": 7
    },
    "evidence_features": [
      {
        "label": "JA3 Fingerprint",
        "value": "a0e9f5d64349fb13191bc781f81f42e8 (CobaltStrike C2 Profile)",
        "highlight": true
      },
      {
        "label": "JA3S Server Response",
        "value": "ec74a5c5110605f9f8eac32c925904e7 (Known Malicious Daemon)",
        "highlight": true
      },
      {
        "label": "X.509 Subject",
        "value": "CN=internal-telemetry-cdn.net (Self-signed Untrusted CA)",
        "highlight": true
      },
      {
        "label": "Cert Validity Period",
        "value": "7 Days (Ephemeral Staging Certificate)",
        "highlight": true
      },
      {
        "label": "TLS Version",
        "value": "TLSv1.3 (Cipher: TLS_AES_256_GCM_SHA384)",
        "highlight": false
      },
      {
        "label": "Packet Burst Profile",
        "value": "Micro-bursts of 240, 240, 512, 1024 bytes (Handshake signature)",
        "highlight": true
      }
    ],
    "why_not": [
      {
        "threat": "Standard Chrome / Firefox Session",
        "reason": "JA3 fingerprint does not match any official Chromium or Gecko TLS client hello distributions."
      },
      {
        "threat": "Legitimate Corporate VPN",
        "reason": "Certificate authority is self-signed and missing root cross-signing in enterprise trust store."
      }
    ],
    "related_alerts": [],
    "has_blast_radius": false
  },
  {
    "id": "ALT-2026-9037",
    "timestamp": "2026-09-29T11:53:33.309Z",
    "flow_id": "FLW-88250-TCP",
    "threat_class": "Reconnaissance/Port Scanning",
    "severity": "medium",
    "confidence": 0.85,
    "calibration": "Higher than 84% of confirmed scan sweeps",
    "summary": "Fast horizontal SYN probe against 1,024 destination ports across internal subnet 10.0.4.0/24",
    "src_ip": "10.0.4.119",
    "src_port": 60102,
    "dst_ip": "10.0.4.1/24",
    "dst_port": "Multi (1-1024)",
    "proto": "TCP/SYN",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "correlation_count": 3,
    "correlation_window": "10 min",
    "evidence": {
      "probed_ports": 1024,
      "syn_ratio": 0.99,
      "sweep_duration_sec": 14.2,
      "fan_out_degree": 64
    },
    "evidence_features": [
      {
        "label": "Probed Ports",
        "value": "1,024 Distinct Ports (1 to 1024 Standard Well-Known Range)",
        "highlight": true
      },
      {
        "label": "SYN-to-ACK Ratio",
        "value": "0.99 (99% unmatched half-open SYN packets)",
        "highlight": true
      },
      {
        "label": "Sweep Duration",
        "value": "14.2 seconds (High concurrency thread pool)",
        "highlight": false
      },
      {
        "label": "Fan-Out Target Count",
        "value": "64 internal host addresses contacted",
        "highlight": true
      },
      {
        "label": "RST Rate Received",
        "value": "812 RST packets returned from closed endpoints",
        "highlight": false
      },
      {
        "label": "Scanner Heuristic",
        "value": "Nmap SYN Stealth (-sS) timing template T4 match",
        "highlight": true
      }
    ],
    "why_not": [
      {
        "threat": "Legitimate Nessus / Vulnerability Scanner",
        "reason": "Source host 10.0.4.119 is a workstation jump-box, not a registered Qualys/Nessus security scanner IP."
      },
      {
        "threat": "Distributed Denial of Service",
        "reason": "Targeting multiple sequential internal ports with single SYN probes rather than flooding single port with high bandwidth."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9040",
        "class": "DGA Domains / DNS Tunneling",
        "sev": "critical",
        "summary": "High-entropy DNS queries from 10.0.4.119",
        "time": "6m ago"
      }
    ],
    "has_blast_radius": false
  },
  {
    "id": "ALT-2026-9036",
    "timestamp": "2026-09-29T11:50:43.309Z",
    "flow_id": "FLW-88210-UDP",
    "threat_class": "Volumetric/Protocol DDoS",
    "severity": "critical",
    "confidence": 0.97,
    "calibration": "Higher than 99% of volumetric anomaly baselines",
    "summary": "Abnormal ingress packet surge (14,200 pps) targeting core perimeter routing interface",
    "src_ip": "Multiple (Botnet)",
    "src_port": 0,
    "dst_ip": "10.0.1.1",
    "dst_port": 53,
    "proto": "UDP/DNS Amplification",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "analyst_note": "Upstream ACL filter engaged at border router",
    "correlation_count": 8,
    "correlation_window": "30 min",
    "evidence": {
      "packet_rate_pps": 14200,
      "entropy": 0.12,
      "baseline_rate": 420,
      "amplification_factor": 48
    },
    "evidence_features": [
      {
        "label": "Ingress Packet Rate",
        "value": "14,200 pkts/sec (Normal Baseline: 420 pps)",
        "highlight": true
      },
      {
        "label": "Source IP Entropy",
        "value": "0.12 (Reflected amplification from fixed reflector pool)",
        "highlight": true
      },
      {
        "label": "Bandwidth Consumed",
        "value": "1.42 Gbps at physical diode optical interface",
        "highlight": true
      },
      {
        "label": "Amplification Factor",
        "value": "48x payload multiplier (ANY query response flood)",
        "highlight": true
      },
      {
        "label": "Target Interface",
        "value": "ETH-CORE-DIODE-INGRESS-01",
        "highlight": false
      },
      {
        "label": "Mitigation State",
        "value": "Rate-limiting applied at upstream BGP peer",
        "highlight": false
      }
    ],
    "why_not": [
      {
        "threat": "Legitimate Peak Traffic",
        "reason": "3,380% surge over historical 30-day baseline during off-peak maintenance window."
      },
      {
        "threat": "Internal Network Loop",
        "reason": "Hop count (TTL) indicates packets traversed external WAN autonomous systems."
      }
    ],
    "related_alerts": [],
    "has_blast_radius": false
  },
  {
    "id": "ALT-2026-9035",
    "timestamp": "2026-09-29T11:46:43.309Z",
    "flow_id": "FLW-88190-TCP",
    "threat_class": "Botnet C2 Beaconing",
    "severity": "low",
    "confidence": 0.52,
    "calibration": "Below 60% probability threshold",
    "summary": "Periodic polling to official Microsoft telemetry endpoint; consistent with Windows Update service",
    "src_ip": "10.0.2.45",
    "src_port": 54100,
    "dst_ip": "20.190.159.0",
    "dst_port": 443,
    "proto": "TCP/HTTPS",
    "state": "false_positive",
    "analyst_label": "false_positive",
    "analyst_note": "Verified legitimate Windows telemetry traffic",
    "correlation_count": 0,
    "correlation_window": "none",
    "evidence": {
      "beacon_interval_sec": 300,
      "jitter_percent": 14.2,
      "asn": "AS8075 MICROSOFT-CORP"
    }
  },
  {
    "id": "ALT-2026-9034",
    "timestamp": "2026-09-29T11:42:33.309Z",
    "flow_id": "FLW-88165-TCP",
    "threat_class": "Data Exfiltration",
    "severity": "high",
    "confidence": 0.89,
    "calibration": "Higher than 89% of confirmed exfiltration triggers",
    "summary": "Scheduled nightly tarball upload to Cloudflare R2 bucket with elevated egress volume",
    "src_ip": "10.0.15.12",
    "src_port": 44102,
    "dst_ip": "104.18.2.10",
    "dst_port": 443,
    "proto": "TCP/HTTPS",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "correlation_count": 2,
    "correlation_window": "24h",
    "evidence": {
      "bytes_out": 128974848,
      "bytes_in": 8192,
      "ratio": 15744,
      "destination_domain": "backup-sync.internal.storage"
    }
  },
  {
    "id": "ALT-2026-9033",
    "timestamp": "2026-09-27T22:15:00.000Z",
    "flow_id": "FLW-87940-TCP",
    "threat_class": "Data Exfiltration",
    "severity": "critical",
    "confidence": 0.95,
    "src_ip": "10.0.12.84",
    "src_port": 52119,
    "dst_ip": "185.220.101.5",
    "dst_port": 443,
    "proto": "TCP/TLS",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "summary": "Tor exit node exfiltration tunnel observed from infected endpoint 10.0.12.84"
  },
  {
    "id": "ALT-2026-9032",
    "timestamp": "2026-09-27T19:30:00.000Z",
    "flow_id": "FLW-87720-UDP",
    "threat_class": "Volumetric/Protocol DDoS",
    "severity": "critical",
    "confidence": 0.98,
    "src_ip": "Multiple (NTP)",
    "src_port": 123,
    "dst_ip": "10.0.1.10",
    "dst_port": 123,
    "proto": "UDP/NTP",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "summary": "NTP monlist amplification flood saturating WAN boundary diode buffer"
  },
  {
    "id": "ALT-2026-9031",
    "timestamp": "2026-09-27T16:12:00.000Z",
    "flow_id": "FLW-87500-TCP",
    "threat_class": "Malware in Encrypted Sessions (TLS/QUIC)",
    "severity": "medium",
    "confidence": 0.74,
    "src_ip": "10.0.3.99",
    "src_port": 49912,
    "dst_ip": "142.250.190.46",
    "dst_port": 443,
    "proto": "QUIC/UDP",
    "state": "false_positive",
    "analyst_label": "false_positive",
    "summary": "Google Chrome QUIC protocol packet sequence misclassified due to packet reordering"
  },
  {
    "id": "ALT-2026-9030",
    "timestamp": "2026-09-27T11:45:00.000Z",
    "flow_id": "FLW-87210-TCP",
    "threat_class": "Reconnaissance/Port Scanning",
    "severity": "high",
    "confidence": 0.92,
    "src_ip": "10.0.12.84",
    "src_port": 59120,
    "dst_ip": "10.0.12.0/24",
    "dst_port": "445 (SMB)",
    "proto": "TCP/SYN",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "summary": "Lateral movement SMB port scan probing internal finance workstations"
  },
  {
    "id": "ALT-2026-9029",
    "timestamp": "2026-09-26T14:20:00.000Z",
    "flow_id": "FLW-86800-UDP",
    "threat_class": "DGA Domains / DNS Tunneling",
    "severity": "high",
    "confidence": 0.9,
    "src_ip": "10.0.5.21",
    "src_port": 54110,
    "dst_ip": "8.8.4.4",
    "dst_port": 53,
    "proto": "UDP/DNS",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "summary": "Base64 encoded data exfiltration inside DNS TXT records to dynamic subdomain"
  },
  {
    "id": "ALT-2026-9028",
    "timestamp": "2026-09-25T09:10:00.000Z",
    "flow_id": "FLW-86400-TCP",
    "threat_class": "Data Exfiltration",
    "severity": "critical",
    "confidence": 0.97,
    "src_ip": "10.0.12.84",
    "src_port": 48910,
    "dst_ip": "91.240.118.17",
    "dst_port": 21,
    "proto": "TCP/FTP",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "summary": "Raw credentials and tarball transmitted via unencrypted FTP to foreign hosting provider"
  }
];

const INVESTIGATION_DATABASE = {
  "ALT-2026-9041": {
    "id": "ALT-2026-9041",
    "timestamp": "2026-09-28T02:14:15.000Z",
    "flow_id": "FLW-88319-TCP",
    "threat_class": "Data Exfiltration",
    "severity": "critical",
    "confidence": 0.96,
    "calibration": "Higher than 98% of past confirmed exfiltration events",
    "summary": "High-volume outbound byte asymmetry (418 MB out vs 14 KB in) over encrypted tunnel to unindexed IP",
    "src_ip": "10.0.12.84",
    "src_port": 49822,
    "dst_ip": "203.0.113.88",
    "dst_port": 443,
    "proto": "TCP/TLS 1.3",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "evidence_features": [
      {
        "label": "Flow Duration",
        "value": "142.6 seconds",
        "highlight": false
      },
      {
        "label": "Outbound Bytes",
        "value": "438,304,768 B (418.0 MB)",
        "highlight": true
      },
      {
        "label": "Inbound Bytes",
        "value": "14,336 B (14.0 KB)",
        "highlight": false
      },
      {
        "label": "Asymmetry Ratio",
        "value": "30,573 : 1 (Exfiltration Index > 99.8th percentile)",
        "highlight": true
      },
      {
        "label": "Payload Entropy",
        "value": "7.94 / 8.00 (High Compression / Ciphertext)",
        "highlight": true
      },
      {
        "label": "Destination ASN",
        "value": "AS64512 (Uncategorized Bulletproof Hosting)",
        "highlight": true
      },
      {
        "label": "Zeek Connection State",
        "value": "SF (Normal syn-ack teardown)",
        "highlight": false
      },
      {
        "label": "Sensor ID",
        "value": "NTRO-DIODE-ZEEK-01",
        "highlight": false
      }
    ],
    "why_not": [
      {
        "threat": "Normal Cloud Backup",
        "reason": "Target IP not registered in approved corporate cloud egress whitelist (S3/Azure/GCS)."
      },
      {
        "threat": "Software Update Download",
        "reason": "Traffic direction is predominantly outbound (99.996% upload vs 0.004% download)."
      },
      {
        "threat": "Volumetric DDoS",
        "reason": "Packet arrival rate (312 pps) is within steady-state link capacity; flag is on byte payload asymmetry, not PPS volume."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9039",
        "class": "Botnet C2 Beaconing",
        "sev": "high",
        "summary": "Periodic TCP heartbeats from 10.0.12.84 to 198.51.100.44",
        "time": "12m ago"
      },
      {
        "id": "ALT-2026-8992",
        "class": "Reconnaissance/Port Scanning",
        "sev": "low",
        "summary": "Internal port scan originated from 10.0.12.84 to subnet 10.0.4.0/24",
        "time": "3h ago"
      }
    ],
    "has_blast_radius": true,
    "blast_nodes": [
      {
        "id": "10.0.12.84",
        "name": "10.0.12.84 (Compromised Host)",
        "type": "source",
        "active_alert": true
      },
      {
        "id": "203.0.113.88",
        "name": "203.0.113.88 (Exfil Drop)",
        "type": "external",
        "active_alert": true
      },
      {
        "id": "198.51.100.44",
        "name": "198.51.100.44 (C2 Staging)",
        "type": "external",
        "active_alert": true
      },
      {
        "id": "10.0.1.10",
        "name": "10.0.1.10 (Domain Controller)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.1",
        "name": "10.0.12.1 (VLAN Gateway)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.55",
        "name": "10.0.12.55 (Fileserver / SMB)",
        "type": "internal",
        "active_alert": true
      },
      {
        "id": "10.0.12.92",
        "name": "10.0.12.92 (Workstation)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.8.20",
        "name": "10.0.8.20 (Database Core)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.4.119",
        "name": "10.0.4.119 (Jump Host)",
        "type": "internal",
        "active_alert": true
      },
      {
        "id": "10.0.4.15",
        "name": "10.0.4.15 (Build Server)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "8.8.8.8",
        "name": "8.8.8.8 (Google DNS)",
        "type": "external",
        "active_alert": false
      },
      {
        "id": "1.1.1.1",
        "name": "1.1.1.1 (Cloudflare DNS)",
        "type": "external",
        "active_alert": false
      }
    ],
    "blast_links": [
      {
        "source": "10.0.12.84",
        "target": "203.0.113.88",
        "label": "HTTPS 418MB"
      },
      {
        "source": "10.0.12.84",
        "target": "198.51.100.44",
        "label": "TLS/8443 1.2MB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.55",
        "label": "SMB/445 422MB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.1.10",
        "label": "Kerberos/88 84KB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.1",
        "label": "ARP / Gateway"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.92",
        "label": "RPC/135 12KB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.8.20",
        "label": "TDS/1433 18MB"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.4.119",
        "label": "SSH/22 4KB"
      },
      {
        "source": "10.0.12.84",
        "target": "8.8.8.8",
        "label": "DNS/53 2KB"
      },
      {
        "source": "10.0.4.119",
        "target": "10.0.4.15",
        "label": "RDP/3389"
      }
    ]
  },
  "ALT-2026-9040": {
    "id": "ALT-2026-9040",
    "timestamp": "2026-09-28T02:13:00.000Z",
    "flow_id": "FLW-88314-UDP",
    "threat_class": "DGA Domains / DNS Tunneling",
    "severity": "critical",
    "confidence": 0.94,
    "calibration": "Higher than 95% of confirmed DNS tunnel events",
    "summary": "High-entropy domain queries (4.38 n-gram) with 380 QPS burst to authoritative server",
    "src_ip": "10.0.4.119",
    "src_port": 53210,
    "dst_ip": "198.51.100.12",
    "dst_port": 53,
    "proto": "UDP/DNS",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "evidence_features": [
      {
        "label": "Queried Domain",
        "value": "qx9z-v88a-secops-update.dyn-dns.io",
        "highlight": true
      },
      {
        "label": "Shannon Entropy",
        "value": "4.38 bits/char (Normal Alexa Top 1M = 2.45)",
        "highlight": true
      },
      {
        "label": "Bi-gram Frequency Score",
        "value": "0.0084 (Extremely abnormal consonant clustering)",
        "highlight": true
      },
      {
        "label": "Query Rate (QPS)",
        "value": "380 queries/sec (Burst Duration: 4.8s)",
        "highlight": true
      },
      {
        "label": "Record Type Ratio",
        "value": "88% TXT, 12% A (Signature DNS Tunnel payload)",
        "highlight": true
      },
      {
        "label": "Authoritative Nameserver",
        "value": "ns1.dyn-dns.io [198.51.100.12]",
        "highlight": false
      },
      {
        "label": "Suricata Signature ID",
        "value": "2028441 (ET MALWARE DGA Query Pattern)",
        "highlight": false
      }
    ],
    "why_not": [
      {
        "threat": "Legitimate CDN Domain Resolution",
        "reason": "Entropy score 4.38 exceeds 99.9th percentile for commercial CDNs (Akamai/Cloudflare mean 2.8)."
      },
      {
        "threat": "Anti-Spam RBL Lookup",
        "reason": "Queries directed to single unindexed IP instead of distributed public Spamhaus/Sorbs resolvers."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9037",
        "class": "Reconnaissance/Port Scanning",
        "sev": "medium",
        "summary": "Port scan sweep from 10.0.4.119 to subnet 10.0.4.0/24",
        "time": "8m ago"
      }
    ],
    "has_blast_radius": false
  },
  "ALT-2026-9039": {
    "id": "ALT-2026-9039",
    "timestamp": "2026-09-28T02:11:40.000Z",
    "flow_id": "FLW-88299-TCP",
    "threat_class": "Botnet C2 Beaconing",
    "severity": "high",
    "confidence": 0.91,
    "calibration": "Higher than 91% of confirmed C2 beacon detections",
    "summary": "Periodic TCP heartbeats with low jitter (delta: 60.1s ±0.4s) to external staging IP",
    "src_ip": "10.0.12.84",
    "src_port": 51240,
    "dst_ip": "198.51.100.44",
    "dst_port": 8443,
    "proto": "TCP/HTTPS",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "evidence_features": [
      {
        "label": "Beacon Interval",
        "value": "60.1 seconds (Strict periodicity)",
        "highlight": true
      },
      {
        "label": "Timing Jitter",
        "value": "0.65% (Calculated deviation ±0.39s)",
        "highlight": true
      },
      {
        "label": "Streak Length",
        "value": "24 consecutive intervals observed without drop",
        "highlight": true
      },
      {
        "label": "Burst Packet Count",
        "value": "4 packets per handshake (184 bytes payload)",
        "highlight": false
      },
      {
        "label": "Destination Port",
        "value": "8443 (Non-standard TLS service)",
        "highlight": false
      },
      {
        "label": "TLS SNI Field",
        "value": "telemetry-sync-cdn.xyz",
        "highlight": true
      }
    ],
    "why_not": [
      {
        "threat": "NTP Time Sync",
        "reason": "Protocol is TLS over port 8443, not UDP port 123; fixed payload size differs from RFC 5905 spec."
      },
      {
        "threat": "Browser Keepalive",
        "reason": "Strict 60.1s regularity maintained for 24 min continuously during zero human user activity hours."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9041",
        "class": "Data Exfiltration",
        "sev": "critical",
        "summary": "418 MB byte asymmetry outbound from 10.0.12.84",
        "time": "3m ago"
      }
    ],
    "has_blast_radius": true,
    "blast_nodes": [
      {
        "id": "10.0.12.84",
        "name": "10.0.12.84 (Beacon Source)",
        "type": "source",
        "active_alert": true
      },
      {
        "id": "198.51.100.44",
        "name": "198.51.100.44 (C2 Server)",
        "type": "external",
        "active_alert": true
      },
      {
        "id": "10.0.1.10",
        "name": "10.0.1.10 (Active Directory)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.1",
        "name": "10.0.12.1 (Core Gateway)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.22",
        "name": "10.0.12.22 (Peer Host)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.12.90",
        "name": "10.0.12.90 (Finance PC)",
        "type": "internal",
        "active_alert": false
      },
      {
        "id": "10.0.4.119",
        "name": "10.0.4.119 (Jump Host)",
        "type": "internal",
        "active_alert": true
      }
    ],
    "blast_links": [
      {
        "source": "10.0.12.84",
        "target": "198.51.100.44",
        "label": "Heartbeat/60s"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.1.10",
        "label": "Kerberos TGT"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.1",
        "label": "Default Route"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.22",
        "label": "RPC / Ping"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.12.90",
        "label": "SMB Probe"
      },
      {
        "source": "10.0.12.84",
        "target": "10.0.4.119",
        "label": "SSH"
      }
    ]
  },
  "ALT-2026-9038": {
    "id": "ALT-2026-9038",
    "timestamp": "2026-09-28T02:09:30.000Z",
    "flow_id": "FLW-88280-TCP",
    "threat_class": "Malware in Encrypted Sessions (TLS/QUIC)",
    "severity": "high",
    "confidence": 0.88,
    "calibration": "Higher than 87% of past malware fingerprint matches",
    "summary": "JA3 hash matches known CobaltStrike malleable C2 profile with anomalous initial burst lengths",
    "src_ip": "10.0.8.210",
    "src_port": 48991,
    "dst_ip": "192.0.2.145",
    "dst_port": 443,
    "proto": "TCP/TLS 1.3",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "evidence_features": [
      {
        "label": "JA3 Fingerprint",
        "value": "a0e9f5d64349fb13191bc781f81f42e8 (CobaltStrike C2 Profile)",
        "highlight": true
      },
      {
        "label": "JA3S Server Response",
        "value": "ec74a5c5110605f9f8eac32c925904e7 (Known Malicious Daemon)",
        "highlight": true
      },
      {
        "label": "X.509 Subject",
        "value": "CN=internal-telemetry-cdn.net (Self-signed Untrusted CA)",
        "highlight": true
      },
      {
        "label": "Cert Validity Period",
        "value": "7 Days (Ephemeral Staging Certificate)",
        "highlight": true
      },
      {
        "label": "TLS Version",
        "value": "TLSv1.3 (Cipher: TLS_AES_256_GCM_SHA384)",
        "highlight": false
      },
      {
        "label": "Packet Burst Profile",
        "value": "Micro-bursts of 240, 240, 512, 1024 bytes (Handshake signature)",
        "highlight": true
      }
    ],
    "why_not": [
      {
        "threat": "Standard Chrome / Firefox Session",
        "reason": "JA3 fingerprint does not match any official Chromium or Gecko TLS client hello distributions."
      },
      {
        "threat": "Legitimate Corporate VPN",
        "reason": "Certificate authority is self-signed and missing root cross-signing in enterprise trust store."
      }
    ],
    "related_alerts": [],
    "has_blast_radius": false
  },
  "ALT-2026-9037": {
    "id": "ALT-2026-9037",
    "timestamp": "2026-09-28T02:06:50.000Z",
    "flow_id": "FLW-88250-TCP",
    "threat_class": "Reconnaissance/Port Scanning",
    "severity": "medium",
    "confidence": 0.85,
    "calibration": "Higher than 84% of confirmed scan sweeps",
    "summary": "Fast horizontal SYN probe against 1,024 destination ports across internal subnet 10.0.4.0/24",
    "src_ip": "10.0.4.119",
    "src_port": 60102,
    "dst_ip": "10.0.4.1/24",
    "dst_port": "Multi (1-1024)",
    "proto": "TCP/SYN",
    "state": "active",
    "analyst_label": null,
    "analyst_note": "",
    "evidence_features": [
      {
        "label": "Probed Ports",
        "value": "1,024 Distinct Ports (1 to 1024 Standard Well-Known Range)",
        "highlight": true
      },
      {
        "label": "SYN-to-ACK Ratio",
        "value": "0.99 (99% unmatched half-open SYN packets)",
        "highlight": true
      },
      {
        "label": "Sweep Duration",
        "value": "14.2 seconds (High concurrency thread pool)",
        "highlight": false
      },
      {
        "label": "Fan-Out Target Count",
        "value": "64 internal host addresses contacted",
        "highlight": true
      },
      {
        "label": "RST Rate Received",
        "value": "812 RST packets returned from closed endpoints",
        "highlight": false
      },
      {
        "label": "Scanner Heuristic",
        "value": "Nmap SYN Stealth (-sS) timing template T4 match",
        "highlight": true
      }
    ],
    "why_not": [
      {
        "threat": "Legitimate Nessus / Vulnerability Scanner",
        "reason": "Source host 10.0.4.119 is a workstation jump-box, not a registered Qualys/Nessus security scanner IP."
      },
      {
        "threat": "Distributed Denial of Service",
        "reason": "Targeting multiple sequential internal ports with single SYN probes rather than flooding single port with high bandwidth."
      }
    ],
    "related_alerts": [
      {
        "id": "ALT-2026-9040",
        "class": "DGA Domains / DNS Tunneling",
        "sev": "critical",
        "summary": "High-entropy DNS queries from 10.0.4.119",
        "time": "6m ago"
      }
    ],
    "has_blast_radius": false
  },
  "ALT-2026-9036": {
    "id": "ALT-2026-9036",
    "timestamp": "2026-09-28T02:04:10.000Z",
    "flow_id": "FLW-88210-UDP",
    "threat_class": "Volumetric/Protocol DDoS",
    "severity": "critical",
    "confidence": 0.97,
    "calibration": "Higher than 99% of volumetric anomaly baselines",
    "summary": "Abnormal ingress packet surge (14,200 pps) targeting core perimeter routing interface",
    "src_ip": "Multiple (Botnet)",
    "src_port": 0,
    "dst_ip": "10.0.1.1",
    "dst_port": 53,
    "proto": "UDP/DNS Amplification",
    "state": "confirmed",
    "analyst_label": "confirmed",
    "analyst_note": "Upstream ACL filter engaged at border router",
    "evidence_features": [
      {
        "label": "Ingress Packet Rate",
        "value": "14,200 pkts/sec (Normal Baseline: 420 pps)",
        "highlight": true
      },
      {
        "label": "Source IP Entropy",
        "value": "0.12 (Reflected amplification from fixed reflector pool)",
        "highlight": true
      },
      {
        "label": "Bandwidth Consumed",
        "value": "1.42 Gbps at physical diode optical interface",
        "highlight": true
      },
      {
        "label": "Amplification Factor",
        "value": "48x payload multiplier (ANY query response flood)",
        "highlight": true
      },
      {
        "label": "Target Interface",
        "value": "ETH-CORE-DIODE-INGRESS-01",
        "highlight": false
      },
      {
        "label": "Mitigation State",
        "value": "Rate-limiting applied at upstream BGP peer",
        "highlight": false
      }
    ],
    "why_not": [
      {
        "threat": "Legitimate Peak Traffic",
        "reason": "3,380% surge over historical 30-day baseline during off-peak maintenance window."
      },
      {
        "threat": "Internal Network Loop",
        "reason": "Hop count (TTL) indicates packets traversed external WAN autonomous systems."
      }
    ],
    "related_alerts": [],
    "has_blast_radius": false
  }
};

const NEW_ALERT_POOL = [
  {
    "threat_class": "DGA Domains / DNS Tunneling",
    "severity": "critical",
    "confidence": 0.95,
    "summary": "High entropy (4.61) TXT query sequence over UDP port 53 to authoritative name server",
    "src_ip": "10.0.12.84",
    "src_port": 58120,
    "dst_ip": "198.51.100.99",
    "dst_port": 53,
    "proto": "UDP/DNS",
    "correlation_count": 6,
    "correlation_window": "15 min"
  },
  {
    "threat_class": "Malware in Encrypted Sessions (TLS/QUIC)",
    "severity": "high",
    "confidence": 0.89,
    "summary": "Known TrickBot C2 JA3S fingerprint matched with sustained small packet intervals",
    "src_ip": "10.0.9.14",
    "src_port": 49120,
    "dst_ip": "192.0.2.201",
    "dst_port": 443,
    "proto": "TCP/TLS 1.3",
    "correlation_count": 2,
    "correlation_window": "10 min"
  },
  {
    "threat_class": "Volumetric/Protocol DDoS",
    "severity": "critical",
    "confidence": 0.98,
    "summary": "Synchronous TCP SYN flood surge (18,400 pps) detected across core DMZ ingress diode",
    "src_ip": "Multiple (Botnet)",
    "src_port": 0,
    "dst_ip": "10.0.1.20",
    "dst_port": 80,
    "proto": "TCP/SYN",
    "correlation_count": 9,
    "correlation_window": "30 min"
  }
];

module.exports = {
  SEED_ALERTS,
  INVESTIGATION_DATABASE,
  NEW_ALERT_POOL
};
