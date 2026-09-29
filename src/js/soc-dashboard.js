/**
 * Paladin AI SOC Dashboard - Live Triage Feed Logic
 * Handles alert state, sorting, filtering, simulated live stream, and analyst actions
 */

(function () {
  'use strict';

  // --- Initial Mock Alerts Data (Standardized Paladin AI Alert Schema) ---
  const INITIAL_ALERTS = [
    {
      id: "ALT-2026-9041",
      timestamp: new Date(Date.now() - 45 * 1000).toISOString(),
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
      proto: "TCP/TLS",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      correlation_count: 5,
      correlation_window: "15 min",
      evidence: {
        bytes_out: 438304768,
        bytes_in: 14336,
        ratio: 30573.7,
        flow_duration_sec: 142,
        entropy: 7.94
      }
    },
    {
      id: "ALT-2026-9040",
      timestamp: new Date(Date.now() - 110 * 1000).toISOString(),
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
      correlation_count: 3,
      correlation_window: "10 min",
      evidence: {
        domain: "qx9z-v88a-secops-update.dyn-dns.io",
        entropy: 4.38,
        qps: 380,
        txt_record_ratio: 0.88
      }
    },
    {
      id: "ALT-2026-9039",
      timestamp: new Date(Date.now() - 190 * 1000).toISOString(),
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
      correlation_count: 5,
      correlation_window: "15 min",
      evidence: {
        beacon_interval_sec: 60.1,
        jitter_percent: 0.65,
        streak_count: 24,
        payload_entropy: 7.21
      }
    },
    {
      id: "ALT-2026-9038",
      timestamp: new Date(Date.now() - 320 * 1000).toISOString(),
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
      correlation_count: 1,
      correlation_window: "10 min",
      evidence: {
        ja3: "a0e9f5d64349fb13191bc781f81f42e8",
        ja3s: "ec74a5c5110605f9f8eac32c925904e7",
        cert_subject: "CN=internal-telemetry-cdn.net",
        cert_validity_days: 7
      }
    },
    {
      id: "ALT-2026-9037",
      timestamp: new Date(Date.now() - 480 * 1000).toISOString(),
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
      correlation_count: 3,
      correlation_window: "10 min",
      evidence: {
        probed_ports: 1024,
        syn_ratio: 0.99,
        sweep_duration_sec: 14.2,
        fan_out_degree: 64
      }
    },
    {
      id: "ALT-2026-9036",
      timestamp: new Date(Date.now() - 650 * 1000).toISOString(),
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
      correlation_count: 8,
      correlation_window: "30 min",
      evidence: {
        packet_rate_pps: 14200,
        entropy: 0.12,
        baseline_rate: 420,
        amplification_factor: 48
      }
    },
    {
      id: "ALT-2026-9035",
      timestamp: new Date(Date.now() - 890 * 1000).toISOString(),
      flow_id: "FLW-88190-TCP",
      threat_class: "Botnet C2 Beaconing",
      severity: "low",
      confidence: 0.52,
      calibration: "Below 60% probability threshold",
      summary: "Periodic polling to official Microsoft telemetry endpoint; consistent with Windows Update service",
      src_ip: "10.0.2.45",
      src_port: 54100,
      dst_ip: "20.190.159.0",
      dst_port: 443,
      proto: "TCP/HTTPS",
      state: "false_positive",
      analyst_label: "false_positive",
      analyst_note: "Verified legitimate Windows telemetry traffic",
      correlation_count: 0,
      correlation_window: "none",
      evidence: {
        beacon_interval_sec: 300,
        jitter_percent: 14.2,
        asn: "AS8075 MICROSOFT-CORP"
      }
    },
    {
      id: "ALT-2026-9034",
      timestamp: new Date(Date.now() - 1140 * 1000).toISOString(),
      flow_id: "FLW-88165-TCP",
      threat_class: "Data Exfiltration",
      severity: "high",
      confidence: 0.89,
      calibration: "Higher than 89% of confirmed exfiltration triggers",
      summary: "Scheduled nightly tarball upload to Cloudflare R2 bucket with elevated egress volume",
      src_ip: "10.0.15.12",
      src_port: 44102,
      dst_ip: "104.18.2.10",
      dst_port: 443,
      proto: "TCP/HTTPS",
      state: "active",
      analyst_label: null,
      analyst_note: "",
      correlation_count: 2,
      correlation_window: "24h",
      evidence: {
        bytes_out: 128974848,
        bytes_in: 8192,
        ratio: 15744.0,
        destination_domain: "backup-sync.internal.storage"
      }
    }
  ];

  // Storage / Session State
  let alerts = [];
  try {
    const cached = sessionStorage.getItem('paladin_live_alerts');
    if (cached) {
      alerts = JSON.parse(cached);
    }
  } catch (e) {
    // fallback
  }

  if (!alerts || alerts.length === 0) {
    alerts = JSON.parse(JSON.stringify(INITIAL_ALERTS));
  }

  // Active Filter & Sort State
  const state = {
    searchQuery: '',
    threatClass: 'all',
    severity: 'all',
    alertState: 'active',   // Default: only show active alerts
    sortBy: 'priority', // 'priority' | 'chronological'
    timeWindow: '24h',
    isPaused: false
  };

  // Severity Weight Mapping for Priority Calculation: (severity_weight * confidence)
  const SEVERITY_WEIGHT = {
    critical: 1.0,
    high: 0.75,
    medium: 0.5,
    low: 0.25
  };

  function calculatePriority(alert) {
    const weight = SEVERITY_WEIGHT[alert.severity] || 0.2;
    return weight * (alert.confidence || 0);
  }

  // Relative Time Formatter
  function formatRelativeTime(isoString) {
    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diffSec = Math.max(1, Math.floor((now - then) / 1000));

    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    return `${Math.floor(diffHour / 24)}d ago`;
  }

  function getSeverityClass(severity) {
    switch (severity) {
      case 'critical': return 'crit';
      case 'high': return 'high';
      case 'medium': return 'med';
      case 'low': return 'low';
      default: return 'low';
    }
  }

  // Save alerts to session
  function persistAlerts() {
    try {
      sessionStorage.setItem('paladin_live_alerts', JSON.stringify(alerts));
    } catch (e) {
      // storage quota or disabled
    }
  }

  // Calculate and update Labeling Stats Strip
  function updateStatsStrip() {
    const total = alerts.length;
    const confirmed = alerts.filter(a => a.analyst_label === 'confirmed').length;
    const fp = alerts.filter(a => a.analyst_label === 'false_positive').length;
    const active = alerts.filter(a => !a.analyst_label).length;

    const labeledTotal = confirmed + fp;
    const precisionPct = labeledTotal > 0 ? Math.round((confirmed / labeledTotal) * 100) : 94;

    const statTotalEl = document.getElementById('statTotal');
    const statConfirmedEl = document.getElementById('statConfirmed');
    const statFpEl = document.getElementById('statFp');
    const statActiveEl = document.getElementById('statActive');
    const statPrecisionEl = document.getElementById('statPrecision');
    const liveCountBadge = document.getElementById('liveCountBadge');

    if (statTotalEl) statTotalEl.textContent = total;
    if (statConfirmedEl) statConfirmedEl.textContent = confirmed;
    if (statFpEl) statFpEl.textContent = fp;
    if (statActiveEl) statActiveEl.textContent = active;
    if (statPrecisionEl) statPrecisionEl.textContent = `${precisionPct}%`;
    if (liveCountBadge) liveCountBadge.textContent = `${active} QUEUED`;
  }

  // Render Filtered & Sorted Feed
  function renderFeed(preserveScroll = true) {
    const feedContainer = document.getElementById('alertFeed');
    if (!feedContainer) return;

    const scrollY = window.scrollY;

    // Filter
    let filtered = alerts.filter(alert => {
      // Search Query
      if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        const matchSearch =
          alert.id.toLowerCase().includes(q) ||
          alert.summary.toLowerCase().includes(q) ||
          alert.src_ip.toLowerCase().includes(q) ||
          alert.dst_ip.toLowerCase().includes(q) ||
          alert.threat_class.toLowerCase().includes(q) ||
          (alert.proto && alert.proto.toLowerCase().includes(q));
        if (!matchSearch) return false;
      }

      // Threat Class
      if (state.threatClass !== 'all' && alert.threat_class !== state.threatClass) {
        return false;
      }

      // Severity
      if (state.severity !== 'all' && alert.severity !== state.severity) {
        return false;
      }

      // State / Label
      if (state.alertState !== 'all') {
        if (state.alertState === 'active' && alert.analyst_label) return false;
        if (state.alertState === 'confirmed' && alert.analyst_label !== 'confirmed') return false;
        if (state.alertState === 'false_positive' && alert.analyst_label !== 'false_positive') return false;
      }

      return true;
    });

    // Sort
    if (state.sortBy === 'priority') {
      filtered.sort((a, b) => calculatePriority(b) - calculatePriority(a));
    } else {
      // Chronological (newest first)
      filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    if (filtered.length === 0) {
      feedContainer.innerHTML = `
        <div style="padding: 48px 24px; text-align: center; background: var(--soc-panel); border: 1px dashed var(--soc-panel-border); border-radius: var(--radius-sm);">
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--soc-text-subtle); margin-bottom: 8px;">NO MATCHING ALERTS IN CURRENT VIEW</div>
          <p style="font-size: 12px; color: var(--soc-text-dim);">Adjust search filters or time window to display queued network events.</p>
        </div>
      `;
      return;
    }

    // Build Cards HTML
    const cardsHtml = filtered.map(alert => {
      const sevClass = getSeverityClass(alert.severity);
      const isConfirmed = alert.analyst_label === 'confirmed';
      const isFp = alert.analyst_label === 'false_positive';
      const isNew = alert.is_new ? 'is-new' : '';

      let cardClasses = `soc-alert-card ${sevClass} ${isNew}`;
      if (isConfirmed) cardClasses += ' is-confirmed';
      if (isFp) cardClasses += ' is-fp';

      let stateBadgeHtml = `<span class="soc-state-badge active">ACTIVE</span>`;
      if (isConfirmed) {
        stateBadgeHtml = `<span class="soc-state-badge confirmed">✓ CONFIRMED</span>`;
      } else if (isFp) {
        stateBadgeHtml = `<span class="soc-state-badge fp">FALSE +</span>`;
      }

      const confPct = Math.round(alert.confidence * 100);
      const relTime = formatRelativeTime(alert.timestamp);
      const fullTime = new Date(alert.timestamp).toLocaleString();

      const correlationHtml = alert.correlation_count > 1 ? `
        <div class="soc-alert-card__correlation" data-action="filter-src" data-ip="${alert.src_ip}" title="Click to filter feed to this source IP">
          <span>⚠️</span>
          <span>${alert.correlation_count} alerts from ${alert.src_ip} in last ${alert.correlation_window}</span>
        </div>
      ` : '';

      return `
        <div class="${cardClasses}" data-alert-id="${alert.id}">
          <div class="soc-alert-card__header">
            <div class="soc-alert-card__header-left">
              <span class="soc-threat-badge ${sevClass}">${alert.threat_class}</span>
              ${stateBadgeHtml}
              <span style="font-family: var(--font-mono); font-size: 10px; color: var(--soc-text-dim);">${alert.id}</span>
            </div>
            <div class="soc-alert-card__time" title="${fullTime}">${relTime}</div>
          </div>

          <div class="soc-alert-card__summary">
            ${alert.summary}
          </div>

          <div class="soc-alert-card__meta">
            <div class="soc-alert-card__network">
              <span class="soc-ip-source">${alert.src_ip}</span>
              ${alert.src_port ? `<span style="color: var(--soc-text-dim);">:${alert.src_port}</span>` : ''}
              <span class="soc-ip-arrow">→</span>
              <span class="soc-ip-dest">${alert.dst_ip}</span>
              ${alert.dst_port ? `<span style="color: var(--soc-text-dim);">:${alert.dst_port}</span>` : ''}
              <span class="soc-proto-tag">${alert.proto}</span>
            </div>

            <div class="soc-alert-card__conf-wrap">
              <span class="soc-conf-label">${confPct}%</span>
              <div class="soc-conf-bar" title="Confidence: ${alert.confidence}">
                <div class="soc-conf-bar__fill ${sevClass}" style="width: ${confPct}%;"></div>
              </div>
            </div>
          </div>

          ${correlationHtml}

          <div class="soc-alert-card__actions" onclick="event.stopPropagation();">
            <div class="soc-card-btn-group">
              <button class="soc-btn-sm soc-btn-confirm" data-action="confirm" data-alert-id="${alert.id}">
                <span>✓</span> Confirm Threat
              </button>
              <button class="soc-btn-sm soc-btn-fp" data-action="fp" data-alert-id="${alert.id}">
                <span>✕</span> False Positive
              </button>
              <button class="soc-note-toggle" data-action="toggle-note" data-alert-id="${alert.id}">
                ${alert.analyst_note ? 'Edit Note' : '+ Note'}
              </button>
            </div>

            <a href="investigation.html?alert_id=${encodeURIComponent(alert.id)}" class="soc-btn-drill">
              INVESTIGATE <span>→</span>
            </a>
          </div>

          <div class="soc-note-drawer ${alert.analyst_note ? 'is-open' : ''}" id="note-drawer-${alert.id}">
            <input type="text" class="soc-note-input" placeholder="Add analyst forensic assessment note..." value="${alert.analyst_note || ''}" data-alert-id="${alert.id}">
            <button class="soc-btn-sm soc-btn-fp" data-action="save-note" data-alert-id="${alert.id}">Save</button>
          </div>
        </div>
      `;
    }).join('');

    feedContainer.innerHTML = cardsHtml;

    if (preserveScroll) {
      window.scrollTo(0, scrollY);
    }

    updateStatsStrip();
  }

  // Analyst Action: Confirm Threat
  function handleConfirm(alertId) {
    const alert = alerts.find(a => a.id === alertId);
    if (!alert) return;

    alert.analyst_label = 'confirmed';
    alert.state = 'confirmed';
    persistAlerts();

    // Animate card out, then re-render (removes it from active feed)
    var _card = document.querySelector(`.soc-alert-card[data-alert-id="${alertId}"]`);
    if (_card) {
      _card.style.transition = 'opacity 0.35s ease, transform 0.35s ease';
      _card.style.opacity = '0';
      _card.style.transform = 'translateX(18px)';
      setTimeout(function() { renderFeed(true); updateStatsStrip(); }, 380);
    } else {
      renderFeed(true);
    }
    updateStatsStrip();

    const apiBase = window.location.origin.startsWith('http') ? '' : 'http://localhost:3001';
    fetch(apiBase + '/api/alerts/' + encodeURIComponent(alertId) + '/confirm', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: alert.analyst_note || '' })
    }).catch(function() {});
  }

  // Analyst Action: Mark False Positive
  function handleFalsePositive(alertId) {
    const alert = alerts.find(a => a.id === alertId);
    if (!alert) return;

    alert.analyst_label = 'false_positive';
    alert.state = 'false_positive';
    persistAlerts();

    // Animate card out, then re-render (removes it from active feed)
    var _cardFp = document.querySelector(`.soc-alert-card[data-alert-id="${alertId}"]`);
    if (_cardFp) {
      _cardFp.style.transition = 'opacity 0.35s ease, transform 0.35s ease';
      _cardFp.style.opacity = '0';
      _cardFp.style.transform = 'translateX(18px)';
      setTimeout(function() { renderFeed(true); updateStatsStrip(); }, 380);
    } else {
      renderFeed(true);
    }
    updateStatsStrip();

    const apiBase = window.location.origin.startsWith('http') ? '' : 'http://localhost:3001';
    fetch(apiBase + '/api/alerts/' + encodeURIComponent(alertId) + '/fp', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: alert.analyst_note || '' })
    }).catch(function() {});
  }

  // Analyst Action: Save Note
  function handleSaveNote(alertId) {
    const alert = alerts.find(a => a.id === alertId);
    if (!alert) return;

    const input = document.querySelector(`.soc-note-input[data-alert-id="${alertId}"]`);
    if (input) {
      alert.analyst_note = input.value.trim();
      persistAlerts();
      renderFeed(true);

      const apiBase = window.location.origin.startsWith('http') ? '' : 'http://localhost:3001';
      fetch(apiBase + '/api/alerts/' + encodeURIComponent(alertId) + '/note', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: alert.analyst_note })
      }).catch(function() {});
    }
  }

  // Export current feed to CSV
  function exportFeedToCsv() {
    const headers = ["Alert_ID", "Timestamp", "Flow_ID", "Threat_Class", "Severity", "Confidence", "Source_IP", "Dest_IP", "Protocol", "State", "Analyst_Label", "Summary"];
    const rows = alerts.map(a => [
      a.id,
      a.timestamp,
      a.flow_id,
      `"${a.threat_class}"`,
      a.severity,
      a.confidence,
      a.src_ip,
      a.dst_ip,
      a.proto,
      a.state,
      a.analyst_label || "unlabeled",
      `"${(a.summary || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `paladin_live_feed_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // Simulated WebSocket Incoming Alert Stream
  const NEW_ALERT_POOL = [
    {
      threat_class: "DGA Domains / DNS Tunneling",
      severity: "critical",
      confidence: 0.95,
      summary: "High entropy (4.61) TXT query sequence over UDP port 53 to authoritative name server",
      src_ip: "10.0.12.84",
      src_port: 58120,
      dst_ip: "198.51.100.99",
      dst_port: 53,
      proto: "UDP/DNS",
      correlation_count: 6,
      correlation_window: "15 min"
    },
    {
      threat_class: "Malware in Encrypted Sessions (TLS/QUIC)",
      severity: "high",
      confidence: 0.89,
      summary: "Known TrickBot C2 JA3S fingerprint matched with sustained small packet intervals",
      src_ip: "10.0.9.14",
      src_port: 49120,
      dst_ip: "192.0.2.201",
      dst_port: 443,
      proto: "TCP/TLS 1.3",
      correlation_count: 2,
      correlation_window: "10 min"
    },
    {
      threat_class: "Volumetric/Protocol DDoS",
      severity: "critical",
      confidence: 0.98,
      summary: "Synchronous TCP SYN flood surge (18,400 pps) detected across core DMZ ingress diode",
      src_ip: "Multiple (Botnet)",
      src_port: 0,
      dst_ip: "10.0.1.20",
      dst_port: 80,
      proto: "TCP/SYN",
      correlation_count: 9,
      correlation_window: "30 min"
    }
  ];

  let nextAlertCounter = 9042;
  function simulateIncomingAlert() {
    if (state.isPaused) return;

    const template = NEW_ALERT_POOL[Math.floor(Math.random() * NEW_ALERT_POOL.length)];
    const newAlert = {
      id: `ALT-2026-${nextAlertCounter++}`,
      timestamp: new Date().toISOString(),
      flow_id: `FLW-${Math.floor(88320 + Math.random() * 1000)}-${template.proto.split('/')[0]}`,
      threat_class: template.threat_class,
      severity: template.severity,
      confidence: template.confidence,
      summary: template.summary,
      src_ip: template.src_ip,
      src_port: template.src_port,
      dst_ip: template.dst_ip,
      dst_port: template.dst_port,
      proto: template.proto,
      state: "active",
      analyst_label: null,
      analyst_note: "",
      correlation_count: template.correlation_count,
      correlation_window: template.correlation_window,
      is_new: true,
      evidence: {}
    };

    // Prepend new alert
    alerts.unshift(newAlert);
    if (alerts.length > 50) alerts.pop(); // keep buffer manageable
    persistAlerts();
    renderFeed(true);

    // Remove is_new flag after animation runs
    setTimeout(() => {
      newAlert.is_new = false;
    }, 2000);
  }

  // --- Initialize UI Event Listeners ---
  document.addEventListener('DOMContentLoaded', () => {
    // 1. Initial Render
    renderFeed(false);

    // 2. Filter Inputs
    const searchInput = document.getElementById('feedSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.trim();
        renderFeed(true);
      });
    }

    const classSelect = document.getElementById('feedClassSelect');
    if (classSelect) {
      classSelect.addEventListener('change', (e) => {
        state.threatClass = e.target.value;
        renderFeed(true);
      });
    }

    const severitySelect = document.getElementById('feedSeveritySelect');
    if (severitySelect) {
      severitySelect.addEventListener('change', (e) => {
        state.severity = e.target.value;
        renderFeed(true);
      });
    }

    const stateSelect = document.getElementById('feedStateSelect');
    if (stateSelect) {
      stateSelect.addEventListener('change', (e) => {
        state.alertState = e.target.value;
        renderFeed(true);
      });
    }

    // 3. Sort Toggle Buttons
    const sortPriorityBtn = document.getElementById('sortPriorityBtn');
    const sortTimeBtn = document.getElementById('sortTimeBtn');
    if (sortPriorityBtn && sortTimeBtn) {
      sortPriorityBtn.addEventListener('click', () => {
        state.sortBy = 'priority';
        sortPriorityBtn.classList.add('is-active');
        sortTimeBtn.classList.remove('is-active');
        renderFeed(true);
      });

      sortTimeBtn.addEventListener('click', () => {
        state.sortBy = 'chronological';
        sortTimeBtn.classList.add('is-active');
        sortPriorityBtn.classList.remove('is-active');
        renderFeed(true);
      });
    }

    // 4. Time Window Buttons
    const twButtons = document.querySelectorAll('.soc-tw-btn');
    twButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        twButtons.forEach(b => b.classList.remove('is-active'));
        btn.classList.add('is-active');
        state.timeWindow = btn.getAttribute('data-window') || '24h';
      });
    });

    // 5. Card delegation for actions & drill-down
    const feedContainer = document.getElementById('alertFeed');
    if (feedContainer) {
      feedContainer.addEventListener('click', (e) => {
        const confirmBtn = e.target.closest('[data-action="confirm"]');
        if (confirmBtn) {
          e.stopPropagation();
          const alertId = confirmBtn.getAttribute('data-alert-id');
          handleConfirm(alertId);
          return;
        }

        const fpBtn = e.target.closest('[data-action="fp"]');
        if (fpBtn) {
          e.stopPropagation();
          const alertId = fpBtn.getAttribute('data-alert-id');
          handleFalsePositive(alertId);
          return;
        }

        const noteToggle = e.target.closest('[data-action="toggle-note"]');
        if (noteToggle) {
          e.stopPropagation();
          const alertId = noteToggle.getAttribute('data-alert-id');
          const drawer = document.getElementById(`note-drawer-${alertId}`);
          if (drawer) drawer.classList.toggle('is-open');
          return;
        }

        const saveNoteBtn = e.target.closest('[data-action="save-note"]');
        if (saveNoteBtn) {
          e.stopPropagation();
          const alertId = saveNoteBtn.getAttribute('data-alert-id');
          handleSaveNote(alertId);
          return;
        }

        const filterSrcBtn = e.target.closest('[data-action="filter-src"]');
        if (filterSrcBtn) {
          e.stopPropagation();
          const ip = filterSrcBtn.getAttribute('data-ip');
          if (ip) {
            state.searchQuery = ip;
            if (searchInput) searchInput.value = ip;
            renderFeed(true);
          }
          return;
        }

        // Clicking anywhere on card opens investigation drill-down
        const card = e.target.closest('.soc-alert-card');
        if (card) {
          const alertId = card.getAttribute('data-alert-id');
          if (alertId) {
            window.location.href = `investigation.html?alert_id=${encodeURIComponent(alertId)}`;
          }
        }
      });
    }

    // 6. Header Export Button
    const headerExportBtn = document.getElementById('headerExportBtn');
    if (headerExportBtn) {
      headerExportBtn.addEventListener('click', (e) => {
        e.preventDefault();
        exportFeedToCsv();
      });
    }

    // 7. Live Stream Pause / Resume Toggle
    const liveStreamBtn = document.getElementById('liveStreamBtn');
    const liveStreamDot = document.getElementById('liveStreamDot');
    const liveStreamText = document.getElementById('liveStreamText');

    if (liveStreamBtn) {
      liveStreamBtn.addEventListener('click', (e) => {
        e.preventDefault();
        state.isPaused = !state.isPaused;
        if (state.isPaused) {
          if (liveStreamDot) {
            liveStreamDot.classList.add('is-paused');
          }
          if (liveStreamText) liveStreamText.textContent = 'PAUSED';
        } else {
          if (liveStreamDot) {
            liveStreamDot.classList.remove('is-paused');
          }
          if (liveStreamText) liveStreamText.textContent = 'LIVE FEED';
        }
      });
    }

    // 8. Real-time Backend API & WebSocket Stream
    async function fetchAlertsFromBackend() {
      try {
        const apiBase = window.location.origin.startsWith('http') ? '' : 'http://localhost:3001';
        const res = await fetch(apiBase + '/api/alerts');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.alerts) && data.alerts.length > 0) {
            alerts = data.alerts;
            renderFeed(false);
          }
        }
      } catch (e) {}
    }
    fetchAlertsFromBackend();

    function connectWebSocket() {
      const isHttps = window.location.protocol === 'https:';
      const host = window.location.host || 'localhost:3001';
      const wsUrl = (isHttps ? 'wss://' : 'ws://') + host;

      let socket;
      try {
        socket = new WebSocket(wsUrl);
      } catch (e) {
        setInterval(simulateIncomingAlert, 14000);
        return;
      }

      socket.onmessage = function(event) {
        if (state.isPaused) return;
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'NEW_ALERT' && msg.payload) {
            const newAlert = msg.payload;
            newAlert.is_new = true;
            alerts.unshift(newAlert);
            if (alerts.length > 100) alerts.pop();
            renderFeed(true);
            setTimeout(function() { newAlert.is_new = false; }, 2500);
          } else if (msg.type === 'ALERT_UPDATED' && msg.payload) {
            const updated = msg.payload;
            const idx = alerts.findIndex(function(a) { return a.id === updated.id; });
            if (idx !== -1) {
              alerts[idx] = Object.assign({}, alerts[idx], updated);
              renderFeed(true);
            }
          }
        } catch (err) {}
      };

      socket.onclose = function() {
        setTimeout(connectWebSocket, 4000);
      };
      socket.onerror = function() {
        socket.close();
      };
    }
    connectWebSocket();

    // 9. Update Relative Times every 30 seconds
    setInterval(() => {
      renderFeed(true);
    }, 30000);
  });

})();
