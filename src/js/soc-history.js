/**
 * Paladin AI SOC History - Historical Search, Table Sorting, Filtering & Export
 * Supports dual-theme (Dark & Light) report styling
 */

(function () {
  'use strict';

  // --- Historical Database of 30+ Alert Incidents ---
  const HISTORICAL_ALERTS = [
    {
      id: "ALT-2026-9041",
      timestamp: "2026-09-28T02:14:15.000Z",
      flow_id: "FLW-88319-TCP",
      threat_class: "Data Exfiltration",
      severity: "critical",
      confidence: 0.96,
      src_ip: "10.0.12.84",
      src_port: 49822,
      dst_ip: "203.0.113.88",
      dst_port: 443,
      proto: "TCP/TLS 1.3",
      state: "active",
      analyst_label: "unlabeled",
      summary: "High-volume outbound byte asymmetry (418 MB out vs 14 KB in) over encrypted tunnel"
    },
    {
      id: "ALT-2026-9040",
      timestamp: "2026-09-28T02:13:00.000Z",
      flow_id: "FLW-88314-UDP",
      threat_class: "DGA Domains / DNS Tunneling",
      severity: "critical",
      confidence: 0.94,
      src_ip: "10.0.4.119",
      src_port: 53210,
      dst_ip: "198.51.100.12",
      dst_port: 53,
      proto: "UDP/DNS",
      state: "active",
      analyst_label: "unlabeled",
      summary: "High-entropy domain queries (4.38 n-gram) with 380 QPS burst to authoritative server"
    },
    {
      id: "ALT-2026-9039",
      timestamp: "2026-09-28T02:11:40.000Z",
      flow_id: "FLW-88299-TCP",
      threat_class: "Botnet C2 Beaconing",
      severity: "high",
      confidence: 0.91,
      src_ip: "10.0.12.84",
      src_port: 51240,
      dst_ip: "198.51.100.44",
      dst_port: 8443,
      proto: "TCP/HTTPS",
      state: "active",
      analyst_label: "unlabeled",
      summary: "Periodic TCP heartbeats with low jitter (delta: 60.1s ±0.4s) to external staging IP"
    },
    {
      id: "ALT-2026-9038",
      timestamp: "2026-09-28T02:09:30.000Z",
      flow_id: "FLW-88280-TCP",
      threat_class: "Malware in Encrypted Sessions (TLS/QUIC)",
      severity: "high",
      confidence: 0.88,
      src_ip: "10.0.8.210",
      src_port: 48991,
      dst_ip: "192.0.2.145",
      dst_port: 443,
      proto: "TCP/TLS 1.3",
      state: "active",
      analyst_label: "unlabeled",
      summary: "JA3 hash matches known CobaltStrike malleable C2 profile with anomalous initial burst lengths"
    },
    {
      id: "ALT-2026-9037",
      timestamp: "2026-09-28T02:06:50.000Z",
      flow_id: "FLW-88250-TCP",
      threat_class: "Reconnaissance/Port Scanning",
      severity: "medium",
      confidence: 0.85,
      src_ip: "10.0.4.119",
      src_port: 60102,
      dst_ip: "10.0.4.1/24",
      dst_port: "Multi (1-1024)",
      proto: "TCP/SYN",
      state: "active",
      analyst_label: "unlabeled",
      summary: "Fast horizontal SYN probe against 1,024 destination ports across internal subnet 10.0.4.0/24"
    },
    {
      id: "ALT-2026-9036",
      timestamp: "2026-09-28T02:04:10.000Z",
      flow_id: "FLW-88210-UDP",
      threat_class: "Volumetric/Protocol DDoS",
      severity: "critical",
      confidence: 0.97,
      src_ip: "Multiple (Botnet)",
      src_port: 0,
      dst_ip: "10.0.1.1",
      dst_port: 53,
      proto: "UDP/DNS",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "Abnormal ingress packet surge (14,200 pps) targeting core perimeter routing interface"
    },
    {
      id: "ALT-2026-9035",
      timestamp: "2026-09-28T01:54:00.000Z",
      flow_id: "FLW-88190-TCP",
      threat_class: "Botnet C2 Beaconing",
      severity: "low",
      confidence: 0.52,
      src_ip: "10.0.2.45",
      src_port: 54100,
      dst_ip: "20.190.159.0",
      dst_port: 443,
      proto: "TCP/HTTPS",
      state: "false_positive",
      analyst_label: "false_positive",
      summary: "Periodic polling to official Microsoft telemetry endpoint; verified Windows Update"
    },
    {
      id: "ALT-2026-9034",
      timestamp: "2026-09-28T01:42:00.000Z",
      flow_id: "FLW-88165-TCP",
      threat_class: "Data Exfiltration",
      severity: "high",
      confidence: 0.89,
      src_ip: "10.0.15.12",
      src_port: 44102,
      dst_ip: "104.18.2.10",
      dst_port: 443,
      proto: "TCP/HTTPS",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "Scheduled nightly tarball upload to Cloudflare R2 bucket with elevated egress volume"
    },
    {
      id: "ALT-2026-9033",
      timestamp: "2026-09-27T22:15:00.000Z",
      flow_id: "FLW-87940-TCP",
      threat_class: "Data Exfiltration",
      severity: "critical",
      confidence: 0.95,
      src_ip: "10.0.12.84",
      src_port: 52119,
      dst_ip: "185.220.101.5",
      dst_port: 443,
      proto: "TCP/TLS",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "Tor exit node exfiltration tunnel observed from infected endpoint 10.0.12.84"
    },
    {
      id: "ALT-2026-9032",
      timestamp: "2026-09-27T19:30:00.000Z",
      flow_id: "FLW-87720-UDP",
      threat_class: "Volumetric/Protocol DDoS",
      severity: "critical",
      confidence: 0.98,
      src_ip: "Multiple (NTP)",
      src_port: 123,
      dst_ip: "10.0.1.10",
      dst_port: 123,
      proto: "UDP/NTP",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "NTP monlist amplification flood saturating WAN boundary diode buffer"
    },
    {
      id: "ALT-2026-9031",
      timestamp: "2026-09-27T16:12:00.000Z",
      flow_id: "FLW-87500-TCP",
      threat_class: "Malware in Encrypted Sessions (TLS/QUIC)",
      severity: "medium",
      confidence: 0.74,
      src_ip: "10.0.3.99",
      src_port: 49912,
      dst_ip: "142.250.190.46",
      dst_port: 443,
      proto: "QUIC/UDP",
      state: "false_positive",
      analyst_label: "false_positive",
      summary: "Google Chrome QUIC protocol packet sequence misclassified due to packet reordering"
    },
    {
      id: "ALT-2026-9030",
      timestamp: "2026-09-27T11:45:00.000Z",
      flow_id: "FLW-87210-TCP",
      threat_class: "Reconnaissance/Port Scanning",
      severity: "high",
      confidence: 0.92,
      src_ip: "10.0.12.84",
      src_port: 59120,
      dst_ip: "10.0.12.0/24",
      dst_port: "445 (SMB)",
      proto: "TCP/SYN",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "Lateral movement SMB port scan probing internal finance workstations"
    },
    {
      id: "ALT-2026-9029",
      timestamp: "2026-09-26T14:20:00.000Z",
      flow_id: "FLW-86800-UDP",
      threat_class: "DGA Domains / DNS Tunneling",
      severity: "high",
      confidence: 0.90,
      src_ip: "10.0.5.21",
      src_port: 54110,
      dst_ip: "8.8.4.4",
      dst_port: 53,
      proto: "UDP/DNS",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "Base64 encoded data exfiltration inside DNS TXT records to dynamic subdomain"
    },
    {
      id: "ALT-2026-9028",
      timestamp: "2026-09-25T09:10:00.000Z",
      flow_id: "FLW-86400-TCP",
      threat_class: "Data Exfiltration",
      severity: "critical",
      confidence: 0.97,
      src_ip: "10.0.12.84",
      src_port: 48910,
      dst_ip: "91.240.118.17",
      dst_port: 21,
      proto: "TCP/FTP",
      state: "confirmed",
      analyst_label: "confirmed",
      summary: "Raw credentials and tarball transmitted via unencrypted FTP to foreign hosting provider"
    }
  ];

  // Filtering, Sorting and Pagination State
  const state = {
    searchQuery: '',
    threatClass: 'all',
    severity: 'all',
    label: 'all',
    dateRange: 'all',
    sortField: 'timestamp',
    sortDir: 'desc',
    currentPage: 1,
    pageSize: 8
  };

  // Severity Weight mapping
  const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1 };

  function getSevClass(sev) {
    switch (sev) {
      case 'critical': return 'crit';
      case 'high': return 'high';
      case 'medium': return 'med';
      case 'low': return 'low';
      default: return 'low';
    }
  }

  // Filter & Sort Logic
  function getFilteredData() {
    const now = Date.now();

    return HISTORICAL_ALERTS.filter(alert => {
      // Search
      if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        const match =
          alert.id.toLowerCase().includes(q) ||
          alert.summary.toLowerCase().includes(q) ||
          alert.src_ip.toLowerCase().includes(q) ||
          alert.dst_ip.toLowerCase().includes(q) ||
          alert.flow_id.toLowerCase().includes(q);
        if (!match) return false;
      }

      // Threat Class
      if (state.threatClass !== 'all' && alert.threat_class !== state.threatClass) {
        return false;
      }

      // Severity
      if (state.severity !== 'all' && alert.severity !== state.severity) {
        return false;
      }

      // Analyst Label
      if (state.label !== 'all' && alert.analyst_label !== state.label) {
        return false;
      }

      // Date Range
      if (state.dateRange !== 'all') {
        const alertTime = new Date(alert.timestamp).getTime();
        const diffHours = (now - alertTime) / (1000 * 60 * 60);

        if (state.dateRange === '24h' && diffHours > 24) return false;
        if (state.dateRange === '7d' && diffHours > 24 * 7) return false;
        if (state.dateRange === '30d' && diffHours > 24 * 30) return false;
      }

      return true;
    }).sort((a, b) => {
      let valA = a[state.sortField];
      let valB = b[state.sortField];

      if (state.sortField === 'timestamp') {
        valA = new Date(valA).getTime();
        valB = new Date(valB).getTime();
      } else if (state.sortField === 'severity') {
        valA = SEV_WEIGHT[valA] || 0;
        valB = SEV_WEIGHT[valB] || 0;
      }

      if (valA < valB) return state.sortDir === 'asc' ? -1 : 1;
      if (valA > valB) return state.sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  // Render History Table Rows
  function renderTable() {
    const tableBody = document.getElementById('historyTableBody');
    const pageInfo = document.getElementById('pageInfo');
    const paginationNav = document.getElementById('paginationNav');
    if (!tableBody) return;

    const filtered = getFilteredData();
    const totalItems = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / state.pageSize));

    if (state.currentPage > totalPages) state.currentPage = totalPages;

    const startIndex = (state.currentPage - 1) * state.pageSize;
    const endIndex = Math.min(startIndex + state.pageSize, totalItems);
    const pageData = filtered.slice(startIndex, endIndex);

    if (pageData.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 48px 16px; color: var(--soc-text-dim);">
            <div style="font-family: var(--font-mono); font-size: 13px; margin-bottom: 6px;">NO HISTORICAL INCIDENTS FOUND</div>
            <div style="font-size: 12px;">Try adjusting the search query, threat class, or date range filter.</div>
          </td>
        </tr>
      `;
    } else {
      tableBody.innerHTML = pageData.map(alert => {
        const sevClass = getSevClass(alert.severity);
        const confPct = Math.round(alert.confidence * 100);
        const isoTime = new Date(alert.timestamp).toISOString().replace('T', ' ').substring(0, 19);

        let labelBadge = `<span class="soc-state-badge" style="opacity: 0.6;">UNLABELED</span>`;
        if (alert.analyst_label === 'confirmed') {
          labelBadge = `<span class="soc-state-badge confirmed">✓ CONFIRMED</span>`;
        } else if (alert.analyst_label === 'false_positive') {
          labelBadge = `<span class="soc-state-badge fp">FALSE +</span>`;
        }

        return `
          <tr onclick="window.location.href='investigation.html?alert_id=${encodeURIComponent(alert.id)}'">
            <td class="mono" style="color: var(--soc-text-subtle);">${isoTime}</td>
            <td>
              <span class="soc-threat-badge ${sevClass}" style="font-size: 9.5px;">${alert.threat_class}</span>
            </td>
            <td class="mono">
              <span style="font-weight: 700; text-transform: uppercase;" class="soc-stat-value ${sevClass === 'crit' ? 'crit' : ''}">${alert.severity}</span>
            </td>
            <td class="mono">
              <strong>${alert.src_ip}</strong>
              <span style="color: var(--soc-text-dim);"> → </span>
              <span>${alert.dst_ip}</span>
              <span style="font-size: 10px; color: var(--soc-text-dim); margin-left: 4px;">(${alert.proto})</span>
            </td>
            <td class="mono">
              <div style="display: flex; align-items: center; gap: 6px;">
                <span>${confPct}%</span>
                <div class="soc-conf-bar" style="width: 50px;">
                  <div class="soc-conf-bar__fill ${sevClass}" style="width: ${confPct}%;"></div>
                </div>
              </div>
            </td>
            <td>${labelBadge}</td>
            <td>
              <a href="investigation.html?alert_id=${encodeURIComponent(alert.id)}" class="soc-btn-drill" onclick="event.stopPropagation();">
                INSPECT <span>→</span>
              </a>
            </td>
          </tr>
        `;
      }).join('');
    }

    // Update Pagination Display
    if (pageInfo) {
      pageInfo.textContent = `Showing ${totalItems > 0 ? startIndex + 1 : 0} - ${endIndex} of ${totalItems} records`;
    }

    if (paginationNav) {
      let navHtml = `
        <button class="soc-page-btn" id="prevPageBtn" ${state.currentPage === 1 ? 'disabled' : ''}>‹</button>
      `;

      for (let p = 1; p <= totalPages; p++) {
        navHtml += `
          <button class="soc-page-btn ${p === state.currentPage ? 'is-active' : ''}" data-page="${p}">${p}</button>
        `;
      }

      navHtml += `
        <button class="soc-page-btn" id="nextPageBtn" ${state.currentPage === totalPages ? 'disabled' : ''}>›</button>
      `;

      paginationNav.innerHTML = navHtml;
    }
  }

  // Export current filtered results as CSV
  function exportCsv() {
    const data = getFilteredData();
    const headers = ["Alert_ID", "Timestamp", "Flow_ID", "Threat_Class", "Severity", "Confidence", "Source_IP", "Dest_IP", "Protocol", "Analyst_Label", "Summary"];
    const rows = data.map(a => [
      a.id,
      a.timestamp,
      a.flow_id,
      `"${a.threat_class}"`,
      a.severity,
      a.confidence,
      a.src_ip,
      a.dst_ip,
      a.proto,
      a.analyst_label,
      `"${a.summary.replace(/"/g, '""')}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    const encoded = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encoded);
    link.setAttribute("download", `paladin_audit_log_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // Export current filtered results as JSON
  function exportJson() {
    const data = getFilteredData();
    const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", jsonStr);
    link.setAttribute("download", `paladin_audit_log_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // Initialize History Event Handlers
  document.addEventListener('DOMContentLoaded', () => {
    renderTable();

    // Search Input
    const searchInput = document.getElementById('histSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.trim();
        state.currentPage = 1;
        renderTable();
      });
    }

    // Threat Class Filter
    const classSelect = document.getElementById('histClassSelect');
    if (classSelect) {
      classSelect.addEventListener('change', (e) => {
        state.threatClass = e.target.value;
        state.currentPage = 1;
        renderTable();
      });
    }

    // Severity Filter
    const sevSelect = document.getElementById('histSevSelect');
    if (sevSelect) {
      sevSelect.addEventListener('change', (e) => {
        state.severity = e.target.value;
        state.currentPage = 1;
        renderTable();
      });
    }

    // Analyst Label Filter
    const labelSelect = document.getElementById('histLabelSelect');
    if (labelSelect) {
      labelSelect.addEventListener('change', (e) => {
        state.label = e.target.value;
        state.currentPage = 1;
        renderTable();
      });
    }

    // Date Range Filter
    const dateSelect = document.getElementById('histDateSelect');
    if (dateSelect) {
      dateSelect.addEventListener('change', (e) => {
        state.dateRange = e.target.value;
        state.currentPage = 1;
        renderTable();
      });
    }

    // Column Header Sorting
    const sortHeaders = document.querySelectorAll('th[data-sort]');
    sortHeaders.forEach(th => {
      th.addEventListener('click', () => {
        const field = th.getAttribute('data-sort');
        if (state.sortField === field) {
          state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          state.sortField = field;
          state.sortDir = 'desc';
        }

        sortHeaders.forEach(h => h.classList.remove('is-sorted'));
        th.classList.add('is-sorted');
        renderTable();
      });
    });

    // Pagination Click Delegation
    const paginationNav = document.getElementById('paginationNav');
    if (paginationNav) {
      paginationNav.addEventListener('click', (e) => {
        const pageBtn = e.target.closest('[data-page]');
        if (pageBtn) {
          state.currentPage = parseInt(pageBtn.getAttribute('data-page'), 10);
          renderTable();
          return;
        }

        if (e.target.closest('#prevPageBtn') && state.currentPage > 1) {
          state.currentPage--;
          renderTable();
          return;
        }

        if (e.target.closest('#nextPageBtn')) {
          state.currentPage++;
          renderTable();
          return;
        }
      });
    }

    // Export Buttons
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
      exportCsvBtn.addEventListener('click', (e) => {
        e.preventDefault();
        exportCsv();
      });
    }

    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
      exportJsonBtn.addEventListener('click', (e) => {
        e.preventDefault();
        exportJson();
      });
    }
  });

})();
