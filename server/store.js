const { SEED_ALERTS, INVESTIGATION_DATABASE, NEW_ALERT_POOL } = require('./data/seed-alerts');

let alerts = JSON.parse(JSON.stringify(SEED_ALERTS));
let invDb = JSON.parse(JSON.stringify(INVESTIGATION_DATABASE));
let nextAlertCounter = 9042;

let healthMetrics = {
  pipelineLatencyMs: 41.8,
  throughputMbps: 9420,
  targetThroughputMbps: 10000,
  flowsPerSec: 46280,
  totalIngestedEventsToday: '1,842,910,402',
  packetsAnalyzed: 4821003,
  threatsDetected: 312,
  falsePositiveRate: 2.1,
  diodeStatus: 'operational',
  mlEngineStatus: 'active',
  uptimePct: 99.97,
  sensors: [
    { name: 'Zeek Network Protocol Analyzer', id: 'ZEEK-DIODE-01', status: 'ok', lastEventSec: 1, rate: '24,800 events/s' },
    { name: 'Suricata Signature & Rule Engine', id: 'SURICATA-DIODE-01', status: 'ok', lastEventSec: 2, rate: '21,480 events/s' },
    { name: 'Data Diode Fiber Ingress', id: 'OPTIC-DIODE-RX', status: 'ok', lastEventSec: 0, rate: '9.42 Gbps Line Rate' }
  ],
  detectors: [
    { name: 'Volumetric DDoS Detector', type: 'Entropy & Burst ML', status: 'active', modelVersion: 'v2.4.1 (Signed)', updated: '2026-09-24 18:30' },
    { name: 'Botnet C2 Beaconing Detector', type: 'FFT Periodicity / Jitter', status: 'active', modelVersion: 'v3.1.0 (Signed)', updated: '2026-09-25 04:12' },
    { name: 'DGA & DNS Tunneling Detector', type: 'Character N-Gram BiLSTM', status: 'active', modelVersion: 'v4.0.2 (Signed)', updated: '2026-09-26 12:00' },
    { name: 'Encrypted TLS/QUIC Malware', type: 'JA3/JA3S Fingerprint Tree', status: 'active', modelVersion: 'v1.9.8 (Signed)', updated: '2026-09-26 18:45' },
    { name: 'Reconnaissance & Scan Detector', type: 'Fan-Out Graph Matrix', status: 'active', modelVersion: 'v2.2.0 (Signed)', updated: '2026-09-27 09:20' },
    { name: 'Data Exfiltration Detector', type: 'Flow Ratio Asymmetry', status: 'active', modelVersion: 'v3.5.0 (Signed)', updated: '2026-09-27 22:15' }
  ]
};

function synthesizeInvestigation(alert) {
  return {
    id: alert.id,
    timestamp: alert.timestamp,
    flow_id: alert.flow_id,
    threat_class: alert.threat_class,
    severity: alert.severity,
    confidence: alert.confidence,
    calibration: 'Higher than ' + Math.round(alert.confidence * 100) + '% of confirmed events',
    summary: alert.summary,
    src_ip: alert.src_ip,
    src_port: alert.src_port,
    dst_ip: alert.dst_ip,
    dst_port: alert.dst_port,
    proto: alert.proto,
    state: alert.state || 'active',
    analyst_label: alert.analyst_label || null,
    analyst_note: alert.analyst_note || '',
    evidence_features: [
      { label: 'Observed Protocol', value: alert.proto, highlight: false },
      { label: 'Source Socket', value: alert.src_ip + ':' + alert.src_port, highlight: true },
      { label: 'Destination Socket', value: alert.dst_ip + ':' + alert.dst_port, highlight: true },
      { label: 'Threat Classification', value: alert.threat_class, highlight: true },
      { label: 'Model Confidence', value: Math.round(alert.confidence * 100) + '%', highlight: true }
    ],
    why_not: [
      { threat: 'Normal Administrative Traffic', reason: 'Traffic patterns and flow entropy deviate significantly from baseline enterprise profiles.' },
      { threat: 'Benign Scheduled Task', reason: 'Timing, burst intervals, or volume asymmetry triggered high anomaly scoring.' }
    ],
    related_alerts: [],
    has_blast_radius: false
  };
}

module.exports = {
  getAlerts: () => alerts,

  getAlertById: (id) => {
    const alert = alerts.find(a => a.id === id);
    if (!alert) {
      if (invDb[id]) return invDb[id];
      return null;
    }
    const inv = invDb[id] ? JSON.parse(JSON.stringify(invDb[id])) : synthesizeInvestigation(alert);
    inv.state = alert.state;
    inv.analyst_label = alert.analyst_label;
    inv.analyst_note = alert.analyst_note || '';
    return inv;
  },

  addAlert: (alert) => {
    alerts.unshift(alert);
    if (alerts.length > 250) {
      alerts.pop();
    }
    if (!invDb[alert.id]) {
      invDb[alert.id] = synthesizeInvestigation(alert);
    }
    return alert;
  },

  updateAlert: (id, patch) => {
    const idx = alerts.findIndex(a => a.id === id);
    if (idx !== -1) {
      alerts[idx] = { ...alerts[idx], ...patch };
      if (invDb[id]) {
        invDb[id] = { ...invDb[id], ...patch };
      }
      return alerts[idx];
    }
    if (invDb[id]) {
      invDb[id] = { ...invDb[id], ...patch };
      return invDb[id];
    }
    return null;
  },

  getNextAlertId: () => 'ALT-2026-' + (nextAlertCounter++),

  getHealthMetrics: () => healthMetrics,

  updateHealthMetrics: (patch) => {
    healthMetrics = { ...healthMetrics, ...patch };
    return healthMetrics;
  },

  getAlertPool: () => NEW_ALERT_POOL
};
