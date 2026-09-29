/**
 * Paladin AI SOC Health - Pipeline Performance, Sensor Liveness & ML Detector Metrics
 * Real-time updates, sparkline charting, throughput benchmarks, and detector status
 */

(function () {
  'use strict';

  // State & Metrics Data
  const healthData = {
    pipelineLatencyMs: 41.8,
    throughputMbps: 9420,
    targetThroughputMbps: 10000,
    flowsPerSec: 46280,
    totalIngestedEventsToday: "1,842,910,402",
    sensors: [
      { name: "Zeek Network Protocol Analyzer", id: "ZEEK-DIODE-01", status: "ok", lastEventSec: 1, rate: "24,800 events/s" },
      { name: "Suricata Signature & Rule Engine", id: "SURICATA-DIODE-01", status: "ok", lastEventSec: 2, rate: "21,480 events/s" },
      { name: "Data Diode Fiber Ingress", id: "OPTIC-DIODE-RX", status: "ok", lastEventSec: 0, rate: "9.42 Gbps Line Rate" }
    ],
    detectors: [
      { name: "Volumetric DDoS Detector", type: "Entropy & Burst ML", status: "active", modelVersion: "v2.4.1 (Signed)", updated: "2026-09-24 18:30" },
      { name: "Botnet C2 Beaconing Detector", type: "FFT Periodicity / Jitter", status: "active", modelVersion: "v3.1.0 (Signed)", updated: "2026-09-25 04:12" },
      { name: "DGA & DNS Tunneling Detector", type: "Character N-Gram BiLSTM", status: "active", modelVersion: "v4.0.2 (Signed)", updated: "2026-09-26 12:00" },
      { name: "Encrypted TLS/QUIC Malware", type: "JA3/JA3S Fingerprint Tree", status: "active", modelVersion: "v1.9.8 (Signed)", updated: "2026-09-26 18:45" },
      { name: "Reconnaissance & Scan Detector", type: "Fan-Out Graph Matrix", status: "active", modelVersion: "v2.2.0 (Signed)", updated: "2026-09-27 09:20" },
      { name: "Data Exfiltration Detector", type: "Flow Ratio Asymmetry", status: "active", modelVersion: "v3.5.0 (Signed)", updated: "2026-09-27 22:15" }
    ]
  };

  let latencyChartInstance = null;
  let throughputChartInstance = null;
  let fpTrendChartInstance = null;

  // Initialize Latency Rolling Sparkline
  function initLatencyChart() {
    const canvas = document.getElementById('latencySparkline');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const labels = ['-12m', '-10m', '-8m', '-6m', '-4m', '-2m', 'NOW'];
    const dataPoints = [43.2, 42.1, 41.5, 44.8, 42.0, 41.2, 41.8];

    latencyChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'E2E Latency (ms)',
          data: dataPoints,
          borderColor: '#2ecc71',
          backgroundColor: 'rgba(46, 204, 113, 0.12)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 3,
          pointBackgroundColor: '#2ecc71'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            min: 30,
            max: 60,
            grid: { color: 'rgba(255,255,255,0.06)' },
            title: { display: true, text: 'ms' }
          },
          x: {
            grid: { display: false }
          }
        }
      }
    });
  }

  // Initialize Throughput vs Benchmark Target Chart
  function initThroughputChart() {
    const canvas = document.getElementById('throughputChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const labels = ['02:00', '02:02', '02:04', '02:06', '02:08', '02:10', '02:12', '02:14'];

    throughputChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Measured Throughput (Mbps)',
            data: [9120, 9280, 9540, 9380, 9460, 9510, 9420, 9480],
            borderColor: '#e07b20',
            backgroundColor: 'rgba(224, 123, 32, 0.15)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 4,
            pointBackgroundColor: '#e07b20'
          },
          {
            label: 'Benchmark Line-Rate Target (10,000 Mbps)',
            data: [10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000],
            borderColor: '#d50f3b',
            borderWidth: 1.5,
            borderDash: [5, 5],
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
          y: {
            min: 7000,
            max: 11000,
            grid: { color: 'rgba(255,255,255,0.06)' },
            title: { display: true, text: 'Throughput (Mbps)' }
          },
          x: { grid: { color: 'rgba(255,255,255,0.06)' } }
        }
      }
    });
  }

  // Initialize Alert Volume vs False-Positive Trend Chart (PRD 2.5)
  function initFpTrendChart() {
    const canvas = document.getElementById('fpTrendChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const labels = ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7 (Today)'];

    fpTrendChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Total Streaming Alerts Raised',
            data: [142, 168, 155, 189, 134, 140, 98],
            backgroundColor: 'rgba(213, 15, 59, 0.8)',
            borderRadius: 2
          },
          {
            label: 'Marked False Positive by Analysts',
            data: [28, 22, 17, 15, 9, 8, 5],
            backgroundColor: 'rgba(139, 148, 158, 0.65)',
            borderRadius: 2
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
          y: {
            grid: { color: 'rgba(255,255,255,0.06)' },
            title: { display: true, text: 'Alerts Count' }
          },
          x: { grid: { color: 'rgba(255,255,255,0.06)' } }
        }
      }
    });
  }

  // Render Sensor Liveness Rows
  function renderSensors() {
    const container = document.getElementById('sensorsContainer');
    if (!container) return;

    container.innerHTML = healthData.sensors.map(s => `
      <div class="soc-sensor-row">
        <div class="soc-sensor-info">
          <div class="soc-sensor-dot"></div>
          <div>
            <div class="soc-sensor-name">${s.name}</div>
            <div class="soc-sensor-detail">${s.id} // ${s.rate}</div>
          </div>
        </div>
        <div class="soc-sensor-time">
          <span>Active</span>
          <div style="font-size: 10px; color: var(--soc-text-dim);">Last: ${s.lastEventSec}s ago</div>
        </div>
      </div>
    `).join('');
  }

  // Render Detector Status Table
  function renderDetectors() {
    const container = document.getElementById('detectorsTableBody');
    if (!container) return;

    container.innerHTML = healthData.detectors.map(d => `
      <tr>
        <td style="font-weight: 600; color: #ffffff;">${d.name}</td>
        <td class="mono" style="color: var(--soc-text-subtle);">${d.type}</td>
        <td>
          <span class="soc-threat-badge ok" style="font-size: 9px; padding: 2px 6px;">ONLINE</span>
        </td>
        <td class="mono" style="color: var(--soc-high);">${d.modelVersion}</td>
        <td class="mono" style="color: var(--soc-text-dim);">${d.updated}</td>
      </tr>
    `).join('');
  }

  // Live Timer Simulation: Update countdowns and latency values every 5s
  function startLiveSimulation() {
    setInterval(() => {
      // Small jitter on latency
      const delta = (Math.random() - 0.48) * 1.5;
      healthData.pipelineLatencyMs = Math.max(38.2, Math.min(48.5, healthData.pipelineLatencyMs + delta));

      const latencyValEl = document.getElementById('metricLatencyVal');
      if (latencyValEl) {
        latencyValEl.textContent = `${healthData.pipelineLatencyMs.toFixed(1)} ms`;
      }

      // Small jitter on throughput
      const tDelta = Math.floor((Math.random() - 0.49) * 80);
      healthData.throughputMbps = Math.max(9100, Math.min(9650, healthData.throughputMbps + tDelta));

      const tValEl = document.getElementById('metricThroughputVal');
      if (tValEl) {
        tValEl.textContent = `${(healthData.throughputMbps / 1000).toFixed(2)} Gbps`;
      }

      // Sensors last event
      healthData.sensors.forEach(s => {
        s.lastEventSec = Math.floor(Math.random() * 3);
      });
      renderSensors();

      // Add point to latency chart
      if (latencyChartInstance) {
        const d = latencyChartInstance.data.datasets[0].data;
        d.shift();
        d.push(parseFloat(healthData.pipelineLatencyMs.toFixed(1)));
        latencyChartInstance.update();
      }
    }, 4500);
  }

  // Connect to Backend WebSocket Health & Telemetry Stream
  function connectHealthWebSocket() {
    const isHttps = window.location.protocol === 'https:';
    const host = window.location.host || 'localhost:3001';
    const wsUrl = (isHttps ? 'wss://' : 'ws://') + host;

    let socket;
    try {
      socket = new WebSocket(wsUrl);
    } catch(e) {
      return;
    }

    socket.onmessage = function(event) {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'HEALTH_UPDATE' && msg.payload) {
          const payload = msg.payload;
          if (payload.pipelineLatencyMs) {
            healthData.pipelineLatencyMs = payload.pipelineLatencyMs;
            const latencyValEl = document.getElementById('metricLatencyVal');
            if (latencyValEl) latencyValEl.textContent = payload.pipelineLatencyMs.toFixed(1) + ' ms';
            if (latencyChartInstance) {
              const d = latencyChartInstance.data.datasets[0].data;
              d.shift();
              d.push(payload.pipelineLatencyMs);
              latencyChartInstance.update();
            }
          }
          if (payload.throughputMbps) {
            healthData.throughputMbps = payload.throughputMbps;
            const tValEl = document.getElementById('metricThroughputVal');
            if (tValEl) tValEl.textContent = (payload.throughputMbps / 1000).toFixed(2) + ' Gbps';
          }
          if (Array.isArray(payload.sensors)) {
            healthData.sensors = payload.sensors;
            renderSensors();
          }
        }
      } catch(e) {}
    };

    socket.onclose = function() {
      setTimeout(connectHealthWebSocket, 4000);
    };
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', async () => {
    initLatencyChart();
    initThroughputChart();
    initFpTrendChart();
    renderSensors();
    renderDetectors();
    startLiveSimulation();
    connectHealthWebSocket();

    // Fetch initial metrics from server
    try {
      const apiBase = window.location.origin.startsWith('http') ? '' : 'http://localhost:3001';
      const res = await fetch(apiBase + '/api/health/metrics');
      if (res.ok) {
        const data = await res.json();
        if (data.metrics) {
          if (data.metrics.pipelineLatencyMs) healthData.pipelineLatencyMs = data.metrics.pipelineLatencyMs;
          if (data.metrics.throughputMbps) healthData.throughputMbps = data.metrics.throughputMbps;
          if (Array.isArray(data.metrics.sensors)) healthData.sensors = data.metrics.sensors;
          renderSensors();
        }
      }
    } catch(e) {}
  });

})();
