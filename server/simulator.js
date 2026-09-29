const store = require('./store');

let isPaused = false;

function buildSyntheticAlert() {
  const pool = store.getAlertPool();
  const template = pool[Math.floor(Math.random() * pool.length)] || {
    threat_class: 'Reconnaissance/Port Scanning',
    severity: 'medium',
    confidence: 0.86,
    summary: 'Stealth SYN sweep across perimeter gateway',
    src_ip: '10.0.4.119',
    src_port: 52100,
    dst_ip: '10.0.4.1/24',
    dst_port: 'Multi (1-1024)',
    proto: 'TCP/SYN',
    correlation_count: 3,
    correlation_window: '10 min'
  };

  const id = store.getNextAlertId();
  const protoMain = (template.proto || 'TCP').split('/')[0];
  const flowId = 'FLW-' + Math.floor(88320 + Math.random() * 1000) + '-' + protoMain;

  const newAlert = {
    id: id,
    timestamp: new Date().toISOString(),
    flow_id: flowId,
    threat_class: template.threat_class,
    severity: template.severity,
    confidence: template.confidence,
    calibration: 'Higher than ' + Math.round(template.confidence * 100) + '% of confirmed baseline events',
    summary: template.summary,
    src_ip: template.src_ip,
    src_port: template.src_port,
    dst_ip: template.dst_ip,
    dst_port: template.dst_port,
    proto: template.proto,
    state: 'active',
    analyst_label: null,
    analyst_note: '',
    correlation_count: template.correlation_count || 3,
    correlation_window: template.correlation_window || '10 min',
    is_new: true,
    evidence: {
      bytes_out: Math.floor(1000000 + Math.random() * 50000000),
      bytes_in: Math.floor(10000 + Math.random() * 500000),
      entropy: +(5.5 + Math.random() * 2.4).toFixed(2)
    }
  };

  return newAlert;
}

function startSimulator(broadcast) {
  // Push live alert every 14 seconds
  setInterval(() => {
    if (isPaused) return;

    const alert = buildSyntheticAlert();
    store.addAlert(alert);

    if (typeof broadcast === 'function') {
      broadcast({
        type: 'NEW_ALERT',
        payload: alert
      });
    }
  }, 14000);

  // Health jitter & sensor update every 4.5 seconds
  setInterval(() => {
    const current = store.getHealthMetrics();
    const lDelta = (Math.random() - 0.48) * 1.5;
    const newLatency = Math.max(38.2, Math.min(48.5, current.pipelineLatencyMs + lDelta));

    const tDelta = Math.floor((Math.random() - 0.49) * 80);
    const newThroughput = Math.max(9100, Math.min(9650, current.throughputMbps + tDelta));

    const updatedSensors = current.sensors.map(s => ({
      ...s,
      lastEventSec: Math.floor(Math.random() * 3)
    }));

    const updated = store.updateHealthMetrics({
      pipelineLatencyMs: parseFloat(newLatency.toFixed(1)),
      throughputMbps: newThroughput,
      sensors: updatedSensors
    });

    if (typeof broadcast === 'function') {
      broadcast({
        type: 'HEALTH_UPDATE',
        payload: updated
      });
    }
  }, 4500);
}

function setPaused(paused) {
  isPaused = Boolean(paused);
}

function getPaused() {
  return isPaused;
}

module.exports = {
  startSimulator,
  setPaused,
  getPaused,
  buildSyntheticAlert
};
