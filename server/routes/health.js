const express = require('express');
const router = express.Router();
const store = require('../store');

// GET /api/health/metrics - Pipeline health metrics & sensors
router.get('/metrics', (req, res) => {
  res.json({
    status: 'ok',
    metrics: store.getHealthMetrics()
  });
});

// GET /api/health/charts/throughput - Throughput timeline
router.get('/charts/throughput', (req, res) => {
  res.json({
    labels: ['02:00', '02:02', '02:04', '02:06', '02:08', '02:10', '02:12', '02:14'],
    measured: [9120, 9280, 9540, 9380, 9460, 9510, 9420, 9480],
    target: 10000
  });
});

// GET /api/health/charts/fp-trend - False positive 7-day trend
router.get('/charts/fp-trend', (req, res) => {
  res.json({
    labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7 (Today)'],
    totalAlerts: [142, 168, 155, 189, 134, 140, 98],
    falsePositives: [28, 22, 17, 15, 9, 8, 5]
  });
});

// GET /api/health/charts/threat-dist - Threat classification distribution
router.get('/charts/threat-dist', (req, res) => {
  const alerts = store.getAlerts();
  const dist = {};
  alerts.forEach(a => {
    dist[a.threat_class] = (dist[a.threat_class] || 0) + 1;
  });
  res.json({
    labels: Object.keys(dist),
    data: Object.values(dist)
  });
});

module.exports = router;
