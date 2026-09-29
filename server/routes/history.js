const express = require('express');
const router = express.Router();
const store = require('../store');

const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1 };

router.get('/', (req, res) => {
  const {
    search = '',
    threatClass = 'all',
    severity = 'all',
    label = 'all',
    dateRange = 'all',
    page = 1,
    limit = 10,
    sortField = 'timestamp',
    sortDir = 'desc'
  } = req.query;

  let allAlerts = store.getAlerts();

  const filtered = allAlerts.filter(alert => {
    if (search) {
      const q = search.toLowerCase();
      const match =
        (alert.id && alert.id.toLowerCase().includes(q)) ||
        (alert.src_ip && alert.src_ip.toLowerCase().includes(q)) ||
        (alert.dst_ip && alert.dst_ip.toLowerCase().includes(q)) ||
        (alert.summary && alert.summary.toLowerCase().includes(q)) ||
        (alert.threat_class && alert.threat_class.toLowerCase().includes(q));
      if (!match) return false;
    }

    if (threatClass !== 'all' && alert.threat_class !== threatClass) return false;
    if (severity !== 'all' && alert.severity !== severity) return false;

    if (label !== 'all') {
      if (label === 'unlabeled' && alert.analyst_label) return false;
      if (label !== 'unlabeled' && alert.analyst_label !== label) return false;
    }

    if (dateRange !== 'all') {
      const diffHours = (Date.now() - new Date(alert.timestamp).getTime()) / (1000 * 60 * 60);
      if (dateRange === '1h' && diffHours > 1) return false;
      if (dateRange === '24h' && diffHours > 24) return false;
      if (dateRange === '7d' && diffHours > 24 * 7) return false;
      if (dateRange === '30d' && diffHours > 24 * 30) return false;
    }

    return true;
  });

  filtered.sort((a, b) => {
    let valA = a[sortField];
    let valB = b[sortField];

    if (sortField === 'timestamp') {
      valA = new Date(valA || 0).getTime();
      valB = new Date(valB || 0).getTime();
    } else if (sortField === 'severity') {
      valA = SEV_WEIGHT[valA] || 0;
      valB = SEV_WEIGHT[valB] || 0;
    }

    if (valA < valB) return sortDir === 'asc' ? -1 : 1;
    if (valA > valB) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  const p = Math.max(1, parseInt(page, 10) || 1);
  const l = Math.max(1, parseInt(limit, 10) || 10);
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / l));
  const startIndex = (p - 1) * l;
  const pageData = filtered.slice(startIndex, startIndex + l);

  res.json({
    records: pageData,
    total,
    page: p,
    limit: l,
    totalPages
  });
});

router.get('/export', (req, res) => {
  const alerts = store.getAlerts();
  const headers = [
    'Timestamp',
    'Alert ID',
    'Threat Classification',
    'Severity',
    'Confidence',
    'Source Socket',
    'Destination Socket',
    'Protocol',
    'Analyst Label',
    'Analyst Note',
    'Summary'
  ];

  const rows = alerts.map(a => [
    JSON.stringify(a.timestamp || ''),
    JSON.stringify(a.id || ''),
    JSON.stringify(a.threat_class || ''),
    JSON.stringify((a.severity || '').toUpperCase()),
    JSON.stringify(Math.round((a.confidence || 0) * 100) + '%'),
    JSON.stringify((a.src_ip || '') + ':' + (a.src_port || '')),
    JSON.stringify((a.dst_ip || '') + ':' + (a.dst_port || '')),
    JSON.stringify(a.proto || ''),
    JSON.stringify((a.analyst_label || 'unlabeled').toUpperCase()),
    JSON.stringify(a.analyst_note || ''),
    JSON.stringify(a.summary || '')
  ]);

  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join(String.fromCharCode(13, 10));

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=paladin_ai_incident_history.csv');
  res.status(200).send(csv);
});

module.exports = router;
