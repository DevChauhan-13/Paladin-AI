const express = require('express');
const router = express.Router();
const store = require('../store');

// GET /api/alerts - List all alerts with optional query filters
router.get('/', (req, res) => {
  const { search, threatClass, severity, state } = req.query;
  let list = store.getAlerts();

  if (search) {
    const q = search.toLowerCase();
    list = list.filter(a =>
      (a.id && a.id.toLowerCase().includes(q)) ||
      (a.summary && a.summary.toLowerCase().includes(q)) ||
      (a.src_ip && a.src_ip.toLowerCase().includes(q)) ||
      (a.dst_ip && a.dst_ip.toLowerCase().includes(q)) ||
      (a.threat_class && a.threat_class.toLowerCase().includes(q))
    );
  }

  if (threatClass && threatClass !== 'all') {
    list = list.filter(a => a.threat_class === threatClass);
  }

  if (severity && severity !== 'all') {
    list = list.filter(a => a.severity === severity);
  }

  if (state && state !== 'all') {
    list = list.filter(a => a.state === state);
  }

  res.json({ alerts: list, total: list.length });
});

// GET /api/alerts/:id - Detailed alert investigation payload
router.get('/:id', (req, res) => {
  const alert = store.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found', alertId: req.params.id });
  }
  res.json({ alert });
});

// PATCH /api/alerts/:id/confirm - Confirm threat
router.patch('/:id/confirm', (req, res) => {
  const { note } = req.body || {};
  const patch = {
    state: 'confirmed',
    analyst_label: 'confirmed'
  };
  if (typeof note === 'string') {
    patch.analyst_note = note;
  }
  const updated = store.updateAlert(req.params.id, patch);
  if (!updated) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  if (req.app.locals.broadcast) {
    req.app.locals.broadcast({ type: 'ALERT_UPDATED', payload: updated });
  }
  res.json({ success: true, alert: updated });
});

// PATCH /api/alerts/:id/fp - Mark false positive
router.patch('/:id/fp', (req, res) => {
  const { note } = req.body || {};
  const patch = {
    state: 'false_positive',
    analyst_label: 'false_positive'
  };
  if (typeof note === 'string') {
    patch.analyst_note = note;
  }
  const updated = store.updateAlert(req.params.id, patch);
  if (!updated) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  if (req.app.locals.broadcast) {
    req.app.locals.broadcast({ type: 'ALERT_UPDATED', payload: updated });
  }
  res.json({ success: true, alert: updated });
});

// PATCH /api/alerts/:id/note - Save analyst note
router.patch('/:id/note', (req, res) => {
  const { note } = req.body || {};
  const updated = store.updateAlert(req.params.id, { analyst_note: note || '' });
  if (!updated) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  if (req.app.locals.broadcast) {
    req.app.locals.broadcast({ type: 'ALERT_UPDATED', payload: updated });
  }
  res.json({ success: true, alert: updated });
});

module.exports = router;
