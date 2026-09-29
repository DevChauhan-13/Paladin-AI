const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const path = require('path');

const alertsRouter = require('./routes/alerts');
const historyRouter = require('./routes/history');
const healthRouter = require('./routes/health');
const { startSimulator, setPaused, getPaused } = require('./simulator');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());

// Broadcast helper for WebSocket clients
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === 1) { // OPEN
      client.send(msg);
    }
  });
}

// Make broadcast available in Express routes
app.locals.broadcast = broadcast;

// REST API Endpoints
app.use('/api/alerts', alertsRouter);
app.use('/api/history', historyRouter);
app.use('/api/health', healthRouter);

// Simulator pause / resume toggle endpoint
app.post('/api/simulator/toggle', (req, res) => {
  const current = getPaused();
  setPaused(!current);
  res.json({ paused: !current });
});

// Serve frontend static files from project root
app.use(express.static(path.join(__dirname, '..')));

// Fallback to dashboard.html for SPA/root
app.get('/live', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dashboard.html'));
});

// WebSocket Connection Management
wss.on('connection', (ws) => {
  // Connected silently

  // Send initial handshake
  ws.send(JSON.stringify({
    type: 'CONNECTED',
    payload: {
      message: 'Connected to Paladin AI Real-Time SOC Stream',
      timestamp: new Date().toISOString()
    }
  }));

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      if (data.type === 'PING') {
        ws.send(JSON.stringify({ type: 'PONG', timestamp: new Date().toISOString() }));
      } else if (data.type === 'TOGGLE_STREAM') {
        const current = getPaused();
        setPaused(!current);
        broadcast({ type: 'STREAM_STATUS', payload: { isPaused: !current } });
      }
    } catch (e) {
      console.error('[WebSocket] Message parse error: ' + e.message);
    }
  });

  ws.on('close', () => {
    // Disconnected silently
  });
});

// Start background live alert & telemetry simulator
startSimulator(broadcast);

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log();
  console.log('  Shield Paladin AI - SOC Engine Online');
  console.log('  Open your browser at:');
  console.log('  -> http://localhost:' + PORT);
  console.log();
});
