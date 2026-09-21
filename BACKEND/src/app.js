require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

const { connectDB } = require('./config/db');
const { initQueue } = require('./queues/scan.queue');
const errorHandler = require('./middlewares/errorHandler');

const scanRoutes = require('./routes/scan.routes');
const aiRoutes = require('./routes/ai.routes');
const reportRoutes = require('./routes/report.routes');

const app = express();
const PORT = process.env.PORT || 5000;

// Create uploads & reports directories if they do not exist
const uploadsDir = path.resolve(process.env.UPLOAD_DIR || './uploads');
const reportsDir = path.resolve(process.env.REPORTS_DIR || './reports');
[uploadsDir, reportsDir].forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Middlewares
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Static directories
app.use('/reports', express.static(reportsDir));

// System Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'online',
    service: 'VigiDock AI Backend',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    config: {
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
      geminiModel: process.env.GEMINI_MODEL || 'gemini-1.5-flash',
      trivyMockFallback: process.env.ENABLE_MOCK_FALLBACK !== 'false',
    },
  });
});

app.get('/', (req, res) => {
  res.status(200).json({
    message: 'Welcome to VigiDock AI Backend API',
    endpoints: {
      health: '/api/health',
      scans: '/api/scans',
      ai: '/api/ai',
      reports: '/api/reports',
    },
    documentation: 'See README.md for complete API specifications.',
  });
});

// API Routes Mount
app.use('/api/scans', scanRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/reports', reportRoutes);

// 404 Handler
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    error: { message: `Route ${req.method} ${req.originalUrl} not found.` },
  });
});

// Centralized Error Handler
app.use(errorHandler);

// Start Server
const startServer = async () => {
  try {
    await connectDB();
    initQueue();

    const server = app.listen(PORT, () => {
      console.log(`===============================================`);
      console.log(`🚀 VigiDock AI Backend is running on port ${PORT}`);
      console.log(`🌐 Base URL: http://localhost:${PORT}`);
      console.log(`🩺 Health check: http://localhost:${PORT}/api/health`);
      console.log(`===============================================`);
    });

    // Graceful Shutdown
    const shutdown = () => {
      console.log('\n[VigiDock AI] Shutting down gracefully...');
      server.close(() => {
        console.log('[VigiDock AI] HTTP server closed.');
        process.exit(0);
      });
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    return server;
  } catch (err) {
    console.error('[VigiDock AI] Server bootstrap failed:', err);
    process.exit(1);
  }
};

if (require.main === module) {
  startServer();
}

module.exports = app;
