const express = require('express');
const router = express.Router();
const ScanController = require('../controllers/scan.controller');
const upload = require('../middlewares/upload');

// POST /api/scans/image - Trigger Docker image scan
router.post('/image', ScanController.triggerImageScan);

// POST /api/scans/file - Upload & scan Kubernetes YAML or Dockerfile
router.post('/file', upload.single('file'), ScanController.triggerFileScan);

// GET /api/scans - List past scans
router.get('/', ScanController.listScans);

// GET /api/scans/:id - Get scan status and results
router.get('/:id', ScanController.getScanById);

module.exports = router;
