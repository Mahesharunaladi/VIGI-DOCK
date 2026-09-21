const { v4: uuidv4 } = require('uuid');
const { ScanRepository } = require('../models/scan.model');
const { addScanJob, processScanJob } = require('../queues/scan.queue');

const ScanController = {
  /**
   * POST /api/scans/image
   * Trigger an asynchronous scan of a Docker container image tag.
   */
  async triggerImageScan(req, res, next) {
    try {
      const { image, sync = false } = req.body;
      if (!image || typeof image !== 'string') {
        return res.status(400).json({
          success: false,
          error: { message: 'A valid "image" name (e.g. "nginx:alpine", "node:18") is required.' },
        });
      }

      const scanId = uuidv4();
      const initialRecord = await ScanRepository.create({
        scanId,
        target: image.trim(),
        targetType: 'docker-image',
        status: 'QUEUED',
      });

      if (sync === true || sync === 'true') {
        const completed = await processScanJob({
          scanId,
          target: image.trim(),
          targetType: 'docker-image',
        });
        return res.status(200).json({
          success: true,
          message: 'Scan executed synchronously.',
          data: completed,
        });
      }

      // Add to async queue
      await addScanJob({
        scanId,
        target: image.trim(),
        targetType: 'docker-image',
      });

      res.status(202).json({
        success: true,
        message: 'Container image scan queued successfully.',
        data: {
          scanId,
          target: image.trim(),
          status: 'QUEUED',
          pollUrl: `/api/scans/${scanId}`,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/scans/file
   * Upload and scan a Kubernetes YAML manifest or Dockerfile.
   */
  async triggerFileScan(req, res, next) {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: { message: 'File is required (.yaml, .yml, or Dockerfile).' },
        });
      }

      const targetType = req.body.targetType || (req.file.originalname.toLowerCase().includes('dockerfile') ? 'dockerfile' : 'kubernetes-yaml');
      const scanId = uuidv4();

      await ScanRepository.create({
        scanId,
        target: req.file.originalname,
        targetType,
        status: 'QUEUED',
      });

      const sync = req.body.sync === 'true' || req.body.sync === true;

      if (sync) {
        const completed = await processScanJob({
          scanId,
          target: req.file.originalname,
          targetType,
          filePath: req.file.path,
        });
        return res.status(200).json({
          success: true,
          message: 'Manifest scan executed synchronously.',
          data: completed,
        });
      }

      await addScanJob({
        scanId,
        target: req.file.originalname,
        targetType,
        filePath: req.file.path,
      });

      res.status(202).json({
        success: true,
        message: 'File scan queued successfully.',
        data: {
          scanId,
          target: req.file.originalname,
          targetType,
          status: 'QUEUED',
          pollUrl: `/api/scans/${scanId}`,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/scans/:id
   * Retrieve scan status, score, vulnerabilities, and AI insights.
   */
  async getScanById(req, res, next) {
    try {
      const { id } = req.params;
      const scan = await ScanRepository.findById(id);

      if (!scan) {
        return res.status(404).json({
          success: false,
          error: { message: `Scan with ID "${id}" was not found.` },
        });
      }

      res.status(200).json({
        success: true,
        data: scan,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/scans
   * List past scans with pagination.
   */
  async listScans(req, res, next) {
    try {
      const limit = parseInt(req.query.limit || '20', 10);
      const offset = parseInt(req.query.offset || '0', 10);

      const scans = await ScanRepository.list(limit, offset);

      res.status(200).json({
        success: true,
        data: scans,
        pagination: {
          limit,
          offset,
          count: scans.length,
        },
      });
    } catch (err) {
      next(err);
    }
  },
};

module.exports = ScanController;
