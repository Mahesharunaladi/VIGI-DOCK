const { Queue, Worker } = require('bullmq');
const Redis = require('ioredis');
const TrivyService = require('../services/trivy.service');
const AiService = require('../services/ai.service');
const { ScanRepository } = require('../models/scan.model');

const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379', 10);
const REDIS_PASSWORD = process.env.REDIS_PASSWORD || undefined;

let redisConnection = null;
let scanQueue = null;
let scanWorker = null;
let useBullMQ = false;

// Job processor implementation
const processScanJob = async (jobData) => {
  const { scanId, target, targetType, filePath } = jobData;
  console.log(`[ScanQueue] Processing scan: ${scanId} (Target: ${target}, Type: ${targetType})`);

  try {
    await ScanRepository.updateById(scanId, { status: 'SCANNING' });

    let scanResult;
    if (targetType === 'docker-image') {
      scanResult = await TrivyService.scanImage(target);
    } else {
      scanResult = await TrivyService.scanConfigFile(filePath || target, targetType);
    }

    // Automatically invoke AI analysis
    const aiAnalysis = await AiService.analyzeScan({
      target,
      targetType,
      summary: scanResult.summary,
      vulnerabilities: scanResult.vulnerabilities,
      misconfigurations: scanResult.misconfigurations,
    });

    const updated = await ScanRepository.updateById(scanId, {
      status: 'COMPLETED',
      summary: scanResult.summary,
      vulnerabilities: scanResult.vulnerabilities,
      misconfigurations: scanResult.misconfigurations,
      rawOutput: scanResult.rawOutput,
      aiAnalysis,
      completedAt: new Date(),
    });

    console.log(`[ScanQueue] Scan ${scanId} COMPLETED successfully. Score: ${scanResult.summary.securityScore}/100`);
    return updated;
  } catch (err) {
    console.error(`[ScanQueue] Scan ${scanId} FAILED:`, err.message);
    await ScanRepository.updateById(scanId, {
      status: 'FAILED',
      errorMessage: err.message,
      completedAt: new Date(),
    });
    throw err;
  }
};

// In-Memory Async fallback worker for local dev when Redis is absent
const inMemoryQueue = {
  async add(name, data) {
    console.log(`[InMemoryQueue] Queueing scan job ${data.scanId} locally in background.`);
    setImmediate(async () => {
      try {
        await processScanJob(data);
      } catch (err) {
        console.error(`[InMemoryQueue] Job ${data.scanId} failed:`, err.message);
      }
    });
    return { id: data.scanId, data };
  }
};

const initQueue = () => {
  try {
    redisConnection = new Redis({
      host: REDIS_HOST,
      port: REDIS_PORT,
      password: REDIS_PASSWORD,
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
      lazyConnect: true,
    });

    redisConnection.connect().then(() => {
      useBullMQ = true;
      scanQueue = new Queue('scan-queue', { connection: redisConnection });
      scanWorker = new Worker('scan-queue', async (job) => {
        return processScanJob(job.data);
      }, { connection: redisConnection, concurrency: 3 });

      scanWorker.on('completed', (job) => {
        console.log(`[BullMQ Worker] Job ${job.id} completed.`);
      });

      scanWorker.on('failed', (job, err) => {
        console.error(`[BullMQ Worker] Job ${job?.id} failed with error:`, err);
      });

      console.log(`[ScanQueue] Connected to Redis at ${REDIS_HOST}:${REDIS_PORT}. BullMQ queue active.`);
    }).catch((err) => {
      console.warn(`[ScanQueue] Redis connection failed (${err.message}). Using in-process asynchronous queue.`);
      useBullMQ = false;
    });
  } catch (err) {
    console.warn(`[ScanQueue] Redis initialization skipped (${err.message}). Using in-process queue.`);
    useBullMQ = false;
  }
};

const addScanJob = async (jobData) => {
  if (useBullMQ && scanQueue) {
    return scanQueue.add('execute-scan', jobData, {
      attempts: 2,
      backoff: { type: 'exponential', delay: 3000 },
      removeOnComplete: 100,
    });
  }
  return inMemoryQueue.add('execute-scan', jobData);
};

module.exports = {
  initQueue,
  addScanJob,
  processScanJob,
};
