const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { isDbConnected } = require('../config/db');

const vulnerabilitySchema = new mongoose.Schema({
  vulnerabilityId: { type: String, required: true },
  pkgName: { type: String, required: true },
  installedVersion: { type: String },
  fixedVersion: { type: String },
  severity: { type: String, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'], default: 'UNKNOWN' },
  title: { type: String },
  description: { type: String },
  primaryUrl: { type: String },
  remediation: { type: String },
}, { _id: false });

const misconfigurationSchema = new mongoose.Schema({
  id: { type: String },
  title: { type: String },
  description: { type: String },
  message: { type: String },
  severity: { type: String, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'], default: 'UNKNOWN' },
  resolution: { type: String },
  status: { type: String },
}, { _id: false });

const scanSchema = new mongoose.Schema({
  scanId: { type: String, default: () => uuidv4(), unique: true, index: true },
  target: { type: String, required: true },
  targetType: { type: String, enum: ['docker-image', 'kubernetes-yaml', 'dockerfile', 'filesystem'], required: true },
  status: { type: String, enum: ['QUEUED', 'SCANNING', 'COMPLETED', 'FAILED'], default: 'QUEUED' },
  summary: {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    totalVulnerabilities: { type: Number, default: 0 },
    totalMisconfigurations: { type: Number, default: 0 },
    securityScore: { type: Number, default: 100 },
  },
  vulnerabilities: [vulnerabilitySchema],
  misconfigurations: [misconfigurationSchema],
  aiAnalysis: {
    summary: { type: String },
    remediationPlan: [{ type: String }],
    securityRecommendations: [{ type: String }],
    patchedConfig: { type: String },
    generatedAt: { type: Date },
  },
  rawOutput: { type: mongoose.Schema.Types.Mixed },
  errorMessage: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date },
});

let ScanModel = null;
try {
  ScanModel = mongoose.model('Scan', scanSchema);
} catch {
  ScanModel = mongoose.model('Scan');
}

// Memory fallback store for when MongoDB is not connected
const memoryStore = new Map();

const ScanRepository = {
  async create(scanData) {
    const record = {
      scanId: scanData.scanId || uuidv4(),
      target: scanData.target,
      targetType: scanData.targetType,
      status: scanData.status || 'QUEUED',
      summary: scanData.summary || {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        totalVulnerabilities: 0,
        totalMisconfigurations: 0,
        securityScore: 100,
      },
      vulnerabilities: scanData.vulnerabilities || [],
      misconfigurations: scanData.misconfigurations || [],
      aiAnalysis: scanData.aiAnalysis || null,
      rawOutput: scanData.rawOutput || null,
      errorMessage: scanData.errorMessage || null,
      createdAt: new Date(),
      completedAt: scanData.completedAt || null,
    };

    if (isDbConnected() && ScanModel) {
      try {
        const doc = await ScanModel.create(record);
        return doc.toObject();
      } catch (err) {
        console.warn(`[ScanRepository] DB insert failed: ${err.message}. Saving to memory store.`);
      }
    }

    memoryStore.set(record.scanId, record);
    return record;
  },

  async findById(scanId) {
    if (isDbConnected() && ScanModel) {
      try {
        const doc = await ScanModel.findOne({ scanId }).lean();
        if (doc) return doc;
      } catch (err) {
        console.warn(`[ScanRepository] DB find failed: ${err.message}. Checking memory store.`);
      }
    }
    return memoryStore.get(scanId) || null;
  },

  async updateById(scanId, updateData) {
    if (isDbConnected() && ScanModel) {
      try {
        const doc = await ScanModel.findOneAndUpdate({ scanId }, { $set: updateData }, { new: true }).lean();
        if (doc) return doc;
      } catch (err) {
        console.warn(`[ScanRepository] DB update failed: ${err.message}. Updating memory store.`);
      }
    }

    const existing = memoryStore.get(scanId) || { scanId };
    const updated = { ...existing, ...updateData };
    memoryStore.set(scanId, updated);
    return updated;
  },

  async list(limit = 20, offset = 0) {
    if (isDbConnected() && ScanModel) {
      try {
        const docs = await ScanModel.find()
          .sort({ createdAt: -1 })
          .skip(offset)
          .limit(limit)
          .lean();
        return docs;
      } catch (err) {
        console.warn(`[ScanRepository] DB list failed: ${err.message}. Listing memory store.`);
      }
    }

    const all = Array.from(memoryStore.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return all.slice(offset, offset + limit);
  },
};

module.exports = {
  ScanModel,
  ScanRepository,
};
