require('dotenv').config();

const env = {
  PORT: parseInt(process.env.PORT || '5000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  DATABASE_URL: process.env.DATABASE_URL || process.env.MONGODB_URI || 'mongodb://localhost:27017/vigidock',
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || '',
  GEMINI_MODEL: process.env.GEMINI_MODEL || 'gemini-1.5-flash',
  REDIS_HOST: process.env.REDIS_HOST || '127.0.0.1',
  REDIS_PORT: parseInt(process.env.REDIS_PORT || '6379', 10),
  REDIS_PASSWORD: process.env.REDIS_PASSWORD || undefined,
  TRIVY_BINARY_PATH: process.env.TRIVY_BINARY_PATH || 'trivy',
  ENABLE_MOCK_FALLBACK: process.env.ENABLE_MOCK_FALLBACK !== 'false',
  UPLOAD_DIR: process.env.UPLOAD_DIR || './uploads',
  REPORTS_DIR: process.env.REPORTS_DIR || './reports',
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
};

module.exports = env;
