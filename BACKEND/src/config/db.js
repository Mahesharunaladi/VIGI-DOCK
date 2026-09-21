const mongoose = require('mongoose');

let isConnected = false;

const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/vigidock';

  try {
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 2000,
    });
    isConnected = true;
    console.log(`[Database] MongoDB connected successfully to ${mongoUri}`);
  } catch (err) {
    isConnected = false;
    console.warn(`[Database] MongoDB connection failed (${err.message}). Using local in-memory fallback store.`);
  }
};

const isDbConnected = () => isConnected;

module.exports = {
  connectDB,
  isDbConnected,
};
