const { GoogleGenerativeAI } = require('@google/generative-ai');

let geminiClient = null;
let generativeModel = null;

const getGeminiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.warn('[AI Config] Warning: GEMINI_API_KEY is not configured in .env. Mock responses will be used as fallback.');
    return null;
  }

  if (!geminiClient) {
    geminiClient = new GoogleGenerativeAI(apiKey);
    const modelName = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
    generativeModel = geminiClient.getGenerativeModel({ model: modelName });
    console.log(`[AI Config] Google Gemini initialized with model: ${modelName}`);
  }

  return generativeModel;
};

module.exports = {
  getGeminiClient,
};
