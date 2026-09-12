import { testGeminiConnection } from '../src/services/geminiService.js';

async function run() {
  console.log('Testing Gemini API Connection...');
  try {
    const response = await testGeminiConnection();
    console.log(`Success! Gemini responded with: "${response}"`);
    if (response.toLowerCase().includes('connected')) {
      console.log('Gemini Integration Test Passed.');
      process.exitCode = 0;
    } else {
      console.log('Unexpected response from Gemini.');
      process.exitCode = 1;
    }
  } catch (error) {
    console.error('Test Failed:', error.message);
    process.exitCode = 1;
  }
}

run();
