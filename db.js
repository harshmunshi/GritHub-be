const { Pool } = require('pg');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  // Serverless-friendly settings
  max: 1, // Limit connections for serverless
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Test database connection (non-blocking for serverless)
if (process.env.DATABASE_URL) {
  pool.connect((err, client, release) => {
    if (err) {
      console.error('❌ Warning: Database connection failed:', err.message);
      // Don't crash the serverless function - just log the error
    } else {
      console.log('✅ Connected to NeonDB successfully');
      release();
    }
  });
} else {
  console.warn('⚠️  Warning: DATABASE_URL not configured');
}

module.exports = pool; 