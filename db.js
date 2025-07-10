const { Pool } = require('pg');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Database connection
let pool;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    // Improved serverless-friendly settings for Neon
    max: 1, // Limit connections for serverless
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 30000, // Increased timeout for Neon
    acquireTimeoutMillis: 30000, // Time to wait for connection from pool
    // Neon-specific optimizations
    keepAlive: true,
    keepAliveInitialDelayMillis: 10000,
  });
} else {
  console.error('❌ DATABASE_URL environment variable is not set');
  // Create a mock pool that will throw errors
  pool = {
    query: () => Promise.reject(new Error('Database not configured - DATABASE_URL missing')),
    connect: () => Promise.reject(new Error('Database not configured - DATABASE_URL missing'))
  };
}

// Test database connection (non-blocking for serverless)
if (process.env.DATABASE_URL && pool.connect) {
  pool.connect((err, client, release) => {
    if (err) {
      console.error('❌ Warning: Database connection failed:', err.message);
      console.error('❌ Error details:', err);
      // Don't crash the serverless function - just log the error
    } else {
      console.log('✅ Connected to NeonDB successfully');
      release();
    }
  });
} else {
  console.warn('⚠️  Warning: DATABASE_URL not configured - database features will not work');
}

module.exports = pool; 