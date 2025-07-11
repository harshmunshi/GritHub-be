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
    // Serverless-optimized settings
    max: 1, // Single connection for serverless
    min: 0, // No minimum connections
    idleTimeoutMillis: 0, // Disable idle timeout
    connectionTimeoutMillis: 60000, // 60 seconds
    acquireTimeoutMillis: 60000,
    // Disable keep-alive for serverless
    keepAlive: false,
    // Handle connection errors gracefully
    allowExitOnIdle: true
  });

  // Handle pool errors
  pool.on('error', (err) => {
    console.error('❌ Database pool error:', err.message);
    // Don't crash the serverless function
  });

  // Handle connection errors
  pool.on('connect', (client) => {
    console.log('✅ Database client connected');
  });

} else {
  console.error('❌ DATABASE_URL environment variable is not set');
  // Create a mock pool that will throw errors
  pool = {
    query: () => Promise.reject(new Error('Database not configured - DATABASE_URL missing')),
    connect: () => Promise.reject(new Error('Database not configured - DATABASE_URL missing'))
  };
}

// Don't test connection at startup in serverless environment
// This prevents the "Connection terminated unexpectedly" error
if (process.env.NODE_ENV !== 'production') {
  // Only test connection in development
  if (process.env.DATABASE_URL && pool.connect) {
    pool.connect((err, client, release) => {
      if (err) {
        console.error('❌ Warning: Database connection failed:', err.message);
      } else {
        console.log('✅ Connected to NeonDB successfully');
        release();
      }
    });
  }
} else {
  console.log('⚡ Serverless mode: Database connections will be established on-demand');
}

module.exports = pool; 