const jwt = require('jsonwebtoken');
const pool = require('../db');

// JWT secret (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Access denied',
      message: 'No authentication token provided.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if session exists and is valid
    const sessionQuery = `
      SELECT s.*, u.name, u.email 
      FROM user_sessions s 
      JOIN users u ON s.user_id = u.id 
      WHERE s.session_token = $1 AND s.expires_at > NOW()
    `;
    
    const sessionResult = await pool.query(sessionQuery, [token]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(401).json({
        error: 'Invalid session',
        message: 'Session has expired or is invalid.'
      });
    }

    // Update last accessed time
    await pool.query(
      'UPDATE user_sessions SET last_accessed = NOW() WHERE session_token = $1',
      [token]
    );

    req.user = {
      id: decoded.userId,
      email: sessionResult.rows[0].email,
      name: sessionResult.rows[0].name
    };
    
    next();
  } catch (error) {
    return res.status(403).json({
      error: 'Invalid token',
      message: 'Authentication token is invalid or expired.'
    });
  }
};

module.exports = {
  authenticateToken,
  JWT_SECRET
}; 