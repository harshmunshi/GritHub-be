const pool = require('../db');

// Log user activity
const logActivity = async (userId, action, description, req, success = true, metadata = null) => {
  try {
    const ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.get('User-Agent');
    const sessionToken = req.headers['authorization']?.split(' ')[1];

    await pool.query(
      `INSERT INTO user_activity_logs 
       (user_id, action, description, ip_address, user_agent, request_path, session_token, success, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [userId, action, description, ip, userAgent, req.path, sessionToken, success, metadata]
    );
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
};

// Middleware to automatically log certain activities
const activityLogger = (action, description) => {
  return async (req, res, next) => {
    // Store original end function
    const originalEnd = res.end;
    
    res.end = function(...args) {
      // Log the activity after response
      if (req.user && req.user.id) {
        const success = res.statusCode < 400;
        setImmediate(() => {
          logActivity(req.user.id, action, description, req, success);
        });
      }
      
      // Call original end function
      originalEnd.apply(this, args);
    };
    
    next();
  };
};

// Check for suspicious activity
const checkSuspiciousActivity = async (userId, action, ip) => {
  try {
    const now = new Date();
    const oneHour = new Date(now.getTime() - 60 * 60 * 1000);
    
    // Check for too many failed attempts
    if (action === 'login_failed') {
      const failedAttempts = await pool.query(
        `SELECT COUNT(*) as count 
         FROM user_activity_logs 
         WHERE action = 'login_failed' 
         AND ip_address = $1 
         AND created_at > $2`,
        [ip, oneHour]
      );
      
      if (parseInt(failedAttempts.rows[0].count) >= 5) {
        return { suspicious: true, reason: 'Too many failed login attempts' };
      }
    }
    
    // Check for rapid session creation
    if (action === 'login_success') {
      const recentLogins = await pool.query(
        `SELECT COUNT(*) as count 
         FROM user_activity_logs 
         WHERE user_id = $1 
         AND action = 'login_success' 
         AND created_at > $2`,
        [userId, oneHour]
      );
      
      if (parseInt(recentLogins.rows[0].count) >= 10) {
        return { suspicious: true, reason: 'Too many login attempts in short time' };
      }
    }
    
    // Check for unusual IP activity
    if (userId) {
      const ipCount = await pool.query(
        `SELECT COUNT(DISTINCT ip_address) as count 
         FROM user_activity_logs 
         WHERE user_id = $1 
         AND created_at > $2`,
        [userId, oneHour]
      );
      
      if (parseInt(ipCount.rows[0].count) >= 5) {
        return { suspicious: true, reason: 'Multiple IP addresses in short time' };
      }
    }
    
    return { suspicious: false };
  } catch (error) {
    console.error('Error checking suspicious activity:', error);
    return { suspicious: false };
  }
};

// Security alert for suspicious activity
const alertSuspiciousActivity = async (userId, reason, req) => {
  try {
    await logActivity(
      userId, 
      'security_alert', 
      `Suspicious activity detected: ${reason}`, 
      req, 
      true, 
      { alertReason: reason, timestamp: new Date() }
    );
    
    // In production, you might want to:
    // - Send email alerts
    // - Temporarily lock account
    // - Notify security team
    console.warn(`🚨 Security Alert - User ${userId}: ${reason}`);
  } catch (error) {
    console.error('Failed to alert suspicious activity:', error);
  }
};

// Get user's recent activity
const getUserActivity = async (userId, limit = 50) => {
  try {
    const result = await pool.query(
      `SELECT 
         action,
         description,
         ip_address,
         request_path,
         success,
         created_at
       FROM user_activity_logs 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2`,
      [userId, limit]
    );
    
    return result.rows;
  } catch (error) {
    console.error('Failed to get user activity:', error);
    return [];
  }
};

// Get security statistics
const getSecurityStats = async (userId) => {
  try {
    const stats = await pool.query(
      `SELECT 
         COUNT(*) as total_activities,
         COUNT(CASE WHEN success = false THEN 1 END) as failed_activities,
         COUNT(CASE WHEN action = 'login_success' THEN 1 END) as logins,
         COUNT(CASE WHEN action = 'password_changed' THEN 1 END) as password_changes,
         COUNT(DISTINCT ip_address) as unique_ips,
         MIN(created_at) as first_activity,
         MAX(created_at) as last_activity
       FROM user_activity_logs 
       WHERE user_id = $1 
       AND created_at > NOW() - INTERVAL '30 days'`,
      [userId]
    );
    
    return stats.rows[0];
  } catch (error) {
    console.error('Failed to get security stats:', error);
    return null;
  }
};

module.exports = {
  logActivity,
  activityLogger,
  checkSuspiciousActivity,
  alertSuspiciousActivity,
  getUserActivity,
  getSecurityStats
}; 