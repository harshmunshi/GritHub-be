const { authenticateToken } = require('./auth');

// For now, we'll use email-based admin check
// In production, you'd want a proper role-based system
const ADMIN_EMAILS = [
  'admin@grithub.com',
  // Add more admin emails here
];

// Middleware to check if user is admin
const requireAdmin = async (req, res, next) => {
  try {
    // First authenticate the user
    await new Promise((resolve, reject) => {
      authenticateToken(req, res, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Check if user is admin
    if (!ADMIN_EMAILS.includes(req.user.email)) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Administrative privileges required.'
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({
      error: 'Authentication failed',
      message: 'Please authenticate first.'
    });
  }
};

module.exports = {
  requireAdmin,
  ADMIN_EMAILS
}; 