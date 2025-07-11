const express = require('express');
const { body, query, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const pool = require('../db');
const { authenticateToken, JWT_SECRET } = require('../middleware/auth');
const { getUserActivity, getSecurityStats, logActivity } = require('../middleware/security');

const router = express.Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     UserPreferences:
 *       type: object
 *       properties:
 *         weekly_goal:
 *           type: integer
 *           minimum: 1
 *           maximum: 7
 *           example: 3
 *         privacy_profile_visible:
 *           type: boolean
 *           example: true
 *         privacy_stats_visible:
 *           type: boolean
 *           example: true
 *         privacy_groups_visible:
 *           type: boolean
 *           example: true
 *         notifications_gym_reminders:
 *           type: boolean
 *           example: true
 *         notifications_streak_alerts:
 *           type: boolean
 *           example: true
 *         notifications_group_updates:
 *           type: boolean
 *           example: true
 *         notifications_leaderboard_updates:
 *           type: boolean
 *           example: true
 *         theme_preference:
 *           type: string
 *           enum: [light, dark, system]
 *           example: system
 *     UserSession:
 *       type: object
 *       properties:
 *         sessionId:
 *           type: string
 *           example: "12345678..."
 *         createdAt:
 *           type: string
 *           format: date-time
 *         lastAccessed:
 *           type: string
 *           format: date-time
 *         expiresAt:
 *           type: string
 *           format: date-time
 *         isCurrent:
 *           type: boolean
 *           example: true
 *     ActivityLog:
 *       type: object
 *       properties:
 *         action:
 *           type: string
 *           example: "login_success"
 *         description:
 *           type: string
 *           example: "User logged in successfully"
 *         ip_address:
 *           type: string
 *           example: "192.168.1.1"
 *         request_path:
 *           type: string
 *           example: "/api/auth/signin"
 *         success:
 *           type: boolean
 *           example: true
 *         created_at:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/users/profile:
 *   get:
 *     summary: Get user profile
 *     description: Retrieve the current user's profile information
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Failed to get profile
 */

/**
 * @swagger
 * /api/users/password:
 *   put:
 *     summary: Change password
 *     description: Change the current user's password
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 example: "oldpassword123"
 *               newPassword:
 *                 type: string
 *                 minLength: 6
 *                 example: "newpassword123"
 *     responses:
 *       200:
 *         description: Password changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password changed successfully"
 *                 note:
 *                   type: string
 *                   example: "All other sessions have been logged out for security."
 *       400:
 *         description: Validation failed or current password incorrect
 *       404:
 *         description: User not found
 *       500:
 *         description: Failed to change password
 */

/**
 * @swagger
 * /api/users/preferences:
 *   get:
 *     summary: Get user preferences
 *     description: Retrieve the current user's preferences and settings
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User preferences retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 preferences:
 *                   $ref: '#/components/schemas/UserPreferences'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Failed to get preferences
 *   put:
 *     summary: Update user preferences
 *     description: Update the current user's preferences and settings
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserPreferences'
 *     responses:
 *       200:
 *         description: Preferences updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Preferences updated successfully"
 *                 preferences:
 *                   $ref: '#/components/schemas/UserPreferences'
 *       400:
 *         description: Validation failed
 *       404:
 *         description: Preferences not found
 *       500:
 *         description: Failed to update preferences
 */

/**
 * @swagger
 * /api/users/sessions:
 *   get:
 *     summary: Get active sessions
 *     description: Retrieve all active sessions for the current user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sessions retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 sessions:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/UserSession'
 *                 totalSessions:
 *                   type: integer
 *                   example: 3
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Failed to get sessions
 */

/**
 * @swagger
 * /api/users/activity:
 *   get:
 *     summary: Get user activity log
 *     description: Retrieve the current user's recent activity log
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 50
 *         description: Number of activities to retrieve
 *     responses:
 *       200:
 *         description: Activity log retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 activities:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/ActivityLog'
 *                 totalActivities:
 *                   type: integer
 *                   example: 25
 *       400:
 *         description: Validation failed
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Failed to get activity
 */

/**
 * @swagger
 * /api/users/security/stats:
 *   get:
 *     summary: Get security statistics
 *     description: Retrieve security statistics for the current user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Security statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 securityStats:
 *                   type: object
 *                   properties:
 *                     totalActivities:
 *                       type: integer
 *                       example: 100
 *                     failedActivities:
 *                       type: integer
 *                       example: 2
 *                     successfulLogins:
 *                       type: integer
 *                       example: 15
 *                     passwordChanges:
 *                       type: integer
 *                       example: 1
 *                     uniqueIpAddresses:
 *                       type: integer
 *                       example: 3
 *                     firstActivity:
 *                       type: string
 *                       format: date-time
 *                     lastActivity:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Failed to get security statistics
 */

// Configure multer for image uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const userQuery = `
      SELECT id, name, email, join_date, current_streak, longest_streak, total_gym_days,
             profile_image, created_at, updated_at
      FROM users 
      WHERE id = $1
    `;
    
    const userResult = await pool.query(userQuery, [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User profile not found.'
      });
    }

    const user = userResult.rows[0];

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        joinDate: user.join_date,
        currentStreak: user.current_streak,
        longestStreak: user.longest_streak,
        totalGymDays: user.total_gym_days,
        profileImage: user.profile_image,
        createdAt: user.created_at,
        updatedAt: user.updated_at
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      error: 'Failed to get profile',
      message: 'An error occurred while retrieving your profile.'
    });
  }
});

// Update user profile
router.put('/profile', [
  authenticateToken,
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({
        error: 'No data provided',
        message: 'No valid fields provided for update.'
      });
    }

    const updateQuery = `
      UPDATE users 
      SET name = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING id, name, email, join_date, current_streak, longest_streak, total_gym_days
    `;

    const result = await pool.query(updateQuery, [name, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account not found.'
      });
    }

    const user = result.rows[0];

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        joinDate: user.join_date,
        currentStreak: user.current_streak,
        longestStreak: user.longest_streak,
        totalGymDays: user.total_gym_days
      }
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      error: 'Failed to update profile',
      message: 'An error occurred while updating your profile.'
    });
  }
});

// Upload/Update profile image
router.post('/profile/image', [
  authenticateToken,
  upload.single('image')
], async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'No image provided',
        message: 'Please provide an image file.'
      });
    }

    const imageBuffer = req.file.buffer;
    const imageType = req.file.mimetype;

    // Update user profile image
    const updateQuery = `
      UPDATE users 
      SET profile_image = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING id, name, email
    `;

    const result = await pool.query(updateQuery, [imageBuffer, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account not found.'
      });
    }

    res.json({
      message: 'Profile image updated successfully',
      imageSize: req.file.size,
      imageType: imageType
    });

  } catch (error) {
    console.error('Upload profile image error:', error);
    
    if (error.message === 'Only image files are allowed') {
      return res.status(400).json({
        error: 'Invalid file type',
        message: 'Only image files are allowed.'
      });
    }
    
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: 'File too large',
        message: 'Image size must be less than 5MB.'
      });
    }

    res.status(500).json({
      error: 'Failed to upload image',
      message: 'An error occurred while uploading your profile image.'
    });
  }
});

// Get profile image
router.get('/profile/image', authenticateToken, async (req, res) => {
  try {
    const imageQuery = 'SELECT profile_image FROM users WHERE id = $1';
    const result = await pool.query(imageQuery, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account not found.'
      });
    }

    const profileImage = result.rows[0].profile_image;

    if (!profileImage) {
      return res.status(404).json({
        error: 'No profile image',
        message: 'No profile image found for this user.'
      });
    }

    // Set appropriate headers for image response
    res.set({
      'Content-Type': 'image/jpeg', // Default to JPEG, in production you'd store the type
      'Content-Length': profileImage.length,
      'Cache-Control': 'public, max-age=3600' // Cache for 1 hour
    });

    res.send(profileImage);

  } catch (error) {
    console.error('Get profile image error:', error);
    res.status(500).json({
      error: 'Failed to get image',
      message: 'An error occurred while retrieving your profile image.'
    });
  }
});

// Get profile image by user ID (for other users to see)
router.get('/:userId/profile/image', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    const imageQuery = 'SELECT profile_image FROM users WHERE id = $1';
    const result = await pool.query(imageQuery, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found.'
      });
    }

    const profileImage = result.rows[0].profile_image;

    if (!profileImage) {
      return res.status(404).json({
        error: 'No profile image',
        message: 'No profile image found for this user.'
      });
    }

    // Set appropriate headers for image response
    res.set({
      'Content-Type': 'image/jpeg',
      'Content-Length': profileImage.length,
      'Cache-Control': 'public, max-age=3600'
    });

    res.send(profileImage);

  } catch (error) {
    console.error('Get user profile image error:', error);
    res.status(500).json({
      error: 'Failed to get image',
      message: 'An error occurred while retrieving the profile image.'
    });
  }
});

// Delete profile image
router.delete('/profile/image', authenticateToken, async (req, res) => {
  try {
    const updateQuery = `
      UPDATE users 
      SET profile_image = NULL, updated_at = NOW()
      WHERE id = $1
      RETURNING id
    `;

    const result = await pool.query(updateQuery, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account not found.'
      });
    }

    res.json({
      message: 'Profile image deleted successfully'
    });

  } catch (error) {
    console.error('Delete profile image error:', error);
    res.status(500).json({
      error: 'Failed to delete image',
      message: 'An error occurred while deleting your profile image.'
    });
  }
});

// Get user statistics
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    // Get basic user stats
    const userQuery = `
      SELECT current_streak, longest_streak, total_gym_days
      FROM users 
      WHERE id = $1
    `;
    
    const userResult = await pool.query(userQuery, [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found.'
      });
    }

    // Get this week's visits
    const weekVisitsQuery = `
      SELECT COUNT(DISTINCT DATE(date)) as week_visits
      FROM gym_visits 
      WHERE user_id = $1 
        AND date >= DATE_TRUNC('week', NOW())
        AND date < DATE_TRUNC('week', NOW()) + INTERVAL '1 week'
    `;

    const weekResult = await pool.query(weekVisitsQuery, [req.user.id]);

    // Get this month's visits
    const monthVisitsQuery = `
      SELECT COUNT(DISTINCT DATE(date)) as month_visits
      FROM gym_visits 
      WHERE user_id = $1 
        AND date >= DATE_TRUNC('month', NOW())
        AND date < DATE_TRUNC('month', NOW()) + INTERVAL '1 month'
    `;

    const monthResult = await pool.query(monthVisitsQuery, [req.user.id]);

    const user = userResult.rows[0];
    const weekVisits = weekResult.rows[0].week_visits || 0;
    const monthVisits = monthResult.rows[0].month_visits || 0;

    res.json({
      statistics: {
        totalGymDays: user.total_gym_days,
        currentStreak: user.current_streak,
        longestStreak: user.longest_streak,
        weeklyGoal: 3, // Default goal
        weeklyProgress: weekVisits,
        thisWeekVisits: weekVisits,
        thisMonthVisits: monthVisits
      }
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      error: 'Failed to get statistics',
      message: 'An error occurred while retrieving your statistics.'
    });
  }
});

// Delete user account
router.delete('/account', authenticateToken, async (req, res) => {
  try {
    // Start transaction
    await pool.query('BEGIN');

    // Delete user sessions
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [req.user.id]);

    // Delete user (cascade will handle related records)
    const deleteResult = await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);

    if (deleteResult.rowCount === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({
        error: 'User not found',
        message: 'User account not found.'
      });
    }

    // Commit transaction
    await pool.query('COMMIT');

    res.json({
      message: 'Account deleted successfully'
    });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Delete account error:', error);
    res.status(500).json({
      error: 'Failed to delete account',
      message: 'An error occurred while deleting your account.'
    });
  }
});

// Change password
router.put('/password', [
  authenticateToken,
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long')
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { currentPassword, newPassword } = req.body;

    // Get current password hash
    const userQuery = 'SELECT password_hash FROM users WHERE id = $1';
    const userResult = await pool.query(userQuery, [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account not found.'
      });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
    if (!isValidPassword) {
      return res.status(400).json({
        error: 'Invalid password',
        message: 'Current password is incorrect.'
      });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    const updateQuery = `
      UPDATE users 
      SET password_hash = $1, updated_at = NOW()
      WHERE id = $2
    `;
    
    await pool.query(updateQuery, [hashedNewPassword, req.user.id]);

    // Invalidate all other sessions except current one
    const currentToken = req.headers['authorization'].split(' ')[1];
    await pool.query(
      'DELETE FROM user_sessions WHERE user_id = $1 AND session_token != $2',
      [req.user.id, currentToken]
    );

    // Log password change activity
    await logActivity(req.user.id, 'password_changed', 'User changed their password', req, true, {
      sessionsInvalidated: true
    });

    res.json({
      message: 'Password changed successfully',
      note: 'All other sessions have been logged out for security.'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      error: 'Failed to change password',
      message: 'An error occurred while changing your password.'
    });
  }
});

// Request password reset
router.post('/password/reset-request', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { email } = req.body;

    // Check if user exists
    const userQuery = 'SELECT id FROM users WHERE email = $1';
    const userResult = await pool.query(userQuery, [email]);

    // Always return success (don't reveal if email exists)
    if (userResult.rows.length === 0) {
      return res.json({
        message: 'If an account with this email exists, a password reset link has been sent.'
      });
    }

    const userId = userResult.rows[0].id;

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour

    // Store reset token
    await pool.query(
      `INSERT INTO password_resets (user_id, token_hash, expires_at) 
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) 
       DO UPDATE SET token_hash = $2, expires_at = $3, created_at = NOW()`,
      [userId, resetTokenHash, expiresAt]
    );

    // In a real app, you would send this via email
    // For now, we'll return it in the response (REMOVE IN PRODUCTION)
    res.json({
      message: 'If an account with this email exists, a password reset link has been sent.',
      // REMOVE THE BELOW IN PRODUCTION - THIS IS FOR TESTING ONLY
      resetToken: resetToken,
      resetUrl: process.env.FRONTEND_URL 
        ? `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`
        : `grithub://reset-password?token=${resetToken}` // Deep link for mobile app
    });

  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      error: 'Failed to process reset request',
      message: 'An error occurred while processing your request.'
    });
  }
});

// Reset password with token
router.post('/password/reset', [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { token, newPassword } = req.body;

    // Hash the provided token
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Find valid reset token
    const resetQuery = `
      SELECT pr.user_id, u.email
      FROM password_resets pr
      JOIN users u ON pr.user_id = u.id
      WHERE pr.token_hash = $1 AND pr.expires_at > NOW()
    `;
    
    const resetResult = await pool.query(resetQuery, [tokenHash]);

    if (resetResult.rows.length === 0) {
      return res.status(400).json({
        error: 'Invalid or expired token',
        message: 'The password reset token is invalid or has expired.'
      });
    }

    const userId = resetResult.rows[0].user_id;

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Start transaction
    await pool.query('BEGIN');

    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [hashedPassword, userId]
    );

    // Delete the reset token
    await pool.query('DELETE FROM password_resets WHERE user_id = $1', [userId]);

    // Invalidate all sessions
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [userId]);

    // Commit transaction
    await pool.query('COMMIT');

    res.json({
      message: 'Password reset successfully',
      note: 'Please sign in with your new password.'
    });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Password reset error:', error);
    res.status(500).json({
      error: 'Failed to reset password',
      message: 'An error occurred while resetting your password.'
    });
  }
});

// Get all active sessions
router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const sessionsQuery = `
      SELECT 
        session_token,
        created_at,
        last_accessed,
        expires_at,
        CASE 
          WHEN session_token = $2 THEN true 
          ELSE false 
        END as is_current
      FROM user_sessions 
      WHERE user_id = $1 AND expires_at > NOW()
      ORDER BY last_accessed DESC
    `;

    const currentToken = req.headers['authorization'].split(' ')[1];
    const result = await pool.query(sessionsQuery, [req.user.id, currentToken]);

    const sessions = result.rows.map(session => ({
      sessionId: session.session_token.substring(0, 8) + '...', // Show only first 8 chars for security
      createdAt: session.created_at,
      lastAccessed: session.last_accessed,
      expiresAt: session.expires_at,
      isCurrent: session.is_current
    }));

    res.json({
      sessions: sessions,
      totalSessions: sessions.length
    });

  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      error: 'Failed to get sessions',
      message: 'An error occurred while retrieving your sessions.'
    });
  }
});

// Logout from specific session
router.delete('/sessions/:sessionId', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const currentToken = req.headers['authorization'].split(' ')[1];

    // Prevent deleting current session
    if (sessionId === currentToken || currentToken.startsWith(sessionId)) {
      return res.status(400).json({
        error: 'Cannot logout current session',
        message: 'Use the general logout endpoint to end your current session.'
      });
    }

    // Find and delete the session
    const deleteQuery = `
      DELETE FROM user_sessions 
      WHERE user_id = $1 AND session_token LIKE $2
      RETURNING session_token
    `;

    const result = await pool.query(deleteQuery, [req.user.id, sessionId + '%']);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Session not found',
        message: 'The specified session was not found or has already expired.'
      });
    }

    res.json({
      message: 'Session terminated successfully'
    });

  } catch (error) {
    console.error('Delete session error:', error);
    res.status(500).json({
      error: 'Failed to terminate session',
      message: 'An error occurred while terminating the session.'
    });
  }
});

// Logout from all other sessions (keep current)
router.delete('/sessions/others', authenticateToken, async (req, res) => {
  try {
    const currentToken = req.headers['authorization'].split(' ')[1];

    const deleteQuery = `
      DELETE FROM user_sessions 
      WHERE user_id = $1 AND session_token != $2
    `;

    const result = await pool.query(deleteQuery, [req.user.id, currentToken]);

    res.json({
      message: 'All other sessions terminated successfully',
      sessionsTerminated: result.rowCount
    });

  } catch (error) {
    console.error('Delete other sessions error:', error);
    res.status(500).json({
      error: 'Failed to terminate sessions',
      message: 'An error occurred while terminating other sessions.'
    });
  }
});

// Logout from all sessions (including current)
router.delete('/sessions/all', authenticateToken, async (req, res) => {
  try {
    const deleteQuery = 'DELETE FROM user_sessions WHERE user_id = $1';
    const result = await pool.query(deleteQuery, [req.user.id]);

    res.json({
      message: 'All sessions terminated successfully',
      sessionsTerminated: result.rowCount,
      note: 'You have been logged out from all devices.'
    });

  } catch (error) {
    console.error('Delete all sessions error:', error);
    res.status(500).json({
      error: 'Failed to terminate sessions',
      message: 'An error occurred while terminating all sessions.'
    });
  }
});

// Get user preferences
router.get('/preferences', authenticateToken, async (req, res) => {
  try {
    const preferencesQuery = `
      SELECT 
        weekly_goal,
        privacy_profile_visible,
        privacy_stats_visible,
        privacy_groups_visible,
        notifications_gym_reminders,
        notifications_streak_alerts,
        notifications_group_updates,
        notifications_leaderboard_updates,
        theme_preference,
        updated_at
      FROM user_preferences 
      WHERE user_id = $1
    `;
    
    const result = await pool.query(preferencesQuery, [req.user.id]);

    if (result.rows.length === 0) {
      // Create default preferences if none exist
      const createQuery = `
        INSERT INTO user_preferences (user_id)
        VALUES ($1)
        RETURNING 
          weekly_goal,
          privacy_profile_visible,
          privacy_stats_visible,
          privacy_groups_visible,
          notifications_gym_reminders,
          notifications_streak_alerts,
          notifications_group_updates,
          notifications_leaderboard_updates,
          theme_preference,
          updated_at
      `;
      
      const createResult = await pool.query(createQuery, [req.user.id]);
      
      res.json({
        preferences: createResult.rows[0]
      });
    } else {
      res.json({
        preferences: result.rows[0]
      });
    }

  } catch (error) {
    console.error('Get preferences error:', error);
    res.status(500).json({
      error: 'Failed to get preferences',
      message: 'An error occurred while retrieving your preferences.'
    });
  }
});

// Update user preferences
router.put('/preferences', [
  authenticateToken,
  body('weekly_goal')
    .optional()
    .isInt({ min: 1, max: 7 })
    .withMessage('Weekly goal must be between 1 and 7'),
  body('privacy_profile_visible')
    .optional()
    .isBoolean()
    .withMessage('Privacy profile visible must be true or false'),
  body('privacy_stats_visible')
    .optional()
    .isBoolean()
    .withMessage('Privacy stats visible must be true or false'),
  body('privacy_groups_visible')
    .optional()
    .isBoolean()
    .withMessage('Privacy groups visible must be true or false'),
  body('notifications_gym_reminders')
    .optional()
    .isBoolean()
    .withMessage('Gym reminders must be true or false'),
  body('notifications_streak_alerts')
    .optional()
    .isBoolean()
    .withMessage('Streak alerts must be true or false'),
  body('notifications_group_updates')
    .optional()
    .isBoolean()
    .withMessage('Group updates must be true or false'),
  body('notifications_leaderboard_updates')
    .optional()
    .isBoolean()
    .withMessage('Leaderboard updates must be true or false'),
  body('theme_preference')
    .optional()
    .isIn(['light', 'dark', 'system'])
    .withMessage('Theme preference must be light, dark, or system')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const {
      weekly_goal,
      privacy_profile_visible,
      privacy_stats_visible,
      privacy_groups_visible,
      notifications_gym_reminders,
      notifications_streak_alerts,
      notifications_group_updates,
      notifications_leaderboard_updates,
      theme_preference
    } = req.body;

    // Build dynamic update query
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (weekly_goal !== undefined) {
      updates.push(`weekly_goal = $${paramCount++}`);
      values.push(weekly_goal);
    }
    if (privacy_profile_visible !== undefined) {
      updates.push(`privacy_profile_visible = $${paramCount++}`);
      values.push(privacy_profile_visible);
    }
    if (privacy_stats_visible !== undefined) {
      updates.push(`privacy_stats_visible = $${paramCount++}`);
      values.push(privacy_stats_visible);
    }
    if (privacy_groups_visible !== undefined) {
      updates.push(`privacy_groups_visible = $${paramCount++}`);
      values.push(privacy_groups_visible);
    }
    if (notifications_gym_reminders !== undefined) {
      updates.push(`notifications_gym_reminders = $${paramCount++}`);
      values.push(notifications_gym_reminders);
    }
    if (notifications_streak_alerts !== undefined) {
      updates.push(`notifications_streak_alerts = $${paramCount++}`);
      values.push(notifications_streak_alerts);
    }
    if (notifications_group_updates !== undefined) {
      updates.push(`notifications_group_updates = $${paramCount++}`);
      values.push(notifications_group_updates);
    }
    if (notifications_leaderboard_updates !== undefined) {
      updates.push(`notifications_leaderboard_updates = $${paramCount++}`);
      values.push(notifications_leaderboard_updates);
    }
    if (theme_preference !== undefined) {
      updates.push(`theme_preference = $${paramCount++}`);
      values.push(theme_preference);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: 'No valid fields provided for update',
        message: 'Please provide at least one valid field to update.'
      });
    }

    const updateQuery = `
      UPDATE user_preferences 
      SET ${updates.join(', ')}
      WHERE user_id = $${paramCount}
      RETURNING 
        weekly_goal,
        privacy_profile_visible,
        privacy_stats_visible,
        privacy_groups_visible,
        notifications_gym_reminders,
        notifications_streak_alerts,
        notifications_group_updates,
        notifications_leaderboard_updates,
        theme_preference,
        updated_at
    `;
    
    const result = await pool.query(updateQuery, [...values, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Preferences not found',
        message: 'User preferences not found.'
      });
    }

    res.json({
      message: 'Preferences updated successfully',
      preferences: result.rows[0]
    });

  } catch (error) {
    console.error('Update preferences error:', error);
    res.status(500).json({
      error: 'Failed to update preferences',
      message: 'An error occurred while updating your preferences.'
    });
  }
});