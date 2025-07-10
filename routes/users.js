const express = require('express');
const { body, validationResult } = require('express-validator');
const pool = require('../db');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

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

module.exports = router; 