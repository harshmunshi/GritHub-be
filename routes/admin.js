const express = require('express');
const { body, query, validationResult } = require('express-validator');
const pool = require('../db');
const { requireAdmin } = require('../middleware/admin');

const router = express.Router();

// Get all users with pagination and search
router.get('/users', [
  requireAdmin,
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('search')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Search term must be less than 100 characters'),
  query('sortBy')
    .optional()
    .isIn(['name', 'email', 'join_date', 'total_gym_days', 'current_streak'])
    .withMessage('Invalid sort field'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const sortBy = req.query.sortBy || 'join_date';
    const sortOrder = req.query.sortOrder || 'desc';
    const offset = (page - 1) * limit;

    // Build search condition
    let searchCondition = '';
    let searchValues = [];
    let paramCount = 1;

    if (search) {
      searchCondition = `WHERE (name ILIKE $${paramCount} OR email ILIKE $${paramCount})`;
      searchValues.push(`%${search}%`);
      paramCount++;
    }

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM users
      ${searchCondition}
    `;

    const countResult = await pool.query(countQuery, searchValues);
    const totalUsers = parseInt(countResult.rows[0].total);

    // Get users
    const usersQuery = `
      SELECT 
        id,
        name,
        email,
        join_date,
        current_streak,
        longest_streak,
        total_gym_days,
        created_at,
        updated_at,
        CASE WHEN profile_image IS NOT NULL THEN true ELSE false END as has_profile_image
      FROM users
      ${searchCondition}
      ORDER BY ${sortBy} ${sortOrder.toUpperCase()}
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `;

    const usersResult = await pool.query(usersQuery, [...searchValues, limit, offset]);

    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      users: usersResult.rows,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalUsers: totalUsers,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
        limit: limit
      }
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      error: 'Failed to get users',
      message: 'An error occurred while retrieving users.'
    });
  }
});

// Get user details by ID
router.get('/users/:userId', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const userQuery = `
      SELECT 
        u.id,
        u.name,
        u.email,
        u.join_date,
        u.current_streak,
        u.longest_streak,
        u.total_gym_days,
        u.created_at,
        u.updated_at,
        CASE WHEN u.profile_image IS NOT NULL THEN true ELSE false END as has_profile_image,
        up.weekly_goal,
        up.privacy_profile_visible,
        up.privacy_stats_visible,
        up.privacy_groups_visible,
        up.theme_preference
      FROM users u
      LEFT JOIN user_preferences up ON u.id = up.user_id
      WHERE u.id = $1
    `;

    const userResult = await pool.query(userQuery, [userId]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found.'
      });
    }

    // Get user's recent gym visits
    const visitsQuery = `
      SELECT id, date, notes, tag, created_at
      FROM gym_visits
      WHERE user_id = $1
      ORDER BY date DESC
      LIMIT 10
    `;

    const visitsResult = await pool.query(visitsQuery, [userId]);

    // Get user's group memberships
    const groupsQuery = `
      SELECT g.id, g.name, g.description, gm.joined_at
      FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.user_id = $1
      ORDER BY gm.joined_at DESC
    `;

    const groupsResult = await pool.query(groupsQuery, [userId]);

    // Get user's active sessions count
    const sessionsQuery = `
      SELECT COUNT(*) as active_sessions
      FROM user_sessions
      WHERE user_id = $1 AND expires_at > NOW()
    `;

    const sessionsResult = await pool.query(sessionsQuery, [userId]);

    res.json({
      user: userResult.rows[0],
      recentVisits: visitsResult.rows,
      groups: groupsResult.rows,
      activeSessions: parseInt(sessionsResult.rows[0].active_sessions)
    });

  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({
      error: 'Failed to get user details',
      message: 'An error occurred while retrieving user details.'
    });
  }
});

// Get admin dashboard statistics
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    // Get overall statistics
    const statsQuery = `
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as new_users_30_days,
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '7 days' THEN 1 END) as new_users_7_days
      FROM users
    `;

    const statsResult = await pool.query(statsQuery);

    // Get gym visits statistics
    const visitsStatsQuery = `
      SELECT 
        COUNT(*) as total_visits,
        COUNT(CASE WHEN date >= NOW() - INTERVAL '30 days' THEN 1 END) as visits_30_days,
        COUNT(CASE WHEN date >= NOW() - INTERVAL '7 days' THEN 1 END) as visits_7_days,
        COUNT(DISTINCT user_id) as active_users
      FROM gym_visits
    `;

    const visitsStatsResult = await pool.query(visitsStatsQuery);

    // Get groups statistics
    const groupsStatsQuery = `
      SELECT 
        COUNT(*) as total_groups,
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as new_groups_30_days
      FROM groups
    `;

    const groupsStatsResult = await pool.query(groupsStatsQuery);

    // Get top users by gym days
    const topUsersQuery = `
      SELECT name, email, total_gym_days, current_streak
      FROM users
      ORDER BY total_gym_days DESC
      LIMIT 10
    `;

    const topUsersResult = await pool.query(topUsersQuery);

    // Get most active groups
    const activeGroupsQuery = `
      SELECT 
        g.name,
        g.description,
        COUNT(gm.user_id) as member_count,
        g.created_date
      FROM groups g
      LEFT JOIN group_members gm ON g.id = gm.group_id
      GROUP BY g.id, g.name, g.description, g.created_date
      ORDER BY member_count DESC
      LIMIT 10
    `;

    const activeGroupsResult = await pool.query(activeGroupsQuery);

    res.json({
      overview: {
        ...statsResult.rows[0],
        ...visitsStatsResult.rows[0],
        ...groupsStatsResult.rows[0]
      },
      topUsers: topUsersResult.rows,
      activeGroups: activeGroupsResult.rows
    });

  } catch (error) {
    console.error('Get admin stats error:', error);
    res.status(500).json({
      error: 'Failed to get statistics',
      message: 'An error occurred while retrieving statistics.'
    });
  }
});

// Update user information (admin only)
router.put('/users/:userId', [
  requireAdmin,
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('current_streak')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Current streak must be a non-negative integer'),
  body('longest_streak')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Longest streak must be a non-negative integer'),
  body('total_gym_days')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Total gym days must be a non-negative integer')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { userId } = req.params;
    const { name, email, current_streak, longest_streak, total_gym_days } = req.body;

    // Build dynamic update query
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (name !== undefined) {
      updates.push(`name = $${paramCount++}`);
      values.push(name);
    }
    if (email !== undefined) {
      // Check if email already exists
      const emailCheckQuery = 'SELECT id FROM users WHERE email = $1 AND id != $2';
      const emailCheckResult = await pool.query(emailCheckQuery, [email, userId]);
      
      if (emailCheckResult.rows.length > 0) {
        return res.status(409).json({
          error: 'Email already exists',
          message: 'An account with this email address already exists.'
        });
      }
      
      updates.push(`email = $${paramCount++}`);
      values.push(email);
    }
    if (current_streak !== undefined) {
      updates.push(`current_streak = $${paramCount++}`);
      values.push(current_streak);
    }
    if (longest_streak !== undefined) {
      updates.push(`longest_streak = $${paramCount++}`);
      values.push(longest_streak);
    }
    if (total_gym_days !== undefined) {
      updates.push(`total_gym_days = $${paramCount++}`);
      values.push(total_gym_days);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: 'No updates provided',
        message: 'No valid fields provided for update.'
      });
    }

    updates.push(`updated_at = NOW()`);
    values.push(userId);

    const updateQuery = `
      UPDATE users 
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, name, email, current_streak, longest_streak, total_gym_days, updated_at
    `;

    const result = await pool.query(updateQuery, values);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found.'
      });
    }

    res.json({
      message: 'User updated successfully',
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      error: 'Failed to update user',
      message: 'An error occurred while updating the user.'
    });
  }
});

// Delete user (admin only)
router.delete('/users/:userId', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    // Start transaction
    await pool.query('BEGIN');

    // Get user info before deletion
    const userQuery = 'SELECT name, email FROM users WHERE id = $1';
    const userResult = await pool.query(userQuery, [userId]);

    if (userResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found.'
      });
    }

    const user = userResult.rows[0];

    // Delete user (cascade will handle related records)
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);

    // Commit transaction
    await pool.query('COMMIT');

    res.json({
      message: 'User deleted successfully',
      deletedUser: {
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Delete user error:', error);
    res.status(500).json({
      error: 'Failed to delete user',
      message: 'An error occurred while deleting the user.'
    });
  }
});

// Cleanup expired sessions (admin utility)
router.post('/cleanup/sessions', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT cleanup_expired_sessions()');
    const deletedCount = result.rows[0].cleanup_expired_sessions;

    res.json({
      message: 'Session cleanup completed',
      deletedSessions: deletedCount
    });

  } catch (error) {
    console.error('Session cleanup error:', error);
    res.status(500).json({
      error: 'Failed to cleanup sessions',
      message: 'An error occurred during session cleanup.'
    });
  }
});

module.exports = router; 