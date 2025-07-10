const express = require('express');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

/**
 * @swagger
 * /api/gym-visits:
 *   post:
 *     summary: Record a new gym visit
 *     description: Add a new gym check-in with optional notes and workout tag
 *     tags: [Gym Visits]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               notes:
 *                 type: string
 *                 maxLength: 500
 *                 example: Great workout today! Felt really strong.
 *               tag:
 *                 type: string
 *                 enum: [cardio, upper-body, lower-body, swimming, walking]
 *                 example: cardio
 *               date:
 *                 type: string
 *                 format: date-time
 *                 example: 2024-01-01T10:00:00Z
 *     responses:
 *       201:
 *         description: Gym visit recorded successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Gym visit recorded successfully
 *                 visit:
 *                   $ref: '#/components/schemas/GymVisit'
 *       400:
 *         description: Validation failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Failed to record visit
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Add gym visit
router.post('/', [
  authenticateToken,
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes must be 500 characters or less'),
  body('tag')
    .optional()
    .isIn(['cardio', 'upper-body', 'lower-body', 'swimming', 'walking'])
    .withMessage('Invalid workout tag')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { notes = '', tag, date } = req.body;
    const visitDate = date ? new Date(date) : new Date();
    const visitId = uuidv4();

    const insertQuery = `
      INSERT INTO gym_visits (id, user_id, date, notes, tag)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, user_id, date, notes, tag, created_at
    `;

    const result = await pool.query(insertQuery, [
      visitId,
      req.user.id,
      visitDate,
      notes,
      tag || null
    ]);

    const visit = result.rows[0];

    // Update user statistics
    await updateUserStatistics(req.user.id);

    res.status(201).json({
      message: 'Gym visit recorded successfully',
      visit: {
        id: visit.id,
        userId: visit.user_id,
        date: visit.date,
        notes: visit.notes,
        tag: visit.tag,
        createdAt: visit.created_at
      }
    });

  } catch (error) {
    console.error('Add gym visit error:', error);
    res.status(500).json({
      error: 'Failed to record visit',
      message: 'An error occurred while recording your gym visit.'
    });
  }
});

/**
 * @swagger
 * /api/gym-visits:
 *   get:
 *     summary: Get user's gym visits
 *     description: Retrieve a paginated list of the authenticated user's gym visits
 *     tags: [Gym Visits]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *           minimum: 1
 *           maximum: 100
 *         description: Number of visits to return
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *           minimum: 0
 *         description: Number of visits to skip
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter visits from this date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Filter visits until this date
 *     responses:
 *       200:
 *         description: List of gym visits
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 visits:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/GymVisit'
 *                 total:
 *                   type: integer
 *                   example: 15
 *                 limit:
 *                   type: integer
 *                   example: 50
 *                 offset:
 *                   type: integer
 *                   example: 0
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Failed to get visits
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Get user's gym visits
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, offset = 0, startDate, endDate } = req.query;
    
    let query = `
      SELECT id, user_id, date, notes, tag, created_at, updated_at
      FROM gym_visits 
      WHERE user_id = $1
    `;
    const params = [req.user.id];
    let paramCount = 1;

    // Add date filters if provided
    if (startDate) {
      paramCount++;
      query += ` AND date >= $${paramCount}`;
      params.push(new Date(startDate));
    }

    if (endDate) {
      paramCount++;
      query += ` AND date <= $${paramCount}`;
      params.push(new Date(endDate));
    }

    query += ` ORDER BY date DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, params);

    const visits = result.rows.map(visit => ({
      id: visit.id,
      userId: visit.user_id,
      date: visit.date,
      notes: visit.notes,
      tag: visit.tag,
      createdAt: visit.created_at,
      updatedAt: visit.updated_at
    }));

    res.json({
      visits,
      total: visits.length,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

  } catch (error) {
    console.error('Get gym visits error:', error);
    res.status(500).json({
      error: 'Failed to get visits',
      message: 'An error occurred while retrieving your gym visits.'
    });
  }
});

// Get today's visits
router.get('/today', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT id, user_id, date, notes, tag, created_at
      FROM gym_visits 
      WHERE user_id = $1 
        AND DATE(date) = CURRENT_DATE
      ORDER BY date DESC
    `;

    const result = await pool.query(query, [req.user.id]);

    const visits = result.rows.map(visit => ({
      id: visit.id,
      userId: visit.user_id,
      date: visit.date,
      notes: visit.notes,
      tag: visit.tag,
      createdAt: visit.created_at
    }));

    res.json({
      visits,
      hasVisitedToday: visits.length > 0,
      visitCount: visits.length
    });

  } catch (error) {
    console.error('Get today visits error:', error);
    res.status(500).json({
      error: 'Failed to get today\'s visits',
      message: 'An error occurred while retrieving today\'s visits.'
    });
  }
});

// Update gym visit
router.put('/:id', [
  authenticateToken,
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Notes must be 500 characters or less'),
  body('tag')
    .optional()
    .isIn(['cardio', 'upper-body', 'lower-body', 'swimming', 'walking'])
    .withMessage('Invalid workout tag')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { id } = req.params;
    const { notes, tag } = req.body;

    const updateQuery = `
      UPDATE gym_visits 
      SET notes = COALESCE($1, notes), 
          tag = COALESCE($2, tag),
          updated_at = NOW()
      WHERE id = $3 AND user_id = $4
      RETURNING id, user_id, date, notes, tag, updated_at
    `;

    const result = await pool.query(updateQuery, [
      notes || null,
      tag || null,
      id,
      req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Visit not found',
        message: 'Gym visit not found or you don\'t have permission to update it.'
      });
    }

    const visit = result.rows[0];

    res.json({
      message: 'Gym visit updated successfully',
      visit: {
        id: visit.id,
        userId: visit.user_id,
        date: visit.date,
        notes: visit.notes,
        tag: visit.tag,
        updatedAt: visit.updated_at
      }
    });

  } catch (error) {
    console.error('Update gym visit error:', error);
    res.status(500).json({
      error: 'Failed to update visit',
      message: 'An error occurred while updating your gym visit.'
    });
  }
});

// Delete gym visit
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const deleteQuery = `
      DELETE FROM gym_visits 
      WHERE id = $1 AND user_id = $2
      RETURNING id
    `;

    const result = await pool.query(deleteQuery, [id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Visit not found',
        message: 'Gym visit not found or you don\'t have permission to delete it.'
      });
    }

    // Update user statistics
    await updateUserStatistics(req.user.id);

    res.json({
      message: 'Gym visit deleted successfully'
    });

  } catch (error) {
    console.error('Delete gym visit error:', error);
    res.status(500).json({
      error: 'Failed to delete visit',
      message: 'An error occurred while deleting your gym visit.'
    });
  }
});

// Get heatmap data (for the last year)
router.get('/heatmap', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT DATE(date) as visit_date, COUNT(*) as visit_count
      FROM gym_visits 
      WHERE user_id = $1 
        AND date >= NOW() - INTERVAL '1 year'
      GROUP BY DATE(date)
      ORDER BY visit_date
    `;

    const result = await pool.query(query, [req.user.id]);

    const heatmapData = result.rows.map(row => ({
      date: row.visit_date,
      count: parseInt(row.visit_count)
    }));

    res.json({
      heatmapData,
      totalDays: heatmapData.length,
      totalVisits: heatmapData.reduce((sum, day) => sum + day.count, 0)
    });

  } catch (error) {
    console.error('Get heatmap error:', error);
    res.status(500).json({
      error: 'Failed to get heatmap data',
      message: 'An error occurred while retrieving heatmap data.'
    });
  }
});

// Helper function to update user statistics
async function updateUserStatistics(userId) {
  try {
    // Calculate total gym days (unique dates)
    const totalDaysQuery = `
      SELECT COUNT(DISTINCT DATE(date)) as total_days
      FROM gym_visits 
      WHERE user_id = $1
    `;
    const totalResult = await pool.query(totalDaysQuery, [userId]);
    const totalGymDays = totalResult.rows[0].total_days || 0;

    // Calculate current streak
    const currentStreak = await calculateCurrentStreak(userId);
    
    // Calculate longest streak
    const longestStreak = await calculateLongestStreak(userId);

    // Update user record
    const updateQuery = `
      UPDATE users 
      SET total_gym_days = $1,
          current_streak = $2,
          longest_streak = $3,
          updated_at = NOW()
      WHERE id = $4
    `;

    await pool.query(updateQuery, [
      totalGymDays,
      currentStreak,
      longestStreak,
      userId
    ]);

  } catch (error) {
    console.error('Update user statistics error:', error);
  }
}

// Helper function to calculate current streak
async function calculateCurrentStreak(userId) {
  const query = `
    SELECT DISTINCT DATE(date) as visit_date
    FROM gym_visits 
    WHERE user_id = $1
    ORDER BY visit_date DESC
  `;

  const result = await pool.query(query, [userId]);
  const dates = result.rows.map(row => new Date(row.visit_date));

  if (dates.length === 0) return 0;

  let streak = 0;
  let currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0);

  // Check if visited today or yesterday to start streak
  const today = new Date(currentDate);
  const yesterday = new Date(currentDate);
  yesterday.setDate(yesterday.getDate() - 1);

  let startDate = null;
  if (dates.some(date => date.getTime() === today.getTime())) {
    startDate = today;
  } else if (dates.some(date => date.getTime() === yesterday.getTime())) {
    startDate = yesterday;
  } else {
    return 0; // No recent visits
  }

  // Count consecutive days
  let checkDate = new Date(startDate);
  for (const date of dates) {
    if (date.getTime() === checkDate.getTime()) {
      streak++;
      checkDate.setDate(checkDate.getDate() - 1);
    }
  }

  return streak;
}

// Helper function to calculate longest streak
async function calculateLongestStreak(userId) {
  const query = `
    SELECT DISTINCT DATE(date) as visit_date
    FROM gym_visits 
    WHERE user_id = $1
    ORDER BY visit_date ASC
  `;

  const result = await pool.query(query, [userId]);
  const dates = result.rows.map(row => new Date(row.visit_date));

  if (dates.length === 0) return 0;

  let longestStreak = 1;
  let currentStreak = 1;

  for (let i = 1; i < dates.length; i++) {
    const prevDate = dates[i - 1];
    const currentDate = dates[i];
    
    // Check if dates are consecutive
    const dayDiff = (currentDate - prevDate) / (1000 * 60 * 60 * 24);
    
    if (dayDiff === 1) {
      currentStreak++;
      longestStreak = Math.max(longestStreak, currentStreak);
    } else {
      currentStreak = 1;
    }
  }

  return longestStreak;
}

module.exports = router; 