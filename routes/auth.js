const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db');
const { authenticateToken, JWT_SECRET } = require('../middleware/auth');

const router = express.Router();

const JWT_EXPIRES_IN = '30d';

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     summary: Create a new user account
 *     description: Register a new user with name, email, and password
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 50
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 minLength: 6
 *                 example: password123
 *     responses:
 *       201:
 *         description: Account created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Account created successfully
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 token:
 *                   type: string
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       400:
 *         description: Validation failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Email already exists
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Registration failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Sign Up
router.post('/signup', [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg,
        details: errors.array()
      });
    }

    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: 'Email already exists',
        message: 'An account with this email address already exists.'
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = uuidv4();
    const userQuery = `
      INSERT INTO users (id, name, email, password_hash)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, email, join_date, current_streak, longest_streak, total_gym_days
    `;

    const userResult = await pool.query(userQuery, [
      userId,
      name,
      email,
      hashedPassword
    ]);

    const user = userResult.rows[0];

    // Create JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Create session
    const sessionQuery = `
      INSERT INTO user_sessions (user_id, session_token, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '30 days')
    `;
    
    await pool.query(sessionQuery, [user.id, token]);

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        joinDate: user.join_date,
        currentStreak: user.current_streak,
        longestStreak: user.longest_streak,
        totalGymDays: user.total_gym_days
      },
      token
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: 'An error occurred while creating your account. Please try again.'
    });
  }
});

/**
 * @swagger
 * /api/auth/signin:
 *   post:
 *     summary: Sign in an existing user
 *     description: Authenticate user with email and password
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: Sign in successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Sign in successful
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *                 token:
 *                   type: string
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       400:
 *         description: Validation failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Sign in failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Sign In
router.post('/signin', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { email, password } = req.body;

    // Find user
    const userQuery = `
      SELECT id, name, email, password_hash, join_date, current_streak, longest_streak, total_gym_days
      FROM users 
      WHERE email = $1
    `;
    
    const userResult = await pool.query(userQuery, [email]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Invalid email or password.'
      });
    }

    const user = userResult.rows[0];

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Invalid email or password.'
      });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Clean up old sessions for this user
    await pool.query(
      'DELETE FROM user_sessions WHERE user_id = $1 AND expires_at < NOW()',
      [user.id]
    );

    // Create new session
    const sessionQuery = `
      INSERT INTO user_sessions (user_id, session_token, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '30 days')
    `;
    
    await pool.query(sessionQuery, [user.id, token]);

    res.json({
      message: 'Sign in successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        joinDate: user.join_date,
        currentStreak: user.current_streak,
        longestStreak: user.longest_streak,
        totalGymDays: user.total_gym_days
      },
      token
    });

  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      error: 'Sign in failed',
      message: 'An error occurred while signing in. Please try again.'
    });
  }
});

/**
 * @swagger
 * /api/auth/signout:
 *   post:
 *     summary: Sign out current user
 *     description: Invalidate the current user session
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Signed out successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Signed out successfully
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Sign out failed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Sign Out
router.post('/signout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Delete the session
    await pool.query(
      'DELETE FROM user_sessions WHERE session_token = $1',
      [token]
    );

    res.json({
      message: 'Signed out successfully'
    });

  } catch (error) {
    console.error('Signout error:', error);
    res.status(500).json({
      error: 'Sign out failed',
      message: 'An error occurred while signing out.'
    });
  }
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user information
 *     description: Retrieve the current authenticated user's profile data
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user information
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Failed to get user data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Verify Token / Get Current User
router.get('/me', authenticateToken, async (req, res) => {
  try {
    // Get updated user data
    const userQuery = `
      SELECT id, name, email, join_date, current_streak, longest_streak, total_gym_days
      FROM users 
      WHERE id = $1
    `;
    
    const userResult = await pool.query(userQuery, [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User account no longer exists.'
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
        totalGymDays: user.total_gym_days
      }
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      error: 'Failed to get user data',
      message: 'An error occurred while retrieving user information.'
    });
  }
});

// Reset Password Request
router.post('/reset-password', [
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
    const userResult = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    // Always return success to prevent email enumeration
    res.json({
      message: 'If an account with this email exists, a password reset link has been sent.'
    });

    // In a real implementation, you would:
    // 1. Generate a reset token
    // 2. Store it in the database with expiration
    // 3. Send an email with the reset link
    
    if (userResult.rows.length > 0) {
      console.log(`Password reset requested for user: ${email}`);
      // TODO: Implement email sending logic
    }

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      error: 'Reset request failed',
      message: 'An error occurred while processing your request.'
    });
  }
});

// Clean up expired sessions (utility endpoint)
router.post('/cleanup-sessions', async (req, res) => {
  try {
    const result = await pool.query('SELECT cleanup_expired_sessions()');
    const deletedCount = result.rows[0].cleanup_expired_sessions;
    
    res.json({
      message: `Cleaned up ${deletedCount} expired sessions`
    });

  } catch (error) {
    console.error('Session cleanup error:', error);
    res.status(500).json({
      error: 'Cleanup failed',
      message: 'An error occurred during session cleanup.'
    });
  }
});

module.exports = router; 