const express = require('express');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     Group:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           format: uuid
 *           description: Unique identifier for the group
 *         name:
 *           type: string
 *           description: Name of the group
 *           example: "Morning Warriors"
 *         description:
 *           type: string
 *           description: Description of the group
 *           example: "Early morning workout group"
 *         createdBy:
 *           type: string
 *           format: uuid
 *           description: ID of the user who created the group
 *         createdDate:
 *           type: string
 *           format: date-time
 *           description: When the group was created
 *         isPrivate:
 *           type: boolean
 *           description: Whether the group is private
 *           example: false
 *         inviteCode:
 *           type: string
 *           description: 6-digit invite code for joining the group
 *           example: "123456"
 *         groupImage:
 *           type: string
 *           format: byte
 *           description: Base64 encoded group image
 *           nullable: true
 *         memberCount:
 *           type: integer
 *           description: Number of members in the group
 *           example: 5
 *         creatorName:
 *           type: string
 *           description: Name of the group creator
 *           example: "John Doe"
 *     GroupMember:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           format: uuid
 *         name:
 *           type: string
 *           example: "Jane Smith"
 *         email:
 *           type: string
 *           format: email
 *           example: "jane@example.com"
 *         joinDate:
 *           type: string
 *           format: date-time
 *         currentStreak:
 *           type: integer
 *           example: 7
 *         longestStreak:
 *           type: integer
 *           example: 15
 *         totalGymDays:
 *           type: integer
 *           example: 42
 *         joinedAt:
 *           type: string
 *           format: date-time
 *         isCreator:
 *           type: boolean
 *           example: false
 *     LeaderboardEntry:
 *       type: object
 *       properties:
 *         userId:
 *           type: string
 *           format: uuid
 *         userName:
 *           type: string
 *           example: "Alice Johnson"
 *         value:
 *           type: integer
 *           description: The value for the leaderboard metric
 *           example: 12
 *         rank:
 *           type: integer
 *           description: Rank position in the leaderboard
 *           example: 1
 *         lastUpdated:
 *           type: string
 *           format: date-time
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

/**
 * @swagger
 * /api/groups:
 *   post:
 *     summary: Create a new group
 *     description: Creates a new gym group with the authenticated user as the creator and first member
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 255
 *                 description: Name of the group
 *                 example: "Morning Warriors"
 *               description:
 *                 type: string
 *                 maxLength: 1000
 *                 description: Optional description of the group
 *                 example: "Early morning workout enthusiasts"
 *               isPrivate:
 *                 type: boolean
 *                 description: Whether the group should be private
 *                 default: false
 *                 example: false
 *     responses:
 *       201:
 *         description: Group created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Group created successfully"
 *                 group:
 *                   $ref: '#/components/schemas/Group'
 *       400:
 *         description: Validation error
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
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Create a new group
router.post('/', [
  authenticateToken,
  body('name')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Group name must be between 1 and 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters'),
  body('isPrivate')
    .optional()
    .isBoolean()
    .withMessage('isPrivate must be a boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { name, description = '', isPrivate = false } = req.body;
    const userId = req.user.id;

    // Start transaction
    await pool.query('BEGIN');

    try {
      // Create the group
      const createGroupQuery = `
        INSERT INTO groups (name, description, created_by, is_private)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, description, created_by, created_date, is_private, invite_code
      `;

      const groupResult = await pool.query(createGroupQuery, [name, description, userId, isPrivate]);
      const group = groupResult.rows[0];

      // The trigger will automatically add the creator as a member,
      // but let's verify the membership was created
      const membershipQuery = `
        SELECT COUNT(*) as member_count 
        FROM group_members 
        WHERE group_id = $1 AND user_id = $2
      `;
      
      const membershipResult = await pool.query(membershipQuery, [group.id, userId]);
      
      if (membershipResult.rows[0].member_count === '0') {
        // If for some reason the trigger didn't work, add manually
        await pool.query(
          'INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)',
          [group.id, userId]
        );
      }

      await pool.query('COMMIT');

      res.status(201).json({
        message: 'Group created successfully',
        group: {
          id: group.id,
          name: group.name,
          description: group.description,
          createdBy: group.created_by,
          createdDate: group.created_date,
          isPrivate: group.is_private,
          inviteCode: group.invite_code,
          memberCount: 1
        }
      });

    } catch (innerError) {
      await pool.query('ROLLBACK');
      throw innerError;
    }

  } catch (error) {
    console.error('Create group error:', error);
    res.status(500).json({
      error: 'Failed to create group',
      message: 'An error occurred while creating the group.'
    });
  }
});

/**
 * @swagger
 * /api/groups:
 *   get:
 *     summary: Get all groups for the current user
 *     description: Retrieves all groups that the authenticated user is a member of
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Groups retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 groups:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Group'
 *                 total:
 *                   type: integer
 *                   description: Total number of groups
 *                   example: 3
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Get all groups for the current user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const groupsQuery = `
      SELECT 
        g.id, g.name, g.description, g.created_by, g.created_date, 
        g.is_private, g.invite_code, g.group_image,
        COUNT(gm.user_id) as member_count,
        u.name as creator_name
      FROM groups g
      INNER JOIN group_members gm_user ON g.id = gm_user.group_id AND gm_user.user_id = $1
      LEFT JOIN group_members gm ON g.id = gm.group_id
      LEFT JOIN users u ON g.created_by = u.id
      GROUP BY g.id, g.name, g.description, g.created_by, g.created_date, 
               g.is_private, g.invite_code, g.group_image, u.name
      ORDER BY g.created_date DESC
    `;

    const result = await pool.query(groupsQuery, [userId]);

    const groups = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      createdBy: row.created_by,
      createdDate: row.created_date,
      isPrivate: row.is_private,
      inviteCode: row.invite_code,
      groupImage: row.group_image,
      memberCount: parseInt(row.member_count),
      creatorName: row.creator_name
    }));

    res.json({
      groups,
      total: groups.length
    });

  } catch (error) {
    console.error('Get groups error:', error);
    res.status(500).json({
      error: 'Failed to get groups',
      message: 'An error occurred while retrieving your groups.'
    });
  }
});

/**
 * @swagger
 * /api/groups/{id}:
 *   get:
 *     summary: Get specific group details
 *     description: Retrieves detailed information about a specific group (user must be a member)
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: The group ID
 *         example: "123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Group details retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 group:
 *                   $ref: '#/components/schemas/Group'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Access denied - not a member of this group
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Group not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Get specific group details
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Check if user is a member of this group
    const membershipQuery = `
      SELECT 1 FROM group_members 
      WHERE group_id = $1 AND user_id = $2
    `;

    const membershipResult = await pool.query(membershipQuery, [id, userId]);

    if (membershipResult.rows.length === 0) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You are not a member of this group.'
      });
    }

    // Get group details
    const groupQuery = `
      SELECT 
        g.id, g.name, g.description, g.created_by, g.created_date, 
        g.is_private, g.invite_code, g.group_image,
        COUNT(gm.user_id) as member_count,
        u.name as creator_name
      FROM groups g
      LEFT JOIN group_members gm ON g.id = gm.group_id
      LEFT JOIN users u ON g.created_by = u.id
      WHERE g.id = $1
      GROUP BY g.id, g.name, g.description, g.created_by, g.created_date, 
               g.is_private, g.invite_code, g.group_image, u.name
    `;

    const groupResult = await pool.query(groupQuery, [id]);

    if (groupResult.rows.length === 0) {
      return res.status(404).json({
        error: 'Group not found',
        message: 'The specified group does not exist.'
      });
    }

    const group = groupResult.rows[0];

    res.json({
      group: {
        id: group.id,
        name: group.name,
        description: group.description,
        createdBy: group.created_by,
        createdDate: group.created_date,
        isPrivate: group.is_private,
        inviteCode: group.invite_code,
        groupImage: group.group_image,
        memberCount: parseInt(group.member_count),
        creatorName: group.creator_name
      }
    });

  } catch (error) {
    console.error('Get group details error:', error);
    res.status(500).json({
      error: 'Failed to get group details',
      message: 'An error occurred while retrieving group details.'
    });
  }
});

/**
 * @swagger
 * /api/groups/join-by-code:
 *   post:
 *     summary: Join a group by invite code
 *     description: Join a group using a 6-digit invite code
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - inviteCode
 *             properties:
 *               inviteCode:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *                 description: 6-digit invite code for the group
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Successfully joined the group
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Successfully joined the group"
 *                 group:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       format: uuid
 *                     name:
 *                       type: string
 *                     description:
 *                       type: string
 *                     createdBy:
 *                       type: string
 *                       format: uuid
 *                     isPrivate:
 *                       type: boolean
 *                 joinedAt:
 *                   type: string
 *                   format: date-time
 *       400:
 *         description: Already a member or validation error
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
 *       404:
 *         description: Invalid invite code
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Join a group by invite code
router.post('/join-by-code', [
  authenticateToken,
  body('inviteCode')
    .trim()
    .isLength({ min: 6, max: 6 })
    .withMessage('Invite code must be exactly 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        message: errors.array()[0].msg
      });
    }

    const { inviteCode } = req.body;
    const userId = req.user.id;

    // Start transaction
    await pool.query('BEGIN');

    try {
      // Find group by invite code
      const groupQuery = `
        SELECT id, name, description, created_by, is_private
        FROM groups 
        WHERE invite_code = $1
      `;

      const groupResult = await pool.query(groupQuery, [inviteCode]);

      if (groupResult.rows.length === 0) {
        await pool.query('ROLLBACK');
        return res.status(404).json({
          error: 'Invalid invite code',
          message: 'No group found with this invite code.'
        });
      }

      const group = groupResult.rows[0];

      // Check if user is already a member
      const membershipQuery = `
        SELECT 1 FROM group_members 
        WHERE group_id = $1 AND user_id = $2
      `;

      const membershipResult = await pool.query(membershipQuery, [group.id, userId]);

      if (membershipResult.rows.length > 0) {
        await pool.query('ROLLBACK');
        return res.status(400).json({
          error: 'Already a member',
          message: 'You are already a member of this group.'
        });
      }

      // Add user to group
      const joinQuery = `
        INSERT INTO group_members (group_id, user_id)
        VALUES ($1, $2)
        RETURNING joined_at
      `;

      const joinResult = await pool.query(joinQuery, [group.id, userId]);

      await pool.query('COMMIT');

      res.json({
        message: 'Successfully joined the group',
        group: {
          id: group.id,
          name: group.name,
          description: group.description,
          createdBy: group.created_by,
          isPrivate: group.is_private
        },
        joinedAt: joinResult.rows[0].joined_at
      });

    } catch (innerError) {
      await pool.query('ROLLBACK');
      throw innerError;
    }

  } catch (error) {
    console.error('Join group error:', error);
    res.status(500).json({
      error: 'Failed to join group',
      message: 'An error occurred while joining the group.'
    });
  }
});

/**
 * @swagger
 * /api/groups/{id}/leave:
 *   delete:
 *     summary: Leave a group
 *     description: Remove the authenticated user from a group. If the user is the creator and there are other members, they cannot leave. If the user is the last member, the group will be deleted.
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: The group ID
 *         example: "123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Successfully left the group
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Successfully left the group"
 *       400:
 *         description: Cannot leave group (creator with other members)
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
 *       404:
 *         description: Not a member of this group
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Leave a group
router.delete('/:id/leave', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Start transaction
    await pool.query('BEGIN');

    try {
      // Check if user is a member
      const membershipQuery = `
        SELECT 1 FROM group_members 
        WHERE group_id = $1 AND user_id = $2
      `;

      const membershipResult = await pool.query(membershipQuery, [id, userId]);

      if (membershipResult.rows.length === 0) {
        await pool.query('ROLLBACK');
        return res.status(404).json({
          error: 'Not a member',
          message: 'You are not a member of this group.'
        });
      }

      // Check if user is the creator and if there are other members
      const groupQuery = `
        SELECT created_by, 
               (SELECT COUNT(*) FROM group_members WHERE group_id = $1) as member_count
        FROM groups 
        WHERE id = $1
      `;

      const groupResult = await pool.query(groupQuery, [id]);
      const group = groupResult.rows[0];

      if (group.created_by === userId && parseInt(group.member_count) > 1) {
        await pool.query('ROLLBACK');
        return res.status(400).json({
          error: 'Cannot leave group',
          message: 'As the group creator, you cannot leave while other members are present. Transfer ownership or delete the group instead.'
        });
      }

      // Remove user from group
      const leaveQuery = `
        DELETE FROM group_members 
        WHERE group_id = $1 AND user_id = $2
      `;

      await pool.query(leaveQuery, [id, userId]);

      // If this was the last member and they were the creator, delete the group
      if (group.created_by === userId && parseInt(group.member_count) === 1) {
        await pool.query('DELETE FROM groups WHERE id = $1', [id]);
      }

      await pool.query('COMMIT');

      res.json({
        message: 'Successfully left the group'
      });

    } catch (innerError) {
      await pool.query('ROLLBACK');
      throw innerError;
    }

  } catch (error) {
    console.error('Leave group error:', error);
    res.status(500).json({
      error: 'Failed to leave group',
      message: 'An error occurred while leaving the group.'
    });
  }
});

/**
 * @swagger
 * /api/groups/{id}/members:
 *   get:
 *     summary: Get group members
 *     description: Retrieve all members of a specific group (user must be a member)
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: The group ID
 *         example: "123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Group members retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 members:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/GroupMember'
 *                 total:
 *                   type: integer
 *                   description: Total number of members
 *                   example: 5
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Access denied - not a member of this group
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Get group members
router.get('/:id/members', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Check if user is a member of this group
    const membershipQuery = `
      SELECT 1 FROM group_members 
      WHERE group_id = $1 AND user_id = $2
    `;

    const membershipResult = await pool.query(membershipQuery, [id, userId]);

    if (membershipResult.rows.length === 0) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You are not a member of this group.'
      });
    }

    // Get all group members
    const membersQuery = `
      SELECT 
        u.id, u.name, u.email, u.join_date, u.current_streak, 
        u.longest_streak, u.total_gym_days, gm.joined_at,
        g.created_by
      FROM group_members gm
      INNER JOIN users u ON gm.user_id = u.id
      INNER JOIN groups g ON gm.group_id = g.id
      WHERE gm.group_id = $1
      ORDER BY gm.joined_at ASC
    `;

    const result = await pool.query(membersQuery, [id]);

    const members = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      email: row.email,
      joinDate: row.join_date,
      currentStreak: row.current_streak,
      longestStreak: row.longest_streak,
      totalGymDays: row.total_gym_days,
      joinedAt: row.joined_at,
      isCreator: row.id === row.created_by
    }));

    res.json({
      members,
      total: members.length
    });

  } catch (error) {
    console.error('Get group members error:', error);
    res.status(500).json({
      error: 'Failed to get group members',
      message: 'An error occurred while retrieving group members.'
    });
  }
});

/**
 * @swagger
 * /api/groups/{id}:
 *   put:
 *     summary: Update group details
 *     description: Update group information (only the group creator can update)
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: The group ID
 *         example: "123e4567-e89b-12d3-a456-426614174000"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 255
 *                 description: New name for the group
 *                 example: "Updated Group Name"
 *               description:
 *                 type: string
 *                 maxLength: 1000
 *                 description: New description for the group
 *                 example: "Updated group description"
 *               isPrivate:
 *                 type: boolean
 *                 description: Whether the group should be private
 *                 example: true
 *     responses:
 *       200:
 *         description: Group updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Group updated successfully"
 *                 group:
 *                   $ref: '#/components/schemas/Group'
 *       400:
 *         description: Validation error or no updates provided
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
 *       403:
 *         description: Permission denied - only creator can update
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Group not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Update group details (only by creator)
router.put('/:id', [
  authenticateToken,
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Group name must be between 1 and 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters'),
  body('isPrivate')
    .optional()
    .isBoolean()
    .withMessage('isPrivate must be a boolean')
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
    const userId = req.user.id;
    const { name, description, isPrivate } = req.body;

    // Check if user is the creator
    const groupQuery = `
      SELECT created_by, name as current_name, description as current_description, is_private as current_is_private
      FROM groups 
      WHERE id = $1
    `;

    const groupResult = await pool.query(groupQuery, [id]);

    if (groupResult.rows.length === 0) {
      return res.status(404).json({
        error: 'Group not found',
        message: 'The specified group does not exist.'
      });
    }

    const group = groupResult.rows[0];

    if (group.created_by !== userId) {
      return res.status(403).json({
        error: 'Permission denied',
        message: 'Only the group creator can update group details.'
      });
    }

    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (name !== undefined) {
      updates.push(`name = $${paramCount}`);
      values.push(name);
      paramCount++;
    }

    if (description !== undefined) {
      updates.push(`description = $${paramCount}`);
      values.push(description);
      paramCount++;
    }

    if (isPrivate !== undefined) {
      updates.push(`is_private = $${paramCount}`);
      values.push(isPrivate);
      paramCount++;
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: 'No updates provided',
        message: 'No valid fields provided for update.'
      });
    }

    updates.push('updated_at = NOW()');
    values.push(id);

    const updateQuery = `
      UPDATE groups 
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, name, description, created_by, created_date, is_private, invite_code
    `;

    const result = await pool.query(updateQuery, values);
    const updatedGroup = result.rows[0];

    res.json({
      message: 'Group updated successfully',
      group: {
        id: updatedGroup.id,
        name: updatedGroup.name,
        description: updatedGroup.description,
        createdBy: updatedGroup.created_by,
        createdDate: updatedGroup.created_date,
        isPrivate: updatedGroup.is_private,
        inviteCode: updatedGroup.invite_code
      }
    });

  } catch (error) {
    console.error('Update group error:', error);
    res.status(500).json({
      error: 'Failed to update group',
      message: 'An error occurred while updating the group.'
    });
  }
});

/**
 * @swagger
 * /api/groups/{id}:
 *   delete:
 *     summary: Delete group
 *     description: Delete a group (only the group creator can delete)
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: The group ID
 *         example: "123e4567-e89b-12d3-a456-426614174000"
 *     responses:
 *       200:
 *         description: Group deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Group deleted successfully"
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Permission denied - only creator can delete
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Group not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Delete group (only by creator)
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Check if user is the creator
    const groupQuery = `
      SELECT created_by, name
      FROM groups 
      WHERE id = $1
    `;

    const groupResult = await pool.query(groupQuery, [id]);

    if (groupResult.rows.length === 0) {
      return res.status(404).json({
        error: 'Group not found',
        message: 'The specified group does not exist.'
      });
    }

    const group = groupResult.rows[0];

    if (group.created_by !== userId) {
      return res.status(403).json({
        error: 'Permission denied',
        message: 'Only the group creator can delete the group.'
      });
    }

    // Delete group (cascade will handle related records)
    const deleteQuery = `
      DELETE FROM groups 
      WHERE id = $1
    `;

    await pool.query(deleteQuery, [id]);

    res.json({
      message: 'Group deleted successfully'
    });

  } catch (error) {
    console.error('Delete group error:', error);
    res.status(500).json({
      error: 'Failed to delete group',
      message: 'An error occurred while deleting the group.'
    });
  }
});

/**
 * @swagger
 * /api/groups/{id}/leaderboard:
 *   get:
 *     summary: Get group leaderboard
 *     description: Retrieve leaderboard data for a specific group with filtering options
 *     tags: [Groups]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: The group ID
 *         example: "123e4567-e89b-12d3-a456-426614174000"
 *       - in: query
 *         name: type
 *         required: false
 *         schema:
 *           type: string
 *           enum: [gym_days, current_streak, longest_streak]
 *           default: gym_days
 *         description: Type of leaderboard metric
 *         example: "gym_days"
 *       - in: query
 *         name: timeframe
 *         required: false
 *         schema:
 *           type: string
 *           enum: [weekly, monthly, quarterly, biannual, yearly]
 *           default: weekly
 *         description: Timeframe for the leaderboard
 *         example: "weekly"
 *     responses:
 *       200:
 *         description: Leaderboard retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 leaderboard:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/LeaderboardEntry'
 *                 type:
 *                   type: string
 *                   description: The leaderboard type used
 *                   example: "gym_days"
 *                 timeframe:
 *                   type: string
 *                   description: The timeframe used
 *                   example: "weekly"
 *                 total:
 *                   type: integer
 *                   description: Total number of entries
 *                   example: 5
 *                 generatedAt:
 *                   type: string
 *                   format: date-time
 *                   description: When the leaderboard was generated
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Access denied - not a member of this group
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Get group leaderboard
router.get('/:id/leaderboard', [
  authenticateToken,
  body('type')
    .optional()
    .isIn(['gym_days', 'current_streak', 'longest_streak'])
    .withMessage('Type must be one of: gym_days, current_streak, longest_streak'),
  body('timeframe')
    .optional()
    .isIn(['weekly', 'monthly', 'quarterly', 'biannual', 'yearly'])
    .withMessage('Timeframe must be one of: weekly, monthly, quarterly, biannual, yearly')
], async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;
    const { type = 'gym_days', timeframe = 'weekly' } = req.query;

    // Check if user is a member of this group
    const membershipQuery = `
      SELECT 1 FROM group_members 
      WHERE group_id = $1 AND user_id = $2
    `;

    const membershipResult = await pool.query(membershipQuery, [id, userId]);

    if (membershipResult.rows.length === 0) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You are not a member of this group.'
      });
    }

    // Calculate date range based on timeframe
    let dateCondition = '';
    const now = new Date();
    
    switch (timeframe) {
      case 'weekly':
        dateCondition = "AND gv.date >= DATE_TRUNC('week', NOW())";
        break;
      case 'monthly':
        dateCondition = "AND gv.date >= DATE_TRUNC('month', NOW())";
        break;
      case 'quarterly':
        dateCondition = "AND gv.date >= DATE_TRUNC('quarter', NOW())";
        break;
      case 'biannual':
        dateCondition = "AND gv.date >= DATE_TRUNC('year', NOW()) + INTERVAL '6 months' * FLOOR(EXTRACT(MONTH FROM NOW() - 1) / 6)";
        break;
      case 'yearly':
        dateCondition = "AND gv.date >= DATE_TRUNC('year', NOW())";
        break;
      default:
        dateCondition = "AND gv.date >= DATE_TRUNC('week', NOW())";
    }

    let leaderboardQuery;

    if (type === 'gym_days') {
      leaderboardQuery = `
        WITH user_stats AS (
          SELECT 
            u.id,
            u.name,
            COUNT(DISTINCT DATE(gv.date)) as gym_days
          FROM group_members gm
          INNER JOIN users u ON gm.user_id = u.id
          LEFT JOIN gym_visits gv ON u.id = gv.user_id ${dateCondition}
          WHERE gm.group_id = $1
          GROUP BY u.id, u.name
        )
        SELECT 
          id as user_id,
          name as user_name,
          gym_days as value,
          RANK() OVER (ORDER BY gym_days DESC, name ASC) as rank
        FROM user_stats
        ORDER BY rank, name
      `;
    } else if (type === 'current_streak') {
      leaderboardQuery = `
        SELECT 
          u.id as user_id,
          u.name as user_name,
          u.current_streak as value,
          RANK() OVER (ORDER BY u.current_streak DESC, u.name ASC) as rank
        FROM group_members gm
        INNER JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = $1
        ORDER BY rank, u.name
      `;
    } else { // longest_streak
      leaderboardQuery = `
        SELECT 
          u.id as user_id,
          u.name as user_name,
          u.longest_streak as value,
          RANK() OVER (ORDER BY u.longest_streak DESC, u.name ASC) as rank
        FROM group_members gm
        INNER JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = $1
        ORDER BY rank, u.name
      `;
    }

    const result = await pool.query(leaderboardQuery, [id]);

    const leaderboard = result.rows.map(row => ({
      userId: row.user_id,
      userName: row.user_name,
      value: parseInt(row.value) || 0,
      rank: parseInt(row.rank),
      lastUpdated: new Date()
    }));

    res.json({
      leaderboard,
      type,
      timeframe,
      total: leaderboard.length,
      generatedAt: new Date()
    });

  } catch (error) {
    console.error('Get group leaderboard error:', error);
    res.status(500).json({
      error: 'Failed to get group leaderboard',
      message: 'An error occurred while retrieving the group leaderboard.'
    });
  }
});

module.exports = router; 