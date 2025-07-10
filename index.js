const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(helmet()); // Security headers
app.use(cors({
  origin: ['http://localhost:3000', 'capacitor://localhost', 'http://localhost', process.env.FRONTEND_URL || '*'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  }
});
app.use('/api/', limiter);

// Auth rate limiting (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.'
  }
});

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'GymTracker API',
      version: '1.0.0',
      description: 'A comprehensive API for the GymTracker iOS app with user authentication and gym visit tracking',
      contact: {
        name: 'GymTracker Team',
        email: 'support@gymtracker.com'
      },
    },
    servers: [
      {
        url: process.env.NODE_ENV === 'production' 
          ? process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'https://your-vercel-app.vercel.app'
          : 'http://localhost:3000',
        description: process.env.NODE_ENV === 'production' ? 'Production server' : 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your JWT token'
        }
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            name: { type: 'string', example: 'John Doe' },
            email: { type: 'string', format: 'email', example: 'john@example.com' },
            joinDate: { type: 'string', format: 'date-time' },
            currentStreak: { type: 'integer', example: 5 },
            longestStreak: { type: 'integer', example: 15 },
            totalGymDays: { type: 'integer', example: 42 }
          }
        },
        GymVisit: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            userId: { type: 'string', format: 'uuid' },
            date: { type: 'string', format: 'date-time' },
            notes: { type: 'string', example: 'Great workout today!' },
            tag: { 
              type: 'string', 
              enum: ['cardio', 'upper-body', 'lower-body', 'swimming', 'walking'],
              example: 'cardio'
            },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' }
          }
        }
      }
    },
    tags: [
      { name: 'Authentication', description: 'User authentication endpoints' },
      { name: 'Users', description: 'User management endpoints' },
      { name: 'Gym Visits', description: 'Gym visit tracking endpoints' },
      { name: 'Groups', description: 'Group management and leaderboard endpoints' }
    ]
  },
  apis: ['./routes/*.js', './index.js'], // Path to the API docs
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'GymTracker API Documentation',
  swaggerOptions: {
    persistAuthorization: true,
    tryItOutEnabled: true
  }
}));

// Routes
app.use('/api/auth', authLimiter);

// Import route modules with error handling
try {
  const authRoutes = require('./routes/auth');
  const userRoutes = require('./routes/users');
  const gymVisitRoutes = require('./routes/gym-visits');
  const groupRoutes = require('./routes/groups');

  // Use routes
  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/gym-visits', gymVisitRoutes);
  app.use('/api/groups', groupRoutes);
} catch (error) {
  console.error('❌ Error loading routes:', error.message);
  // Continue without routes if there's an error
}

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Check API health status
 *     description: Returns the current status of the API server
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: API is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: OK
 *                 message:
 *                   type: string
 *                   example: GymTracker API is running
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 environment:
 *                   type: string
 *                   example: production
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'GymTracker API is running on Vercel',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: process.env.DATABASE_URL ? 'configured' : 'not configured',
    jwt: process.env.JWT_SECRET ? 'configured' : 'not configured'
  });
});

/**
 * @swagger
 * /:
 *   get:
 *     summary: API information and available endpoints
 *     description: Welcome endpoint with API information and documentation links
 *     tags: [Information]
 *     responses:
 *       200:
 *         description: API information
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Welcome to GymTracker API
 *                 version:
 *                   type: string
 *                   example: 1.0.0
 *                 documentation:
 *                   type: string
 *                   example: /api-docs
 *                 endpoints:
 *                   type: object
 */
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to GymTracker API',
    version: '1.0.0',
    documentation: '/api-docs',
    endpoints: {
      health: '/health',
      docs: '/api-docs',
      auth: '/api/auth',
      users: '/api/users',
      gymVisits: '/api/gym-visits',
      groups: '/api/groups'
    },
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist.`,
    availableEndpoints: {
      health: '/health',
      docs: '/api-docs',
      auth: '/api/auth',
      users: '/api/users',
      gymVisits: '/api/gym-visits',
      groups: '/api/groups'
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  
  // Database connection errors
  if (err.code === 'ECONNREFUSED') {
    return res.status(503).json({
      error: 'Database connection failed',
      message: 'Unable to connect to the database. Please try again later.'
    });
  }
  
  // Validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation error',
      message: err.message
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token',
      message: 'Authentication token is invalid.'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token expired',
      message: 'Authentication token has expired.'
    });
  }
  
  // Default error
  res.status(err.status || 500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' 
      ? 'Something went wrong. Please try again later.'
      : err.message
  });
});

// Export for serverless deployment
module.exports = app; 