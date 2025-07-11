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

// Trust proxy for Vercel deployment - more secure configuration
// Trust only the first proxy (Vercel's proxy)
app.set('trust proxy', 1);

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", // Allow inline styles for Swagger UI
        "https://unpkg.com" // Allow Swagger UI CSS from CDN
      ],
      scriptSrc: [
        "'self'", 
        "'unsafe-inline'", // Allow inline scripts for Swagger UI
        "https://unpkg.com" // Allow Swagger UI JS from CDN
      ],
      imgSrc: [
        "'self'", 
        "data:", 
        "https://unpkg.com" // Allow Swagger UI images from CDN
      ],
      fontSrc: ["'self'", "https://unpkg.com"],
      connectSrc: ["'self'"]
    }
  }
})); // Security headers
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'capacitor://localhost', 
    'http://localhost',
    'capacitor://grithub-be.vercel.app',
    'https://grithub-be.vercel.app',
    // Add your iOS app scheme here if you have one (e.g., 'gymtracker://')
    ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : [])
  ],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting with secure proxy configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  // Secure configuration for proxy environment
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Custom key generator for better security in proxy environment
  keyGenerator: (req) => {
    // Use the real IP from trusted proxy headers
    return req.ip || req.connection.remoteAddress || 'unknown';
  }
});
app.use('/api/', limiter);

// Auth rate limiting (stricter) with enhanced security
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // More restrictive for auth endpoints
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress || 'unknown';
  },
  // Skip successful requests for auth endpoints
  skipSuccessfulRequests: true
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
          ? process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'https://grithub-be.vercel.app'
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
        UserPreferences: {
          type: 'object',
          properties: {
            weekly_goal: { type: 'integer', minimum: 1, maximum: 7, example: 3 },
            privacy_profile_visible: { type: 'boolean', example: true },
            privacy_stats_visible: { type: 'boolean', example: true },
            privacy_groups_visible: { type: 'boolean', example: true },
            notifications_gym_reminders: { type: 'boolean', example: true },
            notifications_streak_alerts: { type: 'boolean', example: true },
            notifications_group_updates: { type: 'boolean', example: true },
            notifications_leaderboard_updates: { type: 'boolean', example: true },
            theme_preference: { type: 'string', enum: ['light', 'dark', 'system'], example: 'system' }
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
      { name: 'Groups', description: 'Group management and leaderboard endpoints' },
      { name: 'Admin', description: 'Administrative endpoints' }
    ]
  },
  // Explicitly list route files for better Vercel compatibility
  apis: [
    './routes/auth.js',
    './routes/users.js', 
    './routes/gym-visits.js',
    './routes/groups.js',
    './routes/admin.js',
    './index.js'
  ]
};

// Generate swagger spec with error handling
let swaggerSpec;
try {
  swaggerSpec = swaggerJsdoc(swaggerOptions);
  console.log('✅ Swagger spec generated successfully');
} catch (error) {
  console.error('❌ Error generating swagger spec:', error.message);
  // Fallback minimal spec
  swaggerSpec = {
    openapi: '3.0.0',
    info: {
      title: 'GymTracker API',
      version: '1.0.0',
      description: 'A comprehensive API for the GymTracker iOS app (minimal spec due to loading error)'
    },
    servers: [
      {
        url: 'https://grithub-be.vercel.app',
        description: 'Production server'
      }
    ],
    paths: {
      '/health': {
        get: {
          summary: 'Health check',
          tags: ['Health'],
          responses: {
            '200': {
              description: 'API is healthy'
            }
          }
        }
      }
    }
  };
}

// Serve Swagger UI with CDN assets for better Vercel compatibility
app.get('/api-docs', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>GymTracker API Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
        <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@4.15.5/favicon-32x32.png" sizes="32x32" />
        <style>
          html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
          *, *:before, *:after { box-sizing: inherit; }
          body { margin:0; background: #fafafa; }
          .swagger-ui .topbar { display: none; }
        </style>
      </head>
      <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
        <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
        <script>
          window.onload = function() {
            const spec = ${JSON.stringify(swaggerSpec)};
            
            const ui = SwaggerUIBundle({
              spec: spec,
              dom_id: '#swagger-ui',
              deepLinking: true,
              presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
              ],
              plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
              ],
              layout: "StandaloneLayout",
              tryItOutEnabled: true,
              persistAuthorization: true,
              displayRequestDuration: true,
              docExpansion: "list",
              filter: true,
              showExtensions: true,
              showCommonExtensions: true
            });
          };
        </script>
      </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// Also serve at the root /api-docs/ path
app.get('/api-docs/', (req, res) => {
  res.redirect('/api-docs');
});

// Handle favicon request
app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // No content response for favicon
});

// Swagger JSON spec endpoint
app.get('/api-docs.json', (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  } catch (error) {
    console.error('Error serving swagger spec:', error);
    res.status(500).json({
      error: 'Failed to generate API documentation',
      message: 'There was an error generating the Swagger specification.'
    });
  }
});

// Debug swagger spec generation
app.get('/debug/swagger', (req, res) => {
  try {
    const spec = swaggerJsdoc(swaggerOptions);
    res.json({
      success: true,
      message: 'Swagger spec generated successfully',
      pathCount: Object.keys(spec.paths || {}).length,
      info: spec.info,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
  }
});

// Fallback manual swagger spec for debugging
app.get('/api-docs-simple.json', (req, res) => {
  const simpleSpec = {
    openapi: '3.0.0',
    info: {
      title: 'GymTracker API',
      version: '1.0.0',
      description: 'A comprehensive API for the GymTracker iOS app'
    },
    servers: [
      {
        url: 'https://grithub-be.vercel.app',
        description: 'Production server'
      }
    ],
    paths: {
      '/health': {
        get: {
          summary: 'Health check',
          tags: ['Health'],
          responses: {
            '200': {
              description: 'API is healthy'
            }
          }
        }
      },
      '/debug/routes': {
        get: {
          summary: 'Debug route loading status',
          tags: ['Debug'],
          responses: {
            '200': {
              description: 'Route status information'
            }
          }
        }
      }
    }
  };
  
  res.setHeader('Content-Type', 'application/json');
  res.send(simpleSpec);
});

// Simple manual swagger UI for debugging
app.get('/api-docs-simple', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>GymTracker API Documentation (Simple)</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
        <style>
          .swagger-ui .topbar { display: none; }
        </style>
      </head>
      <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
        <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
        <script>
          const spec = ${JSON.stringify(swaggerSpec)};
          
          SwaggerUIBundle({
            spec: spec,
            dom_id: '#swagger-ui',
            presets: [
              SwaggerUIBundle.presets.apis,
              SwaggerUIStandalonePreset
            ]
          });
        </script>
      </body>
    </html>
  `);
});

// Minimal test page for debugging Swagger UI issues
app.get('/api-docs-test', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Swagger UI Debug Test</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
        <style>
          .debug { background: #f0f0f0; padding: 10px; margin: 10px 0; border: 1px solid #ccc; }
          .swagger-ui .topbar { display: none; }
        </style>
      </head>
      <body>
        <div class="debug">
          <h2>Debug Information</h2>
          <p><strong>Page loaded:</strong> <span id="pageLoaded">❌</span></p>
          <p><strong>CSS loaded:</strong> <span id="cssLoaded">❌</span></p>
          <p><strong>JS loaded:</strong> <span id="jsLoaded">❌</span></p>
          <p><strong>Swagger spec loaded:</strong> <span id="specLoaded">❌</span></p>
          <p><strong>Swagger UI rendered:</strong> <span id="uiRendered">❌</span></p>
        </div>
        
        <div id="swagger-ui"></div>
        
        <script>
          document.getElementById('pageLoaded').innerHTML = '✅';
          
          // Test CSS loading
          const testEl = document.createElement('div');
          testEl.className = 'swagger-ui';
          document.body.appendChild(testEl);
          const computed = getComputedStyle(testEl);
          if (computed.fontFamily) {
            document.getElementById('cssLoaded').innerHTML = '✅';
          }
          document.body.removeChild(testEl);
        </script>
        
        <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js" onload="
          document.getElementById('jsLoaded').innerHTML = '✅';
          
          // Test spec loading
          fetch('/api-docs.json')
            .then(response => response.json())
            .then(spec => {
              document.getElementById('specLoaded').innerHTML = '✅';
              
              // Initialize Swagger UI
              const ui = SwaggerUIBundle({
                spec: spec,
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                  SwaggerUIBundle.presets.apis,
                  SwaggerUIStandalonePreset
                ],
                layout: 'StandaloneLayout',
                onComplete: () => {
                  document.getElementById('uiRendered').innerHTML = '✅';
                }
              });
            })
            .catch(error => {
              document.getElementById('specLoaded').innerHTML = '❌ ' + error.message;
            });
        " onerror="
          document.getElementById('jsLoaded').innerHTML = '❌ Script failed to load';
        "></script>
        <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
      </body>
    </html>
  `);
});

// Simple docs fallback
app.get('/docs', (req, res) => {
  res.send(`
    <html>
      <head><title>GymTracker API Documentation</title></head>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h1>GymTracker API Documentation</h1>
        <p>API documentation is available at the following endpoints:</p>
        <ul>
          <li><a href="/api-docs/">/api-docs/</a> - Interactive Swagger UI</li>
          <li><a href="/api-docs.json">/api-docs.json</a> - OpenAPI JSON spec</li>
          <li><a href="/health">/health</a> - Health check</li>
        </ul>
        <h2>Available Endpoints:</h2>
        <ul>
          <li><strong>Authentication:</strong> /api/auth/*</li>
          <li><strong>Users:</strong> /api/users/*</li>
          <li><strong>Gym Visits:</strong> /api/gym-visits/*</li>
          <li><strong>Groups:</strong> /api/groups/*</li>
          <li><strong>Admin:</strong> /api/admin/*</li>
        </ul>
      </body>
    </html>
  `);
});

// Routes
app.use('/api/auth', authLimiter);

// Import route modules with error handling
let routesLoaded = {
  auth: false,
  users: false,
  gymVisits: false,
  groups: false,
  admin: false
};

try {
  const authRoutes = require('./routes/auth');
  app.use('/api/auth', authRoutes);
  routesLoaded.auth = true;
  console.log('✅ Auth routes loaded');
} catch (error) {
  console.error('❌ Error loading auth routes:', error.message);
}

try {
  const userRoutes = require('./routes/users');
  app.use('/api/users', userRoutes);
  routesLoaded.users = true;
  console.log('✅ User routes loaded');
} catch (error) {
  console.error('❌ Error loading user routes:', error.message);
}

try {
  const gymVisitRoutes = require('./routes/gym-visits');
  app.use('/api/gym-visits', gymVisitRoutes);
  routesLoaded.gymVisits = true;
  console.log('✅ Gym visit routes loaded');
} catch (error) {
  console.error('❌ Error loading gym visit routes:', error.message);
}

try {
  const groupRoutes = require('./routes/groups');
  app.use('/api/groups', groupRoutes);
  routesLoaded.groups = true;
  console.log('✅ Group routes loaded');
} catch (error) {
  console.error('❌ Error loading group routes:', error.message);
}

try {
  const adminRoutes = require('./routes/admin');
  app.use('/api/admin', adminRoutes);
  routesLoaded.admin = true;
  console.log('✅ Admin routes loaded');
} catch (error) {
  console.error('❌ Error loading admin routes:', error.message);
  console.error('Admin route error stack:', error.stack);
}

console.log('📊 Routes loaded status:', routesLoaded);

// Debug endpoint to check routes status
app.get('/debug/routes', (req, res) => {
  res.json({
    message: 'Route loading status',
    routesLoaded: routesLoaded,
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Comprehensive status endpoint
app.get('/debug/status', (req, res) => {
  res.json({
    api: {
      name: 'GymTracker API',
      version: '1.0.0',
      status: 'running',
      timestamp: new Date().toISOString()
    },
    environment: {
      nodeEnv: process.env.NODE_ENV,
      databaseConfigured: !!process.env.DATABASE_URL,
      jwtConfigured: !!process.env.JWT_SECRET,
      vercelUrl: process.env.VERCEL_URL || 'not set'
    },
    routes: {
      loaded: routesLoaded,
      totalLoaded: Object.values(routesLoaded).filter(Boolean).length,
      totalExpected: Object.keys(routesLoaded).length
    },
    swagger: {
      specGenerated: !!swaggerSpec,
      pathCount: swaggerSpec?.paths ? Object.keys(swaggerSpec.paths).length : 0
    },
    endpoints: {
      health: '/health',
      docs: '/api-docs',
      auth: '/api/auth',
      users: '/api/users',
      gymVisits: '/api/gym-visits',
      groups: '/api/groups',
      admin: '/api/admin'
    }
  });
});

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
    jwt: process.env.JWT_SECRET ? 'configured' : 'not configured',
    // Debug info for troubleshooting
    debug: {
      databaseUrlLength: process.env.DATABASE_URL ? process.env.DATABASE_URL.length : 0,
      databaseUrlPrefix: process.env.DATABASE_URL ? process.env.DATABASE_URL.substring(0, 15) + '...' : 'not set',
      nodeEnv: process.env.NODE_ENV,
      vercelUrl: process.env.VERCEL_URL || 'not set'
    }
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
      groups: '/api/groups',
      admin: '/api/admin'
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
      groups: '/api/groups',
      admin: '/api/admin'
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