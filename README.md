# GymTracker Backend API

A Node.js Express API server for the GymTracker iOS app, using NeonDB (PostgreSQL) for data storage.
This will be connected (optionally) with Vercel.

## 🚀 Quick Start

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- NeonDB account and database
- PostgreSQL client (for database setup)

### 1. Install Dependencies

```bash
cd backend
npm install
```

### 2. Set Up Environment Variables

Create a `.env` file in the backend directory:

```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@host/database?sslmode=require

# JWT Configuration  
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Server Configuration
PORT=3000
NODE_ENV=development
```

### 3. Set Up Database

First, make sure your NeonDB database is set up with the schema:

```bash
# From the project root directory
./database/deploy.sh "your-neondb-connection-string"
```

Or manually apply the schema:

```bash
psql "your-neondb-connection-string" -f ../database/schema.sql
```

### 4. Start the Server

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
```

The API will be available at `http://localhost:3000`

## 📖 API Documentation

Interactive Swagger UI documentation is available at:
- **Local**: `http://localhost:3000/api-docs`
- **Production**: `https://your-api-domain.com/api-docs`

The Swagger UI provides:
- Interactive API testing
- Complete endpoint documentation
- Request/response examples
- Authentication testing with JWT tokens

## 📡 API Endpoints

### Health Check
- `GET /health` - Server health status
- `GET /` - API information and available endpoints

### Authentication
- `POST /api/auth/signup` - Create new user account
- `POST /api/auth/signin` - Sign in existing user
- `POST /api/auth/signout` - Sign out user
- `GET /api/auth/me` - Get current user info
- `POST /api/auth/reset-password` - Request password reset

### Users
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `GET /api/users/stats` - Get user statistics
- `DELETE /api/users/account` - Delete user account

### Gym Visits
- `POST /api/gym-visits` - Record new gym visit
- `GET /api/gym-visits` - Get user's gym visits
- `GET /api/gym-visits/today` - Get today's visits
- `GET /api/gym-visits/heatmap` - Get heatmap data
- `PUT /api/gym-visits/:id` - Update gym visit
- `DELETE /api/gym-visits/:id` - Delete gym visit

### Groups
- `GET /api/groups` - Groups endpoints (coming soon)

## 🔐 Authentication

The API uses JWT (JSON Web Tokens) for authentication:

1. **Sign up/Sign in**: Returns a JWT token
2. **Protected routes**: Require `Authorization: Bearer <token>` header
3. **Session management**: Tokens are stored in the database with expiration
4. **Auto-cleanup**: Expired sessions are automatically cleaned up

### Example Authentication Flow

```bash
# 1. Sign up
curl -X POST http://localhost:3000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"password123"}'

# 2. Use the returned token for protected routes
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/users/profile
```

## 📊 Database Schema

The API works with the following main tables:

- **users** - User accounts and profile data
- **gym_visits** - Individual gym check-ins
- **groups** - User groups/communities
- **group_members** - Group membership relationships
- **user_sessions** - Authentication sessions
- **leaderboard_entries** - Competition data

See the [database documentation](../database/README.md) for complete schema details.

## 🛠️ Development

### Project Structure

```
backend/
├── server.js           # Main server file
├── package.json        # Dependencies and scripts
├── routes/            # API route handlers
│   ├── auth.js        # Authentication routes
│   ├── users.js       # User management routes
│   ├── gym-visits.js  # Gym visit routes
│   └── groups.js      # Group routes
├── middleware/        # Express middleware
│   └── auth.js        # JWT authentication middleware
└── README.md          # This file
```

### Available Scripts

```bash
npm start      # Start production server
npm run dev    # Start development server with auto-reload
npm test       # Run tests (to be implemented)
```

### Adding New Endpoints

1. Create route handler in appropriate file under `routes/`
2. Add validation using `express-validator`
3. Use `authenticateToken` middleware for protected routes
4. Update this README with new endpoint documentation

## 🔒 Security Features

- **Rate Limiting**: Prevents brute force attacks
- **Helmet.js**: Security headers
- **CORS**: Configurable cross-origin requests
- **Input Validation**: All inputs validated and sanitized
- **Password Hashing**: bcrypt with salt rounds
- **Session Management**: Secure JWT tokens with expiration
- **SQL Injection Protection**: Parameterized queries

## 🚀 Deployment

### Environment Variables for Production

```bash
DATABASE_URL=your-production-neondb-url
JWT_SECRET=your-very-long-random-secret-key
NODE_ENV=production
PORT=3000
```

### Deploy to Heroku

1. Create Heroku app:
```bash
heroku create your-gymtracker-api
```

2. Set environment variables:
```bash
heroku config:set DATABASE_URL="your-neondb-url"
heroku config:set JWT_SECRET="your-secret-key"
heroku config:set NODE_ENV=production
```

3. Deploy:
```bash
git push heroku main
```

### Deploy to Railway/Render

1. Connect your GitHub repository
2. Set environment variables in the dashboard
3. Deploy automatically on push

### Deploy to VPS

1. Copy files to server
2. Install dependencies: `npm install --production`
3. Set up environment variables
4. Use PM2 for process management:
```bash
npm install -g pm2
pm2 start server.js --name gymtracker-api
pm2 startup
pm2 save
```

## 📱 iOS App Integration

Update your iOS app's API base URL:

```swift
// In APIService.swift
init(baseURL: String = "https://your-api-domain.com/api") {
    self.baseURL = baseURL
}
```

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check your DATABASE_URL format
   - Ensure your IP is whitelisted in NeonDB
   - Verify SSL mode is set to `require`

2. **JWT Token Errors**
   - Make sure JWT_SECRET is set
   - Check token format in Authorization header
   - Verify token hasn't expired

3. **CORS Issues**
   - Update CORS origins in server.js
   - Check request headers from iOS app

### Debug Mode

Set `NODE_ENV=development` for detailed error messages and stack traces.

### Logs

Check server logs for detailed error information:
```bash
# If using PM2
pm2 logs gymtracker-api

# Direct node execution
node server.js
```

## 📞 Support

- Database Issues: Check [database documentation](../database/README.md)
- API Issues: Review server logs and error responses
- iOS Integration: Verify API endpoints and request format

## 🔄 Version History

- **v1.0.0** - Initial release with authentication and gym visit tracking
- Future: Group management, leaderboards, push notifications 