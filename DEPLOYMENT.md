# GymTracker API - Vercel Deployment Guide

## Prerequisites

1. A Vercel account (https://vercel.com)
2. A NeonDB database (or any PostgreSQL database)
3. The Vercel CLI installed (optional but recommended)

## Step 1: Prepare Your Repository

Make sure your backend code is in a Git repository and pushed to GitHub, GitLab, or Bitbucket.

## Step 2: Environment Variables

You'll need to set up the following environment variables in your Vercel project:

### Required Environment Variables:

```
DATABASE_URL=postgresql://username:password@hostname/database?sslmode=require
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRES_IN=7d
NODE_ENV=production
```

### Optional Environment Variables:

```
FRONTEND_URL=https://your-frontend-domain.com
```

## Step 3: Deploy to Vercel

### Option A: Using Vercel Dashboard

1. Go to https://vercel.com/dashboard
2. Click "New Project"
3. Import your repository
4. Set the root directory to `backend` (if your backend is in a subdirectory)
5. Vercel will automatically detect it's a Node.js project
6. Add your environment variables in the "Environment Variables" section
7. Click "Deploy"

### Option B: Using Vercel CLI

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Navigate to your backend directory:
   ```bash
   cd backend
   ```

3. Login to Vercel:
   ```bash
   vercel login
   ```

4. Deploy:
   ```bash
   vercel --prod
   ```

5. Follow the prompts and add environment variables when asked

## Step 4: Configure Environment Variables

After deployment, you need to add your environment variables:

1. Go to your project dashboard on Vercel
2. Navigate to Settings → Environment Variables
3. Add each variable with appropriate values:

   - `DATABASE_URL`: Your NeonDB connection string
   - `JWT_SECRET`: A strong, random secret key
   - `JWT_EXPIRES_IN`: Token expiration time (e.g., "7d")
   - `NODE_ENV`: Set to "production"
   - `FRONTEND_URL`: Your frontend domain (optional)

## Step 5: Verify Deployment

1. Visit your Vercel URL (e.g., https://your-project-name.vercel.app)
2. Check the health endpoint: `https://your-project-name.vercel.app/health`
3. View API documentation: `https://your-project-name.vercel.app/api-docs`

## File Structure

Your backend should have this structure for Vercel:

```
backend/
├── index.js          # Vercel entry point (created)
├── server.js          # Original server file
├── vercel.json        # Vercel configuration (created)
├── package.json       # Dependencies
├── db.js             # Database connection
├── routes/           # API routes
│   ├── auth.js
│   ├── users.js
│   ├── gym-visits.js
│   └── groups.js
└── middleware/       # Custom middleware
    └── auth.js
```

## Important Notes

1. **Database Connection**: Make sure your database allows connections from Vercel's IP ranges
2. **CORS**: The API is configured to accept requests from common origins, but you may need to adjust based on your frontend domain
3. **Rate Limiting**: Rate limits are configured for production use
4. **Swagger Documentation**: Available at `/api-docs` endpoint
5. **Health Check**: Available at `/health` endpoint

## Troubleshooting

### Common Issues:

1. **Database Connection Errors**:
   - Verify your `DATABASE_URL` is correct
   - Check if your database allows external connections
   - Ensure SSL is properly configured

2. **Environment Variables Not Loading**:
   - Make sure variables are set in Vercel dashboard
   - Redeploy after adding new variables

3. **CORS Issues**:
   - Add your frontend domain to the CORS configuration
   - Use the `FRONTEND_URL` environment variable

4. **Function Timeout**:
   - Vercel functions have a 30-second timeout limit
   - Optimize database queries if needed

## Custom Domain (Optional)

To use a custom domain:

1. Go to your project settings in Vercel
2. Navigate to the "Domains" section
3. Add your custom domain
4. Configure DNS as instructed by Vercel

## Monitoring

- Check function logs in the Vercel dashboard
- Use the `/health` endpoint for monitoring
- Monitor database performance through your database provider's dashboard

## Updates

To update your API:

1. Push changes to your repository
2. Vercel will automatically redeploy
3. Or manually trigger a deployment from the Vercel dashboard 