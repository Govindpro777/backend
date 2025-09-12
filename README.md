# Mental Health Platform Backend

A comprehensive Node.js + Express backend API for a mental health and content platform with user management, mood tracking, social features, and psychologist appointments.

## 🚀 Features

- **Authentication & Authorization**: JWT-based auth with OTP verification for email and phone
- **User Management**: Profile management, role-based access control (user, admin, superadmin)
- **Mental Health Tools**: Mood logging, analytics, questionnaires, daily feeling tracking
- **Social Features**: Posts, comments, polls with mood tagging and engagement
- **Professional Services**: Psychologist profiles, appointment booking system
- **Content Library**: Multimedia content with categorization and progress tracking
- **AI Chatbot**: Therapeutic chatbot service (extensible for LLM integration)
- **Admin Panel**: Content and user management with comprehensive controls

## 🛠️ Tech Stack

- **Runtime**: Node.js with Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT with bcrypt password hashing
- **Communication**: Nodemailer (email), Twilio integration (SMS)
- **Documentation**: Swagger/OpenAPI 3.0
- **Security**: Helmet, CORS, rate limiting
- **Logging**: Winston with structured logging
- **Validation**: Joi schema validation

## 📦 Installation

1. **Clone and setup**:
   ```bash
   npm install
   ```

2. **Environment configuration**:
   ```bash
   cp .env.example .env
   ```
   
   Update the `.env` file with your actual values:
   - MongoDB connection string
   - Email service credentials
   - JWT secret key
   - SMS provider settings (Twilio or mock)

3. **Initialize admin user**:
   ```bash
   npm run seed:admin
   ```

4. **Start the server**:
   ```bash
   npm run dev    # Development with nodemon
   npm start      # Production
   ```

## 📚 API Documentation

Interactive API documentation is available at: `http://localhost:8000/docs`

### Core Endpoints

**Authentication**:
- `POST /api/auth/signup` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/verify-contact-otp` - Verify phone OTP
- `POST /api/auth/verify-email-otp` - Verify email OTP

**User Management**:
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update profile
- `POST /api/users/change-password` - Change password

**Mental Health**:
- `POST /api/moods/log` - Log mood entry
- `GET /api/moods/history` - Get mood history
- `POST /api/feelings/today` - Submit daily feeling
- `GET /api/analytics/mood` - Get mood analytics

**Social Features**:
- `GET /api/posts` - Browse posts
- `POST /api/posts` - Create post
- `POST /api/posts/:id/like` - Like/unlike post
- `POST /api/polls` - Create poll
- `POST /api/polls/:id/vote` - Vote on poll

**Professional Services**:
- `GET /api/psychologists` - Browse psychologists
- `POST /api/appointments` - Book appointment
- `GET /api/appointments/my` - Get user appointments

**Content Library**:
- `GET /api/content` - Browse content
- `POST /api/content/:id/like` - Like content
- `POST /api/content/:id/complete` - Mark as completed

**AI Services**:
- `POST /api/chatbot/chat` - Chat with AI therapist

## 🔐 Authentication

The API uses JWT Bearer tokens for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### User Roles

- **user**: Standard user access
- **admin**: Administrative privileges
- **superadmin**: Full system access

## 📊 Database Schema

### Core Models

- **User**: User accounts with profile information
- **Post**: Social posts with mood tagging and engagement
- **Comment**: Post comments with threading support
- **Poll**: Community polls with voting system
- **MoodLog**: Daily mood tracking with emotions and notes
- **FeelingToday**: Simple daily feeling submissions
- **Psychologist**: Professional profiles with availability schedules
- **Appointment**: Booking system for user-psychologist sessions
- **ContentLibrary**: Multimedia content with categorization
- **Questionnaire**: Mental health assessments with responses

## 🔄 OTP Verification Flow

1. User registers with email, phone, and profile info
2. System sends OTP to phone number (SMS)
3. User verifies phone OTP
4. System sends OTP to email address
5. User verifies email OTP
6. If user < 18: parent consent required with additional OTP
7. Account activated after successful verification

## 🏥 Appointment System

- Psychologists have configurable schedules (Mon-Sat)
- Users can view available time slots
- Booking prevents conflicts automatically
- Support for cancellation with reason tracking
- Session notes and rating system

## 📈 Analytics & Insights

- **Mood Trends**: Daily and weekly mood tracking
- **Streak Tracking**: Current and longest streaks
- **Emotion Analysis**: Frequency and pattern analysis
- **Personalized Insights**: AI-generated recommendations
- **Progress Tracking**: Content completion and engagement metrics

## 🤖 AI Chatbot

Extensible chatbot service with:
- Rule-based response system (current)
- Intent recognition and context awareness
- Session management and history
- Easy integration point for LLM services (GPT, Claude, etc.)

## 🛡️ Security Features

- **Password Security**: Bcrypt hashing with salt rounds
- **JWT Tokens**: Secure token-based authentication
- **Rate Limiting**: Request throttling to prevent abuse
- **CORS Protection**: Cross-origin request security
- **Helmet Security**: HTTP security headers
- **Input Validation**: Joi schema validation for all inputs
- **SQL Injection Prevention**: Mongoose ODM protection

## 📁 Project Structure

```
/src
  /config          # Configuration files (DB, JWT, email, SMS)
  /controllers     # Request handlers and business logic
  /middlewares     # Authentication, validation, error handling
  /models          # MongoDB schemas and models
  /routes          # API route definitions
  /services        # Business logic and external integrations
  /utils           # Utility functions and helpers
  /docs            # Swagger/OpenAPI documentation
  /seed            # Database seeding scripts
app.js             # Express application setup
server.js          # Server initialization and startup
```

## 🌐 Environment Variables

Key environment variables (see `.env.example`):

- `MONGO_URL`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT signing
- `EMAIL_USER/EMAIL_PASS`: Email service credentials
- `TWILIO_*`: SMS service configuration
- `ADMIN_EMAIL/ADMIN_PASSWORD`: Default admin credentials

## 🧪 Development

**Start development server**:
```bash
npm run dev
```

**Create admin user**:
```bash
npm run seed:admin
```

**Run tests**:
```bash
npm test
```

## 📋 API Response Format

All API responses follow a consistent format:

```json
{
  "success": true,
  "data": { /* response data */ },
  "message": "Operation successful",
  "errors": null,
  "timestamp": "2025-01-27T10:30:00.000Z"
}
```

## 🚀 Deployment

The application is production-ready with:
- Environment-based configuration
- Comprehensive error handling
- Security middleware
- Graceful shutdown handling
- Health check endpoints

For production deployment, ensure:
- Set `NODE_ENV=production`
- Configure production MongoDB cluster
- Set strong JWT secrets
- Configure real email/SMS providers
- Enable HTTPS

## 📞 Support

For technical support or questions about the API, refer to the Swagger documentation at `/docs` or contact the development team.