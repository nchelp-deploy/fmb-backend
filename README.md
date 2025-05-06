# FundMeBank Backend

This is the backend API for the FundMeBank platform. It provides secure authentication (local and Google OAuth), user management, admin controls, and personalized dashboard content for each user. The backend is designed for a mobile-first, multi-user banking web app.

## Technologies Used
- **Node.js** & **Express** (API server)
- **MongoDB Atlas** (cloud database)
- **Mongoose** (MongoDB ODM)
- **Passport.js** (Google OAuth 2.0)
- **JWT** (JSON Web Tokens for authentication)
- **bcrypt** (password hashing)
- **express-rate-limit** (rate limiting for security)
- **express-validator** (input validation)
- **CORS** (cross-origin resource sharing)
- **dotenv** (environment variable management)

## Features
- User registration and login (username/password or Google)
- Secure password storage (bcrypt)
- JWT-based authentication for API access
- Google OAuth 2.0 login/signup
- Admin role and endpoints for user management
- Personalized dashboard content per user (set by admin)
- Rate limiting and input validation for security

## Setup Instructions
1. **Clone the repository** and `cd` into `fmb-backend`.
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Create a `.env` file** in the backend root:
   ```env
   MONGO_URI=your_mongodb_atlas_connection_string
   JWT_SECRET=yourSuperSecretKeyHere
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   PORT=5000
   ```
4. **Set up Google OAuth credentials:**
   - Go to [Google Cloud Console](https://console.developers.google.com/)
   - Create a project, enable OAuth, and set the redirect URI to:
     `http://localhost:5000/api/auth/google/callback`
   - Copy your client ID and secret into `.env`.
5. **Start the server:**
   ```bash
   npm start
   ```
6. **API Endpoints:**
   - `POST /api/auth/signup` — Register with username, password, email
   - `POST /api/auth/login` — Login with username and password
   - `GET /api/auth/google` — Start Google OAuth login
   - `GET /api/auth/google/callback` — Google OAuth callback
   - `GET /api/dashboard` — Get personalized dashboard (JWT required)
   - `GET /api/admin/users` — Admin: list users
   - `PUT /api/admin/users/:id` — Admin: update user content

## Security Notes
- Passwords are hashed with bcrypt before storage.
- JWTs are used for stateless authentication.
- Rate limiting and input validation are enabled.
- Never commit your `.env` file or secrets to version control.
- Use HTTPS in production.

## Disclaimer
**This project is for educational and advanced demonstration purposes only.**
User data is stored in a database. Do not use real banking credentials or sensitive information. This is not a production banking product.

---

For questions or contributions, please contact the project maintainer. 