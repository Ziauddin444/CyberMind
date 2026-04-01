# CyberMind Sentinel

> **Enterprise-Grade Security Platform for SMEs**  
> A comprehensive security management and device monitoring system designed to protect small and medium-sized enterprises from cyber threats.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Active-brightgreen)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Email Setup](#email-setup)
- [Database](#database)
- [User Roles](#user-roles)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

---

## 🎯 Overview

**CyberMind Sentinel** is a modern, full-stack security platform that provides SMEs with tools to:
- Manage user authentication and authorization securely
- Monitor and manage connected devices
- Receive security alerts and notifications
- Reset passwords safely with email verification
- Maintain audit logs of security events

The platform combines a responsive React frontend with a robust Express.js backend, featuring industry-standard security practices including bcrypt password hashing and JWT token authentication.

---

## ✨ Features

### Authentication & User Management
- ✅ **Secure Registration** - Create accounts with email verification
- ✅ **Login System** - Session-based authentication with JWT tokens
- ✅ **Password Hashing** - Bcrypt encryption (10 salt rounds)
- ✅ **Password Recovery** - Secure password reset flow via email
- ✅ **Profile Management** - Update user information and preferences
- ✅ **Session Management** - Automatic token expiration and refresh

### Device Management
- 📱 **Device Monitoring** - Track connected devices and security status
- 🔧 **Device Configuration** - Manage device settings
- 📧 **Alert System** - Real-time notifications for security events

### Security Features
- 🔒 **JWT Authentication** - Stateless, secure token-based auth
- 🛡️ **CORS Protection** - Cross-Origin Resource Sharing configured
- 📧 **Email Verification** - Confirm user identities via email
- 🔐 **Password Strength** - Minimum 6 characters with validation
- 📝 **Audit Logging** - Track user actions and security events

### User Experience
- 🎨 **Modern UI** - Clean, responsive design built with Tailwind CSS
- ⚡ **Real-time Updates** - Dynamic dashboard with live data
- 📊 **Interactive Dashboard** - Visual analytics and device status
- 🔔 **Toast Notifications** - User feedback for actions
- 🌙 **Professional Design** - Dark theme optimized for security contexts

---

## 🛠️ Tech Stack

### Frontend
- **Vite** (v6.2.0) - Next-generation build tool
- **Tailwind CSS** - Utility-first CSS framework
- **Font Awesome 6** - Icon library
- **Vanilla JavaScript** - Core application logic
- **Modern ES6+** - Latest JavaScript features

### Backend
- **Node.js** - JavaScript runtime
- **Express.js** (v4.21.0) - Web application framework
- **bcrypt** (v5.1.1) - Password hashing library
- **Nodemailer** (v8.0.4) - Email service integration
- **CORS** (v2.8.5) - Cross-origin request handling

### Data Storage
- **JSON File Database** - `users.json` for persistent data
- **In-Memory Sessions** - Temporary session management

---

## 📁 Project Structure

```
CyberMind/
├── README.md                          # Project documentation
├── AUTHENTICATION_SETUP.md            # Auth system guide
├── cybermind.html                     # Main HTML entry point
│
├── backend/
│   ├── server.js                      # Express server & API routes
│   ├── email.js                       # Email service configuration
│   ├── users.json                     # User database (created at runtime)
│   ├── package.json                   # Backend dependencies
│   ├── EMAIL_SETUP.md                 # Email configuration guide
│   └── node_modules/                  # Dependencies
│
└── frontend/
    ├── package.json                   # Frontend dependencies
    ├── vite.config.js                 # Vite configuration
    ├── index.html                     # Frontend entry point
    └── src/
        ├── css/
        │   └── styles.css             # Custom styles
        └── js/
            ├── app.js                 # Main application logic
            └── api.js                 # API service layer
```

---

## 📦 Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v14.0.0 or higher) - [Download](https://nodejs.org/)
- **npm** (v6.0.0 or higher) - Comes with Node.js
- **Git** (optional) - [Download](https://git-scm.com/)
- **A modern web browser** - Chrome, Firefox, Safari, or Edge

Check your versions:
```bash
node --version
npm --version
```

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/CyberMind.git
cd CyberMind
```

### 2. Install Backend Dependencies
```bash
cd backend
npm install
cd ..
```

### 3. Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### 4. Create Environment Configuration (Optional)
Create a `.env` file in the `backend` folder for email configuration:
```env
# Email Configuration
EMAIL_METHOD=demo  # Options: demo, gmail, sendgrid
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=noreply@yourdomain.com

# Server Configuration
PORT=3001
NODE_ENV=development
```

---

## ⚙️ Configuration

### Email Setup

The system supports three email modes:

#### 1. **DEMO Mode** (Default)
Email logs to console instead of sending:
```bash
# No configuration needed - it's the default
```

#### 2. **Gmail** (Recommended)
```bash
# Generate app password in Google Account Security
export EMAIL_METHOD=gmail
export EMAIL_USER=your-email@gmail.com
export EMAIL_PASSWORD="your-16-char-app-password"
```

#### 3. **SendGrid** (Professional)
```bash
export EMAIL_METHOD=sendgrid
export SENDGRID_API_KEY=SG.your_api_key_here
export EMAIL_FROM=noreply@yourdomain.com
```

For detailed email setup instructions, see [EMAIL_SETUP.md](backend/EMAIL_SETUP.md).

### Backend Server Configuration
- **Default Port**: `3001`
- **Modify**: Edit `PORT` variable in [backend/server.js](backend/server.js)

### CORS Configuration
The backend allows requests from:
- `http://localhost:5173` (Vite dev server)
- `http://localhost:3000` (Alternative frontend port)

---

## 🎮 Running the Application

### Option 1: Development Mode (Recommended)

#### Terminal 1 - Start Backend Server
```bash
cd backend
npm start
# Server runs on http://localhost:3001
```

#### Terminal 2 - Start Frontend Dev Server
```bash
cd frontend
npm run dev
# Frontend runs on http://localhost:5173
```

Then open your browser to: **http://localhost:5173**

### Option 2: Production Build

#### Build Frontend
```bash
cd frontend
npm run build
# Creates optimized build in dist/ folder
```

#### Preview Production Build
```bash
# Still in frontend folder
npm run preview
```

### Using the Standalone HTML Version

The project includes a standalone version (`cybermind.html`) that can be opened directly in a browser:

```bash
# Simply open in browser
open cybermind.html
# Or use Python server for better compatibility
python -m http.server 8000
# Then visit http://localhost:8000/cybermind.html
```

---

## 🔌 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Body |
|--------|----------|-------------|------|
| POST | `/api/auth/register` | Create new account | `username, email, password, confirmPassword, name, company` |
| POST | `/api/auth/login` | User login | `username, password` |
| GET | `/api/auth/verify` | Check session validity | - |
| POST | `/api/auth/logout` | End session | - |
| POST | `/api/auth/verify-email` | Confirm email | `token` |
| POST | `/api/auth/forgot-password` | Request password reset | `email` |
| POST | `/api/auth/reset-password` | Reset password | `email, resetCode, newPassword, confirmPassword` |
| GET | `/api/auth/profile` | Get user profile | - |
| PUT | `/api/auth/profile` | Update profile | User data |
| POST | `/api/auth/change-password` | Change password | `currentPassword, newPassword, confirmPassword` |

### Device Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all devices |
| POST | `/api/devices` | Create new device |
| PUT | `/api/devices/:id` | Update device |
| DELETE | `/api/devices/:id` | Delete device |

---

## 🔐 Authentication

### Login Flow
1. User enters credentials on login form
2. Backend validates username and password against `users.json`
3. Passwords verified using bcrypt comparison
4. JWT token generated on successful login
5. Token stored in browser localStorage as `cybermind_token`
6. Token sent with subsequent API requests in Authorization header

### Authorization
All protected endpoints require:
```
Authorization: Bearer <jwt_token>
```

### Session Expiration
- Tokens expire after inactivity
- Automatic logout on token expiration
- User redirected to login screen

### Password Security
- Minimum 6 characters required
- Hashed with bcrypt (10 salt rounds)
- Never stored in plain text
- Password confirmation required on registration and reset

---

## 📧 Email System

### Supported Operations
1. **Email Verification** - Confirm new user accounts
2. **Password Reset** - Secure password recovery
3. **Notifications** - Alert users of security events

### Email Configuration Guide
See [EMAIL_SETUP.md](backend/EMAIL_SETUP.md) for detailed instructions on:
- Enabling Gmail
- Setting up SendGrid
- Testing email functionality
- Troubleshooting email issues

---

## 💾 Database

### Data Storage
User data is stored in `backend/users.json`:

```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "password": "$2b$10$...",
      "email": "admin@cybermind.com",
      "name": "Admin User",
      "company": "Acme Corp",
      "createdAt": "2025-01-15",
      "emailVerified": true
    }
  ]
}
```

### User Schema
| Field | Type | Description |
|-------|------|-------------|
| `id` | Number | Unique user identifier |
| `username` | String | Unique login username |
| `password` | String | Bcrypt hashed password |
| `email` | String | User email address |
| `name` | String | Full name |
| `company` | String | Company/Organization name |
| `createdAt` | String | Account creation date |
| `emailVerified` | Boolean | Email verification status |

### Backups
Regularly backup `backend/users.json` to prevent data loss.

---

## 👥 User Roles

Currently, the system supports:

### Standard User
- Full access to personal dashboard
- Device management
- Profile editing
- Password changes

### Admin (Future)
Planned features:
- User management
- System settings
- Analytics and reporting

---

## 🛡️ Security Features

- ✅ **Password Hashing** - Bcrypt with 10 salt rounds
- ✅ **JWT Tokens** - Stateless authentication
- ✅ **HTTPS Ready** - Supports secure connections
- ✅ **CORS Protection** - Restricted origin access
- ✅ **Input Validation** - Sanitized user inputs
- ✅ **SQL Injection Protection** - No database queries (JSON storage)
- ✅ **XSS Protection** - Content Security Policy ready
- ✅ **Session Management** - Automatic timeout
- ✅ **Email Verification** - Account confirmation
- ✅ **Audit Logging** - Track user actions

### Best Practices
1. Always use HTTPS in production
2. Set strong environment variables
3. Keep dependencies updated
4. Regularly backup user data
5. Monitor server logs
6. Enable email verification for new accounts

---

## 🐛 Troubleshooting

### Frontend won't load
```bash
# Clear frontend cache and rebuild
cd frontend
rm -rf node_modules dist
npm install
npm run dev
```

### Backend won't start
```bash
# Check if port 3001 is in use
lsof -i :3001
# Kill process if needed
kill -9 <PID>
# Restart server
npm start
```

### Email not sending
1. Check EMAIL_SETUP.md for configuration
2. Verify internet connection
3. Check server logs for errors
4. Test with DEMO mode first

### CORS errors
- Ensure frontend and backend are running
- Check CORS configuration in [backend/server.js](backend/server.js)
- Verify browser developer console for specific errors

### Users.json not found
- Restart backend server to auto-create the file
- Ensure backend folder has write permissions
- Check disk space availability

---

## 📚 Documentation

- [Authentication Setup Guide](AUTHENTICATION_SETUP.md) - Complete auth system documentation
- [Email Configuration Guide](backend/EMAIL_SETUP.md) - Email service setup and troubleshooting
- [API Documentation](#api-endpoints) - Detailed endpoint reference

---

## 🐾 Getting Started - Quick Start

### 5-Minute Setup
```bash
# 1. Clone repo
git clone <repo-url> && cd CyberMind

# 2. Install dependencies
cd backend && npm install && cd ..
cd frontend && npm install && cd ..

# 3. Terminal 1 - Backend
cd backend && npm start

# 4. Terminal 2 - Frontend
cd frontend && npm run dev

# 5. Open browser
# Visit http://localhost:5173
# Default Login: admin / admin123
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Standards
- Use consistent indentation (2 spaces)
- Write descriptive commit messages
- Test changes before submitting PR
- Follow existing code style

---

## 📞 Support

Need help? Here's how to get support:

- 📖 **Read Documentation** - Check [Authentication](AUTHENTICATION_SETUP.md) and Email setup guides
- 🐛 **Report Bugs** - Open an issue with detailed reproduction steps
- 💡 **Request Features** - Submit feature requests in discussions
- 📧 **Email Support** - Contact maintainers directly

---

## 📄 License

This project is licensed under the **MIT License** - see the LICENSE file for details.

You are free to use this project for personal, commercial, and open-source purposes.

---

## 🙏 Acknowledgments

- Built with [Express.js](https://expressjs.com/)
- Styled with [Tailwind CSS](https://tailwindcss.com/)
- Bundled with [Vite](https://vitejs.dev/)
- Secured with [bcrypt](https://github.com/kelektiv/node.bcrypt.js)
- Icons from [Font Awesome](https://fontawesome.com/)

---

## 📊 Project Status

- ✅ Authentication System - Complete
- ✅ User Registration - Complete
- ✅ Email System - Complete
- ✅ Device Management - In Progress
- ⏳ Advanced Analytics - Planned
- ⏳ Admin Dashboard - Planned
- ⏳ Mobile App - Planned

---

## 🎯 Roadmap

### v1.1 (Next Release)
- Enhanced device analytics
- Custom dashboards
- Role-based access control (RBAC)

### v1.2 (Future)
- Mobile app (React Native)
- Advanced threat detection
- API rate limiting

### v2.0 (Long-term)
- Machine learning alerts
- Blockchain audit logs
- Enterprise integrations

---

## 📮 Contact

- **Email**: your-email@example.com
- **GitHub**: [@yourusername](https://github.com/yourusername)
- **Twitter**: [@yourhandle](https://twitter.com/yourhandle)

---

<div align="center">

**[⬆ Back to Top](#cybermind-sentinel)**

Made with ❤️ for cybersecurity

© 2025 CyberMind Sentinel. All rights reserved.

</div>
