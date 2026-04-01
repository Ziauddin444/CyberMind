# CyberMind Sentinel - User Authentication System

## Overview
Your project now has a complete **file-based user authentication system** that allows users to:
- ✅ Sign in with existing accounts
- ✅ Create new accounts with registration form
- ✅ Secure passwords with bcrypt hashing
- ✅ Store user data persistently in `users.json`

---

## What Was Added

### 1. **Backend Improvements** (`backend/server.js`)

#### Dependencies Added
- **bcrypt** - For secure password hashing and verification

#### New Features
- **File-based User Database** - Users are now stored in `backend/users.json`
- **Password Hashing** - All passwords are hashed using bcrypt (10 salt rounds)
- **New Registration API Endpoint**
  ```
  POST /api/auth/register
  ```
  Accepts:
  - `username` - Unique username
  - `email` - User email
  - `password` - Min 6 characters
  - `confirmPassword` - Must match password
  - `name` - User's full name
  - `company` - Company name

- **Improved Login** - Now uses bcrypt to securely verify passwords
- **Validation** - Checks for existing usernames/emails, password matching, etc.

#### User Data Schema
```json
{
  "id": 1,
  "username": "admin",
  "password": "$2b$10$...", // bcrypt hashed
  "email": "admin@cybermind.com",
  "name": "Admin",
  "company": "Acme Bakery",
  "createdAt": "2025-01-15"
}
```

---

### 2. **Frontend Improvements**

#### HTML Updates (`frontend/index.html`)
- **Authentication Tabs**
  - "SIGN IN" tab for existing users
  - "CREATE ACCOUNT" tab for new registrations
- **Tab-based Form Switching** - Users can easily switch between login and signup
- **Enhanced Signup Form** with fields:
  - Full Name
  - Username
  - Email
  - Company
  - Password
  - Confirm Password

#### JavaScript Updates (`frontend/src/js/app.js`)
- **Tab Switching Logic** - `switchAuthTab()` function to toggle forms
- **Signup Handler** - `handleSignup()` function with:
  - Form validation
  - Error handling
  - Success feedback
  - Auto-login after registration
- **Form Clearing** - `clearAuthForms()` for security after logout
- **Event Listeners** - Wired up tab buttons and signup form

#### API Integration (`frontend/src/js/api.js`)
- **New Register Endpoint**
  ```javascript
  register(username, email, password, confirmPassword, name, company)
  ```

---

## Demo Credentials

You can test with these existing accounts:

| Username | Password | Name |
|----------|----------|------|
| admin | cybermind2025 | Admin |
| demo | demo123 | Demo User |
| zia | 123 | Zia |

Or create a new account directly in the app!

---

## File Structure

```
backend/
├── users.json          ← User database (created automatically)
├── server.js           ← Updated with bcrypt & registration
└── package.json        ← Updated with bcrypt dependency

frontend/
├── index.html          ← Added signup form & tabs
├── src/
│   └── js/
│       ├── app.js      ← Updated with signup handlers
│       └── api.js      ← Updated with register endpoint
```

---

## How to Use

### For Users - Creating an Account
1. Open the app and click "CREATE ACCOUNT" tab
2. Fill in the registration form with:
   - Full Name
   - Username (must be unique)
   - Email (must be unique)
   - Company
   - Password (min 6 characters)
   - Confirm Password
3. Click "CREATE ACCOUNT"
4. On success, automatically switched to login form with username pre-filled
5. Enter password and sign in

### For Developers - Testing the API

Register a new user:
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "new@example.com",
    "password": "password123",
    "confirmPassword": "password123",
    "name": "New User",
    "company": "My Company"
  }'
```

Login:
```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "password123"}'
```

---

## Security Features

✅ **Password Hashing** - bcrypt with 10 salt rounds  
✅ **Password Validation** - Min 6 characters, match confirmation  
✅ **Unique Constraints** - Duplicate username/email prevention  
✅ **Session Tokens** - 32-byte random tokens for auth  
✅ **File Persistence** - User data survives server restarts  
✅ **Input Validation** - All fields required for registration  

---

## Future Improvements (Ready to Switch to Google OAuth)

When you're ready to integrate Google OAuth:
1. You already have the file-based system as a fallback
2. The `users.json` can be extended with Google profile info
3. The API endpoints can be updated to accept OAuth tokens
4. No frontend changes needed - same login/signup flow

**Just tell me when you want to implement this!**

---

## Testing Checklist

- ✅ Register new user with valid data
- ✅ Attempt duplicate registration (username/email)
- ✅ Password mismatch error
- ✅ Login with new account
- ✅ Server restart - data persists in users.json
- ✅ Tab switching between login/signup
- ✅ Error messages display correctly
- ✅ Toast notifications on actions

---

## Database Persistence

All user data is stored in `backend/users.json`. This file:
- ✅ Is automatically created on first registration
- ✅ Persists data between server restarts
- ✅ Is overwritten safely with new user additions
- ✅ Can be manually edited (be careful with password hashes!)

---

**Ready to add more features! What would you like to improve next?**
