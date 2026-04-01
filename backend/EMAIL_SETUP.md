# Email Configuration Guide

## Current Mode: DEMO (Console Logging)
The system is currently running in **DEMO mode** - all emails are logged to the console instead of being sent.

## Switch to Real Email Sending

### Option 1: Gmail (Recommended - Free)

1. **Enable Gmail App Password**
   - Go to [Google Account Security](https://myaccount.google.com/security)
   - Enable 2-Step Verification (if not already enabled)
   - Go to App Passwords
   - Select "Mail" and "Windows Computer" (or your device)
   - Google will generate a 16-character app password

2. **Set Environment Variables**
   ```bash
   export EMAIL_METHOD=gmail
   export EMAIL_USER=your-email@gmail.com
   export EMAIL_PASSWORD="xxxx xxxx xxxx xxxx"  # 16-char app password
   export EMAIL_FROM=your-email@gmail.com
   ```

3. **Or create `.env` file in `/backend` folder:**
   ```env
   EMAIL_METHOD=gmail
   EMAIL_USER=your@gmail.com
   EMAIL_PASSWORD=your app password here
   EMAIL_FROM=your@gmail.com
   ```

4. **Restart the server** - it will now send real emails via Gmail

---

### Option 2: SendGrid (Professional)

1. **Get SendGrid API Key**
   - Sign up at [SendGrid.com](https://sendgrid.com)
   - Create API key in Settings
   - Copy the key

2. **Set Environment Variables**
   ```bash
   export EMAIL_METHOD=sendgrid
   export SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxx
   export EMAIL_FROM=noreply@yourdomain.com
   ```

3. **Or create `.env` file:**
   ```env
   EMAIL_METHOD=sendgrid
   SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxx
   EMAIL_FROM=noreply@yourdomain.com
   ```

4. **Restart the server** - it will now send via SendGrid

---

### Option 3: Keep DEMO Mode (Current)

The system logs all emails to console. Verification codes are shown in the console output:

```
============================================================
[EMAIL - DEMO MODE]
To: user@example.com
Subject: Verify Your CyberMind Account
Verification Code: ABC12345
Full Token: abc12345def67890ghi12345jkl67890
============================================================
```

Users can:
1. See the code displayed in browser (in dev mode)
2. See it in server console logs
3. Check email in test file (future implementation)

---

## Frontend Configuration (Optional)

If you want the frontend to display the email in DEMO mode:

1. Add to browser's `localStorage`: `skipEmailVerification=true`
2. Auto-verify on signup without requiring code
3. Or display the code in a demo banner

Currently, the frontend shows: **"Check your email for verification code"**

---

## Testing with Real Email (Gmail Example)

```bash
# In backend folder
export EMAIL_METHOD=gmail
export EMAIL_USER=your@gmail.com
export EMAIL_PASSWORD="16-char-app-password"
npm start

# Now:
# 1. Register new account
# 2. Check your email inbox
# 3. Enter the verification code in the app
# 4. Login successfully
```

---

## Current Email Templates

### Verification Email
- Clean, branded design
- Shows 8-character verification code
- Indicates 24-hour expiration
- Matches CyberMind branding (black/yellow)

### Password Reset Email
- Similar design
- Shows 6-digit reset code
- Indicates 15-minute expiration
- Clear security messaging

---

## Troubleshooting

### "Failed to send email: Invalid login"
- ✅ Check Gmail app password is correct (16 chars with spaces)
- ✅ Verify 2-Step Authentication is enabled
- ✅ Use app password, NOT regular password

### "SendGrid API key invalid"  
- ✅ Get key from SendGrid dashboard (starts with "SG.")
- ✅ Make sure key hasn't expired
- ✅ Use "Send" permission level minimum

### Emails going to spam
- ✅ Add SPF/DKIM records in your DNS
- ✅ Use a branded "From" email
- ✅ Send from real domain (not generic)

### Still seeing DEMO mode?
- ✅ Check `EMAIL_METHOD` environment variable is set
- ✅ Restart the server after changing env vars
- ✅ Check for typos in email/password

---

## Next Steps

Ready to use real email? Just:
1. Pick Gmail or SendGrid
2. Get your credentials
3. Set environment variables
4. Restart server
5. Test signup → should receive real email ✅
