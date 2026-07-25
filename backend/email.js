// ─── Email Configuration & Sending ──────────────────────────────────────────

const nodemailer = require('nodemailer');

// Configuration - supports multiple email methods
const EMAIL_CONFIG = {
  // METHOD OPTIONS: 'gmail', 'sendgrid', 'console' (demo mode)
  method: process.env.EMAIL_METHOD || 'console',

  // GMAIL: Set EMAIL_USER and EMAIL_PASSWORD (app password, not real password)
  // Example: EMAIL_USER=your@gmail.com EMAIL_PASSWORD=xxxx xxxx xxxx xxxx
  gmail: {
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER || 'your-email@gmail.com',
      pass: process.env.EMAIL_PASSWORD || 'your-app-password'
    }
  },

  // SENDGRID: Set SENDGRID_API_KEY
  sendgrid: {
    host: 'smtp.sendgrid.net',
    port: 587,
    auth: {
      user: 'apikey',
      pass: process.env.SENDGRID_API_KEY || ''
    }
  },

  // Default from email
  fromEmail: process.env.EMAIL_FROM || 'noreply@cybermind.com'
};

let transporter = null;

// Initialize email transporter based on config
function initializeTransporter() {
  const method = EMAIL_CONFIG.method.toLowerCase();

  if (method === 'gmail') {
    transporter = nodemailer.createTransport(EMAIL_CONFIG.gmail);
  } else if (method === 'sendgrid') {
    transporter = nodemailer.createTransport(EMAIL_CONFIG.sendgrid);
  } else if (method === 'console') {
    console.log('[EMAIL] Running in DEMO mode - emails logged to console');
    transporter = null;
  }
}

// Send verification email
async function sendVerificationEmail(email, verificationToken) {
  const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3001'}`;
  const formattedCode = verificationToken.substring(0, 8).toUpperCase();

  const emailContent = {
    from: EMAIL_CONFIG.fromEmail,
    to: email,
    subject: 'Verify Your CyberMind Account',
    html: `
      <div style="font-family: Arial, sans-serif; background: #0f172a; color: #fff; padding: 40px; text-align: center;">
        <div style="max-width: 400px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155;">
          <h2 style="color: #facc15; margin-bottom: 20px;">🛡️ Verify Your Email</h2>
          
          <p style="margin-bottom: 30px; color: #cbd5e1;">
            Welcome! Your verification code is:
          </p>
          
          <div style="background: #0f172a; padding: 20px; border-radius: 8px; margin: 30px 0; font-size: 24px; letter-spacing: 4px; color: #facc15; font-weight: bold;">
            ${formattedCode}
          </div>
          
          <p style="color: #cbd5e1; margin: 20px 0;">
            This code will expire in <strong>24 hours</strong>.
          </p>
          
          <p style="color: #94a3b8; font-size: 12px; margin-top: 30px; border-top: 1px solid #334155; padding-top: 20px;">
            If you did not sign up for this account, please ignore this email.
          </p>
        </div>
      </div>
    `,
    text: `Your CyberMind verification code: ${formattedCode}\n\nThis code expires in 24 hours.`
  };

  // DEMO mode - just log to console
  if (EMAIL_CONFIG.method === 'console') {
    console.log('\n' + '='.repeat(60));
    console.log('[EMAIL - DEMO MODE]');
    console.log('To:', email);
    console.log('Subject:', emailContent.subject);
    console.log('Verification Code:', formattedCode);
    console.log('Full Token:', verificationToken);
    console.log('='.repeat(60) + '\n');
    return { success: true, demo: true };
  }

  // Real email sending
  if (!transporter) {
    throw new Error('Email service not configured');
  }

  try {
    const info = await transporter.sendMail(emailContent);
    console.log('[EMAIL SENT]', email, 'Message ID:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error('[EMAIL ERROR]', err.message);
    throw new Error(`Failed to send email: ${err.message}`);
  }
}

// Send password reset email
async function sendPasswordResetEmail(email, resetCode) {
  const emailContent = {
    from: EMAIL_CONFIG.fromEmail,
    to: email,
    subject: 'Reset Your CyberMind Password',
    html: `
      <div style="font-family: Arial, sans-serif; background: #0f172a; color: #fff; padding: 40px; text-align: center;">
        <div style="max-width: 400px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155;">
          <h2 style="color: #facc15; margin-bottom: 20px;">🔐 Password Reset</h2>
          
          <p style="margin-bottom: 30px; color: #cbd5e1;">
            Your password reset code is:
          </p>
          
          <div style="background: #0f172a; padding: 20px; border-radius: 8px; margin: 30px 0; font-size: 24px; letter-spacing: 2px; color: #facc15; font-weight: bold;">
            ${resetCode}
          </div>
          
          <p style="color: #cbd5e1; margin: 20px 0;">
            This code will expire in <strong>15 minutes</strong>.
          </p>
          
          <p style="color: #94a3b8; font-size: 12px; margin-top: 30px; border-top: 1px solid #334155; padding-top: 20px;">
            If you did not request a password reset, please ignore this email.
          </p>
        </div>
      </div>
    `,
    text: `Your password reset code: ${resetCode}\n\nThis code expires in 15 minutes.`
  };

  if (EMAIL_CONFIG.method === 'console') {
    console.log('\n' + '='.repeat(60));
    console.log('[EMAIL - DEMO MODE] Password Reset');
    console.log('To:', email);
    console.log('Reset Code:', resetCode);
    console.log('='.repeat(60) + '\n');
    return { success: true, demo: true };
  }

  if (!transporter) {
    throw new Error('Email service not configured');
  }

  try {
    const info = await transporter.sendMail(emailContent);
    console.log('[EMAIL SENT]', email, 'Message ID:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error('[EMAIL ERROR]', err.message);
    throw new Error(`Failed to send email: ${err.message}`);
  }
}

// Initialize on module load
initializeTransporter();

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  EMAIL_CONFIG
};
