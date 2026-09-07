const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const router = express.Router();
const db = require('./database');
const { requireAuth } = require('./auth-guard');

/**
 * GET /api/auth/me
 * Endpoint required by protectPage() in auth-guard.js to verify active sessions.
 */
router.get('/me', requireAuth, async (req, res) => {
  try {
    const sessionUser = req.user || req.session?.user?.user || req.session?.user;
    
    // Fetch fresh details from DB to ensure roles/access flags aren't stale
    const user = await db.findUserByEmail(sessionUser.email);
    if (!user) {
      return res.status(401).json({ error: 'User account no longer exists.' });
    }

    const safeUser = {
      id: user.id,
      email: user.email,
      role: user.role,
      access_helpdesk: user.access_helpdesk,
      access_assets: user.access_assets,
      name: user.name || user.full_name || undefined,
      subsidiary: user.subsidiary || null,
      department: user.department || null
    };

    return res.status(200).json(safeUser);
  } catch (error) {
    console.error('Auth /me Error:', error);
    return res.status(500).json({ error: 'Failed to retrieve current user context.' });
  }
});

/**
 * POST /api/auth/login
 * Establishes session required by auth-guard.js
 */
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash || user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Attach full user payload to session for auth-guard.js checks
    const sessionData = {
      id: user.id,
      email: user.email,
      role: user.role,
      access_helpdesk: user.access_helpdesk,
      access_assets: user.access_assets
    };

    req.session.user = sessionData;

    // Explicitly save session before returning response
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Failed to initialize user session.' });
      }

      return res.status(200).json({
        message: 'Login successful.',
        user: sessionData
      });
    });
  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({ error: 'Server error during login.' });
  }
});

/**
 * POST /api/auth/logout
 * Destroys session and clears session cookie
 */
router.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
        return res.status(500).json({ error: 'Could not log out.' });
      }
      
      res.clearCookie('connect.sid', { path: '/' });
      return res.status(200).json({ message: 'Logged out successfully.' });
    });
  } else {
    res.clearCookie('connect.sid', { path: '/' });
    return res.status(200).json({ message: 'Logged out successfully.' });
  }
});

/**
 * POST /api/auth/forgot-password
 */
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const user = await db.findUserByEmail(email.trim());
    
    // Generic response prevents account enumeration
    if (!user) {
      return res.status(200).json({ 
        message: 'If an account with that email exists, a reset token has been generated.' 
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

    await db.updateUserResetToken(user.id, resetTokenHash, resetTokenExpires);

    return res.status(200).json({
      message: 'Reset token generated successfully.',
      token: resetToken 
    });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    return res.status(500).json({ error: 'Server error processing password reset.' });
  }
});

/**
 * GET /api/auth/verify-reset-token/:token
 */
router.get('/verify-reset-token/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await db.findUserByResetToken(tokenHash);

    if (!user || new Date(user.reset_token_expires) < new Date()) {
      return res.status(400).json({ valid: false, error: 'Invalid or expired token.' });
    }

    return res.status(200).json({ valid: true });
  } catch (error) {
    return res.status(500).json({ valid: false, error: 'Failed to verify token.' });
  }
});

/**
 * POST /api/auth/reset-password
 */
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await db.findUserByResetToken(tokenHash);

    if (!user || new Date(user.reset_token_expires) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired password reset token.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.updateUserPasswordAndClearToken(user.id, hashedPassword);

    return res.status(200).json({ message: 'Password updated successfully.' });

  } catch (error) {
    console.error('Reset Password Error:', error);
    return res.status(500).json({ error: 'Server error resetting password.' });
  }
});

module.exports = router;