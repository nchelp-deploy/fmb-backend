const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const PasswordResetToken = require('../models/PasswordResetToken');
const { sendPasswordResetEmail } = require('../utils/emailService');
const passport = require('passport');
const crypto = require('crypto');
const { verifyToken, isAdmin } = require('../middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';

// Generate tokens
const generateTokens = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  const accessToken = jwt.sign({ 
    userId: user._id,
    role: user.role 
  }, JWT_SECRET, { expiresIn: '15m' });
  
  const refreshToken = crypto.randomBytes(40).toString('hex');
  
  // Save refresh token
  await RefreshToken.create({
    userId,
    token: refreshToken
  });

  return { accessToken, refreshToken };
};

// Signup route (local)
router.post('/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Input validation
    if (!username || !password || !email) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: {
          username: !username ? 'Username is required' : null,
          password: !password ? 'Password is required' : null,
          email: !email ? 'Email is required' : null
        }
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ 
        error: 'User already exists',
        details: {
          email: existingUser.email === email ? 'Email already in use' : null,
          username: existingUser.username === username ? 'Username already taken' : null
        }
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create new user with all required fields
  const user = new User({
    username,
      email,
    passwordHash,
      role: 'user',
      isActive: true,
      accountBalance: 0,
      lastLogin: new Date(),
      createdAt: new Date()
    });

    // Save the user
  await user.save();

    // Generate tokens
    const { accessToken, refreshToken } = await generateTokens(user._id);

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Login route (local)
router.post('/login', async (req, res) => {
  try {
    console.log('Login attempt with:', { username: req.body.username });
    
  const { username, password } = req.body;

    if (!username || !password) {
      console.log('Missing credentials:', { username: !!username, password: !!password });
      return res.status(400).json({ 
        error: 'Missing credentials',
        details: {
          username: !username ? 'Username is required' : null,
          password: !password ? 'Password is required' : null
        }
      });
    }

    // Find user and explicitly select passwordHash
    const user = await User.findOne({ username }).select('+passwordHash');
    console.log('User found:', user ? { username: user.username, role: user.role } : 'Not found');
    
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        details: 'Username or password is incorrect'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      console.log('User account inactive:', user.username);
      return res.status(403).json({ 
        error: 'Account disabled',
        details: 'Your account has been disabled. Please contact support.'
      });
    }

    // Check password using the model's comparePassword method
    const validPassword = await user.comparePassword(password);
    console.log('Password validation:', validPassword ? 'Valid' : 'Invalid');
    
    if (!validPassword) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        details: 'Username or password is incorrect'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Create token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    console.log('Token generated for user:', user.username);

    // Return user data and token
    const response = {
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        accountBalance: user.accountBalance || 0
      },
      token
    };
    console.log('Login successful, sending response');
    res.json(response);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Server error',
      details: error.message
    });
  }
});

// Google OAuth routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  async (req, res) => {
    try {
      const { accessToken, refreshToken } = await generateTokens(req.user._id);
      
      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?accessToken=${accessToken}&refreshToken=${refreshToken}`);
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
    }
  }
);

// Refresh token route
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ 
        error: 'Missing refresh token',
        details: 'Refresh token is required'
      });
    }

    // Find and verify refresh token
    const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
    if (!tokenDoc) {
      return res.status(401).json({ 
        error: 'Invalid refresh token',
        details: 'Refresh token not found'
      });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = await generateTokens(tokenDoc.userId);

    // Delete old refresh token
    await RefreshToken.deleteOne({ token: refreshToken });

    res.json({
      accessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Password reset routes
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        error: 'Missing email',
        details: 'Email is required'
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found',
        details: 'No user found with this email'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Save reset token
    await PasswordResetToken.create({
      userId: user._id,
      token: hashedToken,
      expiresAt: new Date(Date.now() + 3600000) // 1 hour
    });

    // Send reset email
    await sendPasswordResetEmail(user.email, resetToken);

    res.json({ 
      message: 'Password reset email sent',
      details: 'Check your email for reset instructions'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: {
          token: !token ? 'Reset token is required' : null,
          password: !password ? 'New password is required' : null
        }
      });
    }

    // Find reset token
    const resetToken = await PasswordResetToken.findOne({
      token: { $exists: true },
      expiresAt: { $gt: new Date() }
    });

    if (!resetToken) {
      return res.status(400).json({ 
        error: 'Invalid or expired token',
        details: 'Password reset token is invalid or has expired'
      });
    }

    // Verify token
    const isValidToken = await bcrypt.compare(token, resetToken.token);
    if (!isValidToken) {
      return res.status(400).json({ 
        error: 'Invalid token',
        details: 'Password reset token is invalid'
      });
    }

    // Update password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await User.findByIdAndUpdate(resetToken.userId, {
      passwordHash: hashedPassword
    });

    // Delete reset token
    await PasswordResetToken.deleteOne({ _id: resetToken._id });

    res.json({ 
      message: 'Password reset successful',
      details: 'You can now login with your new password'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Get user profile
router.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-passwordHash -__v');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        accountBalance: user.accountBalance || 0,
        bonus: user.bonus || 0,
        transactions: user.transactions || []
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin protected route example
router.get('/admin', verifyToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error('Admin route error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

module.exports = router;
