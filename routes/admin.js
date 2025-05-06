const express = require('express');
const router = express.Router();
const adminAuth = require('../middleware/adminAuth');
const User = require('../models/User');
const { body, validationResult } = require('express-validator');
const { verifyToken, isAdmin } = require('../middleware/auth');
const { validateUserUpdate } = require('../middleware/validation');
const Transaction = require('../models/Transaction');

// Get all users with detailed information
router.get('/users', adminAuth, async (req, res, next) => {
  try {
    const { search, role, status } = req.query;
    const query = {};

    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ];
    }

    if (role) {
      query.role = role;
    }

    if (status) {
      query.isActive = status === 'active';
    }

    const users = await User.find(query)
      .select('-passwordHash -__v')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      users: users.map(user => ({
        _id: user._id,
        username: user.username,
        email: user.email,
        name: user.name,
        role: user.role,
        isActive: user.isActive,
        accountBalance: user.accountBalance || 0,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }))
    });
  } catch (err) {
    next(err);
  }
});

// Update user status
router.patch('/users/:id/status', adminAuth, [
  body('isActive').isBoolean()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { isActive } = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isSuperAdmin()) {
      return res.status(403).json({ error: 'Cannot modify super admin status' });
    }

    user.isActive = isActive;
    await user.save();

    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
    });
  } catch (err) {
    next(err);
  }
});

// Update user role
router.patch('/users/:id/role', adminAuth, [
  body('role').isIn(['user', 'admin'])
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { role } = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isSuperAdmin()) {
      return res.status(403).json({ error: 'Cannot modify super admin role' });
    }

    user.role = role;
    await user.save();

    res.json({
      success: true,
      message: 'User role updated successfully'
    });
  } catch (err) {
    next(err);
  }
});

// Get security settings
router.get('/security-settings', adminAuth, async (req, res) => {
  try {
    const settings = {
      passwordPolicy: {
        minLength: 8,
        requireUppercase: true,
        requireNumbers: true,
        requireSpecialChars: true
      },
      loginPolicy: {
        maxAttempts: 5,
        lockoutDuration: 30, // minutes
        require2FA: false
      },
      sessionPolicy: {
        sessionTimeout: 15, // minutes
        maxConcurrentSessions: 3
      }
    };
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching security settings' });
  }
});

// Update security settings
router.patch('/security-settings', adminAuth, async (req, res) => {
  try {
    // In a real application, these settings would be stored in a database
    // For now, we'll just validate the input
    const { passwordPolicy, loginPolicy, sessionPolicy } = req.body;

    if (passwordPolicy) {
      if (passwordPolicy.minLength < 8) {
        return res.status(400).json({ message: 'Minimum password length must be at least 8' });
      }
    }

    if (loginPolicy) {
      if (loginPolicy.maxAttempts < 3) {
        return res.status(400).json({ message: 'Maximum login attempts must be at least 3' });
      }
      if (loginPolicy.lockoutDuration < 15) {
        return res.status(400).json({ message: 'Lockout duration must be at least 15 minutes' });
      }
    }

    if (sessionPolicy) {
      if (sessionPolicy.sessionTimeout < 5) {
        return res.status(400).json({ message: 'Session timeout must be at least 5 minutes' });
      }
      if (sessionPolicy.maxConcurrentSessions < 1) {
        return res.status(400).json({ message: 'Maximum concurrent sessions must be at least 1' });
      }
    }

    res.json({ message: 'Security settings updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating security settings' });
  }
});

// Get audit logs
router.get('/audit-logs', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, type = '', startDate = '', endDate = '' } = req.query;
    const skip = (page - 1) * limit;

    const query = {};
    if (type) {
      query.type = type;
    }
    if (startDate && endDate) {
      query.timestamp = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    // In a real application, this would query an audit logs collection
    // For now, we'll return mock data
    const logs = [
      {
        type: 'user_update',
        description: 'User role updated',
        timestamp: new Date(),
        adminId: req.user._id,
        targetId: 'mock_user_id'
      },
      {
        type: 'security_update',
        description: 'Security settings updated',
        timestamp: new Date(Date.now() - 3600000),
        adminId: req.user._id
      }
    ];

    res.json({
      logs,
      total: logs.length,
      page: parseInt(page),
      pages: 1
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching audit logs' });
  }
});

// Get user details
router.get('/users/:id', adminAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-passwordHash -__v');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      user
    });
  } catch (err) {
    next(err);
  }
});

// Get audit logs for a user
router.get('/users/:id/audit', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('modifiedBy')
      .populate('modifiedBy.adminId', 'username email');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user.modifiedBy);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching audit logs' });
  }
});

// Search users
router.get('/users/search', adminAuth, async (req, res) => {
  try {
    const { query } = req.query;
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ]
    }).select('-passwordHash -__v');

    if (users.length === 0) {
      return res.status(404).json({ error: 'No users found matching your search' });
    }

  res.json(users);
  } catch (err) {
    console.error('Error searching users:', err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Update user
router.put('/users/:id', adminAuth, [
  body('username').optional().isLength({ min: 3 }),
  body('email').optional().isEmail(),
  body('role').optional().isIn(['user', 'admin'])
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const updates = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isSuperAdmin()) {
      return res.status(403).json({ error: 'Cannot modify super admin users' });
    }

    Object.keys(updates).forEach(update => {
      user[update] = updates[update];
    });

    await user.save();

    res.json({
      success: true,
      message: 'User updated successfully'
    });
  } catch (err) {
    next(err);
  }
});

// Get user's recent transactions
router.get('/user-transactions/:userId', verifyToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId).select('transactions');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user.transactions);
  } catch (error) {
    console.error('Get user transactions error:', error);
    res.status(500).json({ message: 'Error fetching user transactions' });
  }
});

// Get admin profile
router.get('/profile', adminAuth, async (req, res) => {
  try {
    const admin = await User.findById(req.user._id).select('-passwordHash');
    res.json(admin);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching admin profile' });
  }
});

// Get admin statistics
router.get('/stats', adminAuth, async (req, res) => {
  try {
    const [
      totalUsers,
      activeUsers,
      newUsers,
      suspendedUsers
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true }),
      User.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      User.countDocuments({ isActive: false })
    ]);

    res.json({
      totalUsers,
      activeUsers,
      newUsers,
      suspendedUsers
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching statistics' });
  }
});

// Get security alerts
router.get('/security-alerts', adminAuth, async (req, res) => {
  try {
    // In a real application, this would fetch from a security alerts collection
    // For now, we'll return some mock data
    const alerts = [
      {
        message: 'Multiple failed login attempts detected',
        timestamp: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
        severity: 'high'
      },
      {
        message: 'New user registered with suspicious email pattern',
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
        severity: 'medium'
      }
    ];

    res.json(alerts);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching security alerts' });
  }
});

// Get recent activity
router.get('/recent-activity', adminAuth, async (req, res) => {
  try {
    // In a real application, this would fetch from an activity log collection
    // For now, we'll return some mock data
    const activities = [
      {
        type: 'login',
        description: 'User logged in from new device',
        timestamp: new Date(Date.now() - 5 * 60 * 1000) // 5 minutes ago
      },
      {
        type: 'update',
        description: 'User profile updated',
        timestamp: new Date(Date.now() - 15 * 60 * 1000) // 15 minutes ago
      }
    ];

    res.json(activities);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching recent activity' });
  }
});

// Delete user
router.delete('/users/:id', adminAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isSuperAdmin()) {
      return res.status(403).json({ error: 'Cannot delete super admin users' });
    }

    await user.remove();

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (err) {
    next(err);
  }
});

// List all users
router.get('/users', verifyToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0, __v: 0 });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user account balance
router.patch('/users/:userId/balance', adminAuth, async (req, res, next) => {
  try {
    const { newBalance } = req.body;
    const userId = req.params.userId;

    if (isNaN(newBalance) || newBalance < 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid balance amount'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const oldBalance = user.accountBalance || 0;
    const balanceChange = newBalance - oldBalance;

    // Create a transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'admin_adjustment',
      amount: balanceChange,
      description: `Balance adjusted by admin. Old balance: $${oldBalance.toFixed(2)}, New balance: $${newBalance.toFixed(2)}`,
      status: 'completed',
      createdBy: req.user._id,
      metadata: {
        adminId: req.user._id,
        oldBalance,
        newBalance
      }
    });
    await transaction.save();

    // Update user balance
    user.accountBalance = newBalance;
    await user.save();

    res.json({
      success: true,
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        accountBalance: user.accountBalance,
        role: user.role,
        isActive: user.isActive
      }
    });
  } catch (err) {
    console.error('Balance update error:', err);
    res.status(500).json({
      success: false,
      message: err.message || 'Failed to update balance'
    });
  }
});

// Update user balance
router.post('/update-balance', adminAuth, [
  body('userId').isMongoId(),
  body('newBalance').isFloat({ min: 0 })
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { userId, newBalance } = req.body;

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get the old balance
    const oldBalance = user.accountBalance || 0;
    const balanceChange = newBalance - oldBalance;

    // Update user balance
    user.accountBalance = newBalance;
    await user.save();

    // Create a transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'admin_adjustment',
      amount: balanceChange,
      description: `Balance adjusted by admin. Old balance: $${oldBalance.toFixed(2)}, New balance: $${newBalance.toFixed(2)}`,
      status: 'completed',
      metadata: {
        adminId: req.user._id,
        oldBalance,
        newBalance
      }
    });
    await transaction.save();

    res.json({
      success: true,
      message: 'User balance updated successfully',
      data: {
        userId: user._id,
        username: user.username,
        oldBalance,
        newBalance
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
