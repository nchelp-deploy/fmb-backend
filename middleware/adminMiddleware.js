const User = require('../models/User');

async function adminMiddleware(req, res, next) {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        details: 'User not found'
      });
    }

    if (!user.isAdmin()) {
      return res.status(403).json({
        error: 'Access denied',
        details: 'This action requires admin privileges'
      });
    }

    // Add admin user to request for use in routes
    req.adminUser = user;
    next();
  } catch (err) {
    console.error('Admin middleware error:', err);
    res.status(500).json({
      error: 'Server error',
      details: 'An error occurred while verifying admin privileges'
    });
  }
}

module.exports = adminMiddleware; 