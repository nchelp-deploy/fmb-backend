const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ 
      error: 'Authentication required',
      details: 'No authorization token provided'
    });
  }

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Invalid token format',
      details: 'Authorization header must start with Bearer'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { userId: decoded.userId };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired',
        details: 'Please refresh your access token',
        code: 'TOKEN_EXPIRED'
      });
    } else if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Invalid token',
        details: 'Token signature is invalid',
        code: 'INVALID_TOKEN'
      });
    }
    
    return res.status(401).json({ 
      error: 'Authentication failed',
      details: 'Invalid or malformed token',
      code: 'AUTH_FAILED'
    });
  }
}

module.exports = authMiddleware; 