const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  
  // Handle specific types of errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: err.message
    });
  }
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Unauthorized',
      details: 'Invalid token or no token provided'
    });
  }

  if (err.name === 'CastError') {
    return res.status(400).json({
      error: 'Invalid ID',
      details: 'The provided ID is not valid'
    });
  }

  if (err.code === 11000) {
    return res.status(400).json({
      error: 'Duplicate Entry',
      details: 'A record with this value already exists'
    });
  }
  
  // Default error response
  res.status(err.status || 500).json({ 
    error: err.message || 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.stack : 'Something went wrong'
  });
};

module.exports = errorHandler; 