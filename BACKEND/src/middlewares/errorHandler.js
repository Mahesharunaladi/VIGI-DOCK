/**
 * Centralized Global Error Handler Middleware
 */
const errorHandler = (err, req, res, next) => {
  console.error(`[Error] [${req.method} ${req.url}]`, err.stack || err.message);

  const statusCode = err.statusCode || (res.statusCode && res.statusCode !== 200 ? res.statusCode : 500);

  res.status(statusCode).json({
    success: false,
    error: {
      message: err.message || 'Internal Server Error',
      status: statusCode,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    },
  });
};

module.exports = errorHandler;
