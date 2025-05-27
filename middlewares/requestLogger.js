const logger = require('../utils/logger');

const requestLogger = (req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const { method, originalUrl } = req;
    const status = res.statusCode;
    const duration = Date.now() - start;

    logger.info(`[Request] ${method} ${originalUrl} ${status} - ${duration}ms`);
  });

  next();
};

module.exports = requestLogger;
