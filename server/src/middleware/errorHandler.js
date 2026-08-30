'use strict';

/** Central error handler — never leaks stack traces or internals to clients. */

const logger = require('../utils/logger');
const config = require('../config');

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  if (status >= 500) {
    logger.error(`Unhandled error on ${req.method} ${req.path}: ${err.message}`);
  }
  const payload = { message: status >= 500 ? 'Something went wrong. Please try again.' : err.message };
  if (err.data && typeof err.data === 'object') Object.assign(payload, err.data);
  if (config.isProduction === false && status >= 500) payload.hint = err.message;
  res.status(status).json(payload);
}

function notFound(req, res) {
  res.status(404).json({ message: 'Not found.' });
}

module.exports = { errorHandler, notFound };
