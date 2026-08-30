const app = require('../../server/src/index.js');

exports.handler = async (event, context) => {
  const serverless = require('serverless-http');
  return serverless(app)(event, context);
};
