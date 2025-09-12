const createResponse = (success, data = null, message = '', errors = null) => {
  return {
    success,
    data,
    message,
    errors,
    timestamp: new Date().toISOString()
  };
};

const successResponse = (res, data = null, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json(createResponse(true, data, message));
};

const errorResponse = (res, message = 'Error', statusCode = 500, errors = null) => {
  return res.status(statusCode).json(createResponse(false, null, message, errors));
};

module.exports = {
  createResponse,
  successResponse,
  errorResponse
};